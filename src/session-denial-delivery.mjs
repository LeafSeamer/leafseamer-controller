export function startSessionDenialDelivery({store,transport,intervalMs=1000,pageSize=16}){
 if(typeof store?.scan!=='function'||typeof store?.deliverPending!=='function'||typeof transport?.deliverSessionDenial!=='function'||
  !Number.isInteger(intervalMs)||intervalMs<10||intervalMs>60000||!Number.isInteger(pageSize)||pageSize<1||pageSize>64)throw new Error('session_denial_delivery_configuration');
 return startOutboxDelivery({scan:request=>store.scan(request),async deliver(item){
  return (await store.deliverPending(item,transport))?.state;
 },intervalMs,pageSize});
}

// 固定单并发、有限分页；持久队列和原回执是恢复依据。
export function startOutboxDelivery({scan,deliver,intervalMs=1000,pageSize=16}){
 let stopped=false,timer=null,active=null,after=null;
 const counts={delivered:0,acknowledged:0,failed:0,scan_failed:0};
 const add=key=>{counts[key]=Math.min(Number.MAX_SAFE_INTEGER,counts[key]+1);};
 async function page(){
  let result;try{result=scan({after,limit:pageSize});}catch{add('scan_failed');return;}
  for(const item of result.items){
   if(stopped)return;
   try{const state=await deliver(item);if(!['delivered','acknowledged'].includes(state))throw new Error('outbox_delivery_result');add(state);}
   catch{add('failed');}
  }
  after=result.next;
 }
 function schedule(delay){if(stopped)return;timer=setTimeout(()=>{
  timer=null;active=page().catch(()=>{add('scan_failed');}).finally(()=>{active=null;schedule(intervalMs);});
 },delay);timer.unref();}
 schedule(0);
 return Object.freeze({
  status:()=>({state:stopped?'stopped':'running',active:active!==null,...counts}),
  async close(){stopped=true;clearTimeout(timer);timer=null;await active;}
 });
}
