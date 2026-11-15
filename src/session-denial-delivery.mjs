// 固定单并发、有限分页；持久outbox和已校验回执是恢复依据，内存游标不是成功记录。
export function startSessionDenialDelivery({store,transport,intervalMs=1000,pageSize=16}){
 if(typeof store?.scan!=='function'||typeof store?.deliverPending!=='function'||typeof transport?.deliverSessionDenial!=='function'||
  !Number.isInteger(intervalMs)||intervalMs<10||intervalMs>60000||!Number.isInteger(pageSize)||pageSize<1||pageSize>64)throw new Error('session_denial_delivery_configuration');
 let stopped=false,timer=null,active=null,after=null;
 const counts={delivered:0,acknowledged:0,failed:0,scan_failed:0};
 const add=key=>{counts[key]=Math.min(Number.MAX_SAFE_INTEGER,counts[key]+1);};
 async function page(){
  let result;try{result=store.scan({after,limit:pageSize});}catch{add('scan_failed');return;}
  for(const item of result.items){
   if(stopped)return;
   try{const value=await store.deliverPending(item,transport);if(!['delivered','acknowledged'].includes(value?.state))throw new Error('session_denial_delivery_result');add(value.state);}
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
