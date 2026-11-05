import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {openNativeClock} from './native-clock.mjs';
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const need=(ok,code)=>{if(!ok){const error=new Error('worker_authorization_'+code);error.code=error.message;throw error;}};
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};

// 仅核心内部使用。授权来自当前受理与资源原件；短授权不赋予设备写入资格。
export function workerAuthorizationStore({db,service,bootId,isOpen,core,prepared,all,extension,verifyDependencies}){
 let source=null,clock=null,receipt=null,closed=false,failed=false,unsubscribe=null,timer=null,tail=Promise.resolve(),pending=0;
 const denied=new Set();
 const available=()=>need(!closed&&!failed&&isOpen()&&db.open&&!db.inTransaction,'unavailable');
 function connected(){
  need(!closed&&!failed&&isOpen()&&db.open&&source,'source');source.assertCurrent();
  need(same(source.current().payload.record.admission_receipt,receipt)&&same(core().receipt,receipt),'source_changed');
 }
 function stop(){failed=true;clearTimeout(timer);source?.close();}
 function enqueue(job){
  available();need(pending<4,'capacity');++pending;
  const result=tail.then(async()=>{available();connected();try{return await job();}catch(error){if(error.code?.startsWith('SQLITE_'))stop();throw error;}});
  tail=result.catch(()=>{});return result.finally(()=>--pending);
 }
 const hasDenied=id=>denied.has(id)||!!db.prepare('SELECT 1 FROM worker_launch_denial WHERE launch_id=?').pluck().get(id);
 function written(ok){if(!ok){stop();need(false,'storage_failed');}}
 function deny(id,reason){denied.add(id);db.prepare('INSERT OR IGNORE INTO worker_launch_denial VALUES(?,?)').run(id,reason);
  written(!!db.prepare('SELECT 1 FROM worker_launch_denial WHERE launch_id=?').pluck().get(id));}
 function current(key){
  connected();const value=prepared(key);need(value?.current_boot,'preparation');need(!hasDenied(value.intent.launch_id),'denied');
  const selected=extension.current(value.intent);verifyDependencies(value.intent,selected);return {value,selected};
 }
 function items(){
  return all().map(value=>{
   const key={launch_id:value.intent.launch_id,launch_intent_digest:value.ref.digest};
   try{current(key);}catch(error){
    if(error.code?.startsWith('SQLITE_'))throw error;
    // 资格丢失在本boot永久关闭；重新批准也不能复活原launch。
    deny(key.launch_id,'qualification_lost');
   }
   return {...key,disposition:hasDenied(key.launch_id)?'deny':'allow'};
  });
 }
 function snapshot(){
  connected();const entries=items(),last=db.prepare('SELECT revision,body_jcs,body_digest FROM worker_fence_snapshot WHERE service_boot_id=? ORDER BY revision DESC LIMIT 1').raw().get(bootId);
  if(last){const value=JSON.parse(last[1]);written(canonicalize(value)===last[1]&&hash(value)===last[2]&&same(value.scope,source.scope));if(same(value.items,entries))return value;}
  const revision=(last?.[0]??0)+1;need(revision<=4096,'capacity');
  const body={scope:structuredClone(source.scope),revision:String(revision),items:entries},value={...body,digest:hash(body)};
  written(db.prepare('INSERT INTO worker_fence_snapshot VALUES(?,?,?,?)').run(bootId,revision,canonicalize(value),hash(value)).changes===1);return value;
 }
 async function sync(){
  // 原监督器已关闭的实例必须在下一完整快照中保持deny，不能因审批仍有效而重新allow。
  const prepared=all();
  for(const value of prepared){
   const key={launch_id:value.intent.launch_id,launch_intent_digest:value.ref.digest};
   if(hasDenied(key.launch_id))continue;
   const record=await source.queryLaunch(key);connected();
   if(record&&!['registered','creating','awaiting_bootstrap','admitted_closed'].includes(record.state))
    db.transaction(()=>deny(key.launch_id,'qualification_lost')).immediate();
  }
  // 先持久化完整快照，再发送；任何ACK不确定或本地写入失败均终止连接。
  const value=db.transaction(snapshot).immediate();
  if(!db.prepare('SELECT 1 FROM worker_fence_ack WHERE service_boot_id=? AND revision=?').pluck().get(bootId,Number(value.revision))){
   try{
    const ack=await source.putFence(value);connected();
    need(ack?.revision===value.revision&&ack.snapshot_digest===value.digest&&ack.journal_committed===true,'fence_ack');
    db.transaction(()=>{connected();written(db.prepare('INSERT INTO worker_fence_ack VALUES(?,?,?)').run(bootId,Number(value.revision),canonicalize(ack)).changes===1);}).immediate();
   }catch(error){stop();throw error;}
  }
  // ACK期间撤销会生成下一完整deny快照，绝不签发刚失效的allow。
  const fresh=db.transaction(items).immediate();
  if(!same(fresh,value.items))return sync();return value;
 }
 async function issueCurrent(key){
  const initial=db.transaction(()=>current(key)).immediate();
  const observed=await extension.observe(initial.value.intent);connected();
  const record=await source.queryLaunch(key);connected();
  need(record===null||record.state==='registered'&&record.creation_attempted===false&&record.retirement_evidence===null,'creation_attempted');
  const fence=await sync();
  return db.transaction(()=>{
   const fresh=current(key);need(same(fresh,initial)&&same(fresh.selected,observed),'qualification_changed');
   need(fence.items.some(item=>same(item,{...key,disposition:'allow'})),'denied');
   need(db.prepare('SELECT count(*) FROM worker_launch_authorization').pluck().get()<4096,'capacity');
   const now=BigInt(clock.tick()),binding=fresh.value.intent.extension_binding;
   const body={...key,installation_ref:binding.installation_ref,approval_ref:binding.approval_ref,role_resolution_ref:binding.role_resolution_ref,
    permissions_digest:binding.permissions_digest,supervisor_instance_id:source.scope.supervisor_instance_id,fence_revision:fence.revision,
    lifetime:{clock:structuredClone(receipt.domain_ref),issued_tick:String(now),deadline_tick:String(now+2000000000n)}};
   const id=crypto.randomUUID(),value={...body,authorization_ref:{kind:'launch_authorization',authority_service_id:service.service_id,
    database_instance_id:service.database_instance_id,object_id:id,revision:'1',digest:hash(body)}};
   written(db.prepare('INSERT INTO worker_launch_authorization VALUES(?,?,?,?,?,?)').run(id,key.launch_id,bootId,Number(fence.revision),canonicalize(value),hash(value)).changes===1);
   return freeze(value);
  }).immediate();
 }
 async function issue(key){
  try{return await issueCurrent(key);}catch(error){
   if(error.code?.startsWith('SQLITE_')){stop();throw error;}
   if(!closed&&!failed)await sync();throw error;
  }
 }
 function schedule(){timer=setTimeout(()=>{void Promise.resolve().then(()=>enqueue(sync)).catch(()=>stop()).finally(()=>{if(!closed&&!failed)schedule();});},500);timer.unref();}
 function fixed(key){available();const value=prepared(key);need(value?.current_boot,'preparation');return {launch_id:value.intent.launch_id,launch_intent_digest:value.ref.digest};}
 return Object.freeze({
  bindSource(value){
   available();need(!source&&value&&['assertCurrent','current','putFence','queryLaunch','registerWorker','createWorker','subscribeLost','close'].every(name=>typeof value[name]==='function'),'source');
   const parent=db.transaction(core).immediate();value.assertCurrent();
   need(parent.descriptor.clock_backend_id==='windows_interrupt_precise'&&same(value.scope,{service_id:service.service_id,database_instance_id:service.database_instance_id,
    supervisor_instance_id:parent.descriptor.supervisor_instance_id,domain_ref:parent.receipt.domain_ref})&&same(value.current().payload.record.admission_receipt,parent.receipt),'source_binding');
   source=value;receipt=freeze(parent.receipt);clock=openNativeClock();unsubscribe=source.subscribeLost(()=>{failed=true;clearTimeout(timer);});connected();schedule();
  },
  authorize(key){const copy=fixed(key);return enqueue(()=>issue(copy));},
  register(key){const copy=fixed(key);return enqueue(async()=>{const authorization=await issue(copy),value=db.transaction(()=>current(copy)).immediate();return source.registerWorker(value.value.intent,authorization);});},
  create(key,proof){const copy=fixed(key),fixedProof=structuredClone(proof);need(fixedProof&&Object.keys(fixedProof).sort().join(',')==='load_id,materialization_challenge_id,materialization_evidence_id','create_input');
   return enqueue(async()=>{const authorization=await issue(copy);db.transaction(()=>current(copy)).immediate();return source.createWorker({...fixedProof,key:copy,authorization});});},
  deny(key){const copy=fixed(key);denied.add(copy.launch_id);return enqueue(async()=>{db.transaction(()=>deny(copy.launch_id,'requested')).immediate();return sync();});},
  synchronize(){return enqueue(sync);},
  close(){if(closed)return;closed=true;clearTimeout(timer);unsubscribe?.();source?.close();}
 });
}
