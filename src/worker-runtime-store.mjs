import crypto from 'node:crypto';
import canonicalize from 'canonicalize';

export class WorkerRuntimeError extends Error {constructor(code){super(code);this.name='WorkerRuntimeError';this.code=code;}}
const need=(value,code)=>{if(!value)throw new WorkerRuntimeError(code);};
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
const rows=(db,sql,...args)=>{const q=db.prepare(sql),names=q.columns().map(c=>c.name);return q.raw().all(...args).map(v=>Object.fromEntries(names.map((name,i)=>[name,v[i]])));};

// 核心内部采用点。调用方只给启动键，回执必须从本次绑定的监督连接取得。
export function workerRuntimeStore({db,service,bootId,isOpen,prepared,core,extension,verifyDependencies}){
 let source=null,unsubscribe=null,closed=false,lost=false,storageFailed=false,pending=0;
 const active=new Map(),waiting=new Set();let inspecting=Promise.resolve();
 const available=()=>need(!closed&&isOpen()&&db.open&&!db.inTransaction,'worker_runtime_closed');
 const connected=()=>{need(!closed&&isOpen()&&db.open&&source&&!lost&&!storageFailed,'worker_runtime_source');source.assertCurrent();};
 const live=()=>{available();connected();};
 function observe(intent){const result=inspecting.then(async()=>{live();const selected=await extension.observe(intent),observed=await source.observeWorker(intent);return {selected,observed};});inspecting=result.catch(()=>{});return result;}
 const find=launch=>rows(db,'SELECT * FROM worker_runtime_binding WHERE launch_id=?',launch)[0];
 function view(row){
  if(!row)return null;const body=JSON.parse(row.body_jcs);
  need(canonicalize(body)===row.body_jcs&&hash(body)===row.body_digest,'worker_runtime_integrity');
  const withdrawn=rows(db,'SELECT body_jcs FROM worker_runtime_withdrawal WHERE runtime_id=?',row.runtime_id)[0];
  return freeze({binding:body,ref:{kind:'runtime_binding',authority_service_id:service.service_id,database_instance_id:service.database_instance_id,
   object_id:row.runtime_id,revision:'1',digest:row.body_digest},current_boot:row.service_boot_id===bootId,withdrawal:withdrawn?JSON.parse(withdrawn.body_jcs):null});
 }
 function saveWithdrawal(row,reason){
  if(db.prepare('SELECT 1 FROM worker_runtime_withdrawal WHERE runtime_id=?').pluck().get(row.runtime_id))return;
  const transaction=crypto.randomUUID(),body={format:'leafseamer-worker-runtime-withdrawal/1',runtime_binding_id:row.runtime_id,
   service_boot_id:row.service_boot_id,transaction_id:transaction,reason};
  db.prepare('INSERT INTO worker_runtime_withdrawal VALUES(?,?,?,?)').run(row.runtime_id,transaction,reason,canonicalize(body));
 }
 function stopEntry(entry){entry.stopped=true;clearTimeout(entry.timer);active.delete(entry.prepared.intent.launch_id);}
 function retire(intent){if(source&&!lost&&!closed)void Promise.resolve().then(()=>source.retireWorker(intent,'revoked')).catch(()=>{});}
 function withdraw(entry,reason){
  if(entry.stopped)return;stopEntry(entry); // 本地资格先关闭，持久写入失败也不能恢复。
  try{if(db.open)db.transaction(()=>saveWithdrawal(entry.row,reason)).immediate();}
  catch{storageFailed=true;for(const other of [...active.values()]){stopEntry(other);retire(other.prepared.intent);}}
  retire(entry.prepared.intent);
 }
 function checkInWriter(entry){
  need(db.inTransaction,'worker_runtime_writer');connected();need(!entry.stopped&&active.get(entry.prepared.intent.launch_id)===entry,'worker_runtime_withdrawn');
  source.assertWorkerObservation(entry.observation);
  core();const selected=extension.current(entry.prepared.intent);verifyDependencies?.(entry.prepared.intent,selected);
  need(!db.prepare('SELECT 1 FROM worker_runtime_withdrawal WHERE runtime_id=?').pluck().get(entry.row.runtime_id),'worker_runtime_withdrawn');
 }
 function check(entry){live();db.transaction(()=>checkInWriter(entry)).immediate();}
 function withdrawFromWriter(entry,error){
  // 外层受理事务可能回滚，不能让回滚恢复进程资格或吞掉必须落盘的撤回。
  stopEntry(entry);retire(entry.prepared.intent);
  queueMicrotask(()=>{
   try{if(db.open)db.transaction(()=>saveWithdrawal(entry.row,error?.code?.startsWith('extension_')?'approval_changed':'source_changed')).immediate();}
   catch{storageFailed=true;for(const other of [...active.values()]){stopEntry(other);retire(other.prepared.intent);}}
  });
 }
 function refresh(entry){
  if(entry.stopped)return Promise.resolve();
  if(entry.refreshing)return entry.refreshing;
  clearTimeout(entry.timer);
  entry.refreshing=(async()=>{try{
   check(entry);
   const {selected,observed}=await observe(entry.prepared.intent);
   check(entry);source.assertWorkerObservation(observed);
   need(same(observed.receipt,entry.observation.receipt),'worker_runtime_receipt_changed');
   db.transaction(()=>need(same(extension.current(entry.prepared.intent),selected),'worker_runtime_approval_changed')).immediate();
   entry.observation=observed;
  }catch(error){withdraw(entry,error?.code?.startsWith('extension_')?'approval_changed':'source_changed');}
  finally{entry.refreshing=null;if(!entry.stopped){entry.timer=setTimeout(()=>{void refresh(entry);},500);entry.timer.unref();}}})();
  return entry.refreshing;
 }
 // 重启只有历史，不恢复上次进程的采用资格。
 db.transaction(()=>{for(const row of rows(db,'SELECT runtime_id,service_boot_id FROM worker_runtime_binding r WHERE service_boot_id<>? AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)',bootId))saveWithdrawal(row,'restarted');}).immediate();
 return Object.freeze({
  bindSource(value){
   available();need(!source&&value&&['assertCurrent','current','observeWorker','assertWorkerObservation','subscribeLost','retireWorker'].every(name=>typeof value[name]==='function'),'worker_runtime_source');
   const parent=db.transaction(core).immediate();value.assertCurrent();
   need(same(value.scope,{service_id:service.service_id,database_instance_id:service.database_instance_id,
    supervisor_instance_id:parent.descriptor.supervisor_instance_id,domain_ref:parent.receipt.domain_ref})&&
    same(value.current().payload.record.admission_receipt,parent.receipt),'worker_runtime_source_binding');
   source=value;unsubscribe=source.subscribeLost(()=>{lost=true;for(const entry of [...active.values()])withdraw(entry,'source_lost');});
   live();
  },
  async adopt(key){
   available();const preparation=prepared(key);need(preparation?.current_boot,'worker_runtime_preparation');
   const prior=find(preparation.intent.launch_id);if(prior)return view(prior);
   live();need(active.size+pending<4&&!waiting.has(preparation.intent.launch_id),'worker_runtime_capacity');pending++;waiting.add(preparation.intent.launch_id);
   let entry=null;
   try{
    const {selected,observed}=await observe(preparation.intent);live();source.assertWorkerObservation(observed);
    const row=db.transaction(()=>{
     connected();source.assertWorkerObservation(observed);const parent=core();
     const intent=preparation.intent,receipt=observed.receipt;
     need(same(observed.key,{launch_id:intent.launch_id,launch_intent_digest:hash(intent)})&&same(observed.descriptor,parent.descriptor)&&
      receipt?.role==='worker'&&receipt.gate_state==='closed'&&receipt.launch_id===intent.launch_id&&receipt.launch_intent_digest===hash(intent)&&
      receipt.member_id===intent.member_id&&same(receipt.artifact_manifest_ref,intent.artifact_manifest_ref)&&same(receipt.containment_ref,intent.containment_ref)&&
      same(receipt.domain_ref,parent.receipt.domain_ref)&&receipt.receipt_id!==parent.receipt.receipt_id&&receipt.bootstrap_id!==parent.receipt.bootstrap_id&&
      receipt.member_boot_id!==parent.receipt.member_boot_id&&same(extension.current(intent),selected),'worker_runtime_binding');
     verifyDependencies?.(preparation.intent,selected);
     need(!find(preparation.intent.launch_id),'worker_runtime_conflict');
     const runtime=crypto.randomUUID(),transaction=crypto.randomUUID(),body={format:'leafseamer-worker-runtime-binding/1',runtime_binding_id:runtime,
      service_id:service.service_id,database_instance_id:service.database_instance_id,service_boot_id:bootId,
      launch_intent:preparation.intent,clock_domain_descriptor:observed.descriptor,admission_receipt:observed.receipt,gate_state:'closed'};
     const text=canonicalize(body);need(Buffer.byteLength(text)<=524288,'worker_runtime_capacity');
     db.prepare('INSERT INTO worker_runtime_binding VALUES(?,?,?,?,?,?,?,?,?)').run(runtime,preparation.intent.launch_id,bootId,
      observed.receipt.receipt_id,observed.receipt.bootstrap_id,observed.receipt.member_boot_id,text,hash(body),transaction);
     db.prepare('INSERT INTO worker_runtime_commit VALUES(?,?,?)').run(transaction,runtime,canonicalize({kind:'worker_runtime_adopted',transaction_id:transaction,runtime_binding_id:runtime,body_digest:hash(body)}));
     return find(preparation.intent.launch_id);
    }).immediate();
    entry={row,prepared:preparation,observation:observed,stopped:false,timer:null};active.set(preparation.intent.launch_id,entry);
    check(entry);entry.timer=setTimeout(()=>{void refresh(entry);},500);entry.timer.unref();return view(row);
   }catch(error){
    if(entry)withdraw(entry,'source_changed');else retire(preparation.intent);
    if(error?.code?.startsWith('SQLITE_')){storageFailed=true;for(const other of [...active.values()])withdraw(other,'storage_failed');}
    throw error;
   }finally{pending--;waiting.delete(preparation.intent.launch_id);}
  },
  query(key){available();const value=prepared(key);return value?view(find(value.intent.launch_id)):null;},
  async refreshCurrent(key){
   available();const value=prepared(key),entry=value&&active.get(value.intent.launch_id);need(entry,'worker_runtime_unavailable');
   await refresh(entry);check(entry);return view(entry.row);
  },
  current(key){
   available();const value=prepared(key),entry=value&&active.get(value.intent.launch_id);need(entry,'worker_runtime_unavailable');
   try{check(entry);return view(entry.row);}catch(error){withdraw(entry,error?.code?.startsWith('extension_')?'approval_changed':'source_changed');throw error;}
  },
  currentInTransaction(key){
   need(db.inTransaction&&db.open,'worker_runtime_writer');const value=prepared(key),entry=value&&active.get(value.intent.launch_id);
   need(entry,'worker_runtime_unavailable');
   try{checkInWriter(entry);return view(entry.row);}catch(error){withdrawFromWriter(entry,error);throw error;}
  },
  invalidate(key){available();const value=prepared(key),entry=value&&active.get(value.intent.launch_id);if(entry)withdraw(entry,'source_changed');},
  close(){if(closed)return;closed=true;unsubscribe?.();for(const entry of [...active.values()])withdraw(entry,'closed');}
 });
}
