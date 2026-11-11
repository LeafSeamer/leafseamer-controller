import crypto from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import canonicalize from 'canonicalize';
import {controlNeed as need,controlHash as hash,controlSame as same,controlFrozen as frozen} from './device-control-value.mjs';
import {classifyControlCommands,readControlCommandCut} from './control-command-cut.mjs';

// 当前产品只有受登记监督的模块出口；所有历史准备均进入切点，未知旧boot不作空集合。
export function deviceControlBarrier({db,bootId,authorization,runtime,isOpen}){
 const issued=new WeakSet();
 const targets=id=>db.prepare('SELECT launch_id,launch_intent_digest,service_boot_id FROM control_barrier_target WHERE operation_id=? ORDER BY launch_id').raw().all(id)
  .map(([launch_id,launch_intent_digest,service_boot_id])=>({launch_id,launch_intent_digest,service_boot_id}));
 function pending(operation){
  need(isOpen()&&db.open,'unavailable');const row=db.prepare('SELECT r.body_jcs,r.body_digest FROM control_operation_revision r JOIN control_operation_head h USING(operation_id,revision) WHERE operation_id=?').raw().get(operation.operation_id);
  need(row&&hash(JSON.parse(row[0]))===row[1],'integrity');const current=JSON.parse(row[0]);
  need(['pending','indeterminate'].includes(current.state)&&current.device_id===operation.device_id&&same(current.target,operation.target),'conflict');
  if(Number(db.pragma('user_version',{simple:true}))>=58){
   const read=()=>readControlCommandCut(db,operation);if(db.inTransaction)read();else db.transaction(read)();
  }else need(!db.prepare("SELECT 1 FROM ca_adjudication a JOIN ca_request_key k USING(key_id) WHERE k.device_id=? AND a.decision!='rejected'").pluck().get(operation.device_id),'command_barrier_required');
 }
 function historical(target){
  const rows=db.prepare('SELECT operation_id,body_jcs,body_digest FROM control_barrier_evidence ORDER BY operation_id').raw().all();
  for(const [operation_id,text,digest] of rows){
   const body=JSON.parse(text);need(canonicalize(body)===text&&hash(body)===digest,'integrity');
   const index=body.targets.findIndex(value=>same(value,target));if(index<0)continue;
   const receipt=body.receipts[index];need(receipt&&same(receipt.key,{launch_id:target.launch_id,launch_intent_digest:target.launch_intent_digest})&&
    (receipt.record===null&&receipt.retirement===null||receipt.record?.state==='retired'&&receipt.retirement?.result==='confirmed_empty'),'old_exit_unresolved');
   return frozen({...receipt,prior_barrier:{operation_id,digest}});
  }
  need(false,'old_exit_unresolved');
 }
 return Object.freeze({
  domain(){need(isOpen()&&db.open,'unavailable');try{return authorization.domain();}
   catch(error){
    // 已知监督来源缺失是资格拒绝；未知异常及SQLite失败仍交由writer关闭服务。
    if(/^(worker_authorization_(source|source_changed|unavailable)|supervisor_[a-z_]+)$/.test(error?.code??''))need(false,'source_unavailable');
    throw error;
   }},
  selectCoreSource(){need(isOpen()&&db.open,'unavailable');return authorization.selectCoreSource();},
  currentCoreSource(reference){need(isOpen()&&db.open,'unavailable');return authorization.currentCoreSource(reference);},
  async protect(operation){
   need(!db.inTransaction,'writer');pending(operation);const domain=authorization.domain(),selected=targets(operation.operation_id),receipts=[];
   for(const target of selected){
    if(target.service_boot_id!==bootId){receipts.push(historical(target));continue;}
    const key={launch_id:target.launch_id,launch_intent_digest:target.launch_intent_digest};runtime.invalidate(key);
    const deadline=performance.now()+5000;let result;
    for(;;){pending(operation);try{result=await authorization.retireForControl(key);break;}catch(error){
     if(error.code!=='supervisor_indeterminate'||performance.now()>=deadline)throw error;await delay(25);
    }}
    receipts.push(result);
   }
   pending(operation);need(same(authorization.domain().ref,domain.ref)&&same(targets(operation.operation_id),selected),'barrier_changed');
   const commandSelection=Number(db.pragma('user_version',{simple:true}))>=58?db.transaction(()=>classifyControlCommands(db,operation))():null;
   const result=frozen({format:'leafseamer-control-exit-retirement/1',selection_id:crypto.randomUUID(),operation_id:operation.operation_id,
    device_id:operation.device_id,control_epoch:operation.expected_control.epoch,target_version:operation.target.version,service_boot_id:bootId,
    domain_ref:domain.ref,targets:selected,receipts,...(commandSelection?{command_selection:commandSelection}:{})});issued.add(result);return result;
  },
  verify(operation,evidence){
   need(db.inTransaction&&issued.has(evidence),'barrier_proof');pending(operation);
   need(same(authorization.domain().ref,evidence.domain_ref),'barrier_changed');
   need(evidence.operation_id===operation.operation_id&&evidence.service_boot_id===bootId&&same(evidence.targets,targets(operation.operation_id)),'barrier_changed');
   // T3期间新增准备由数据库触发器阻止；再核全集，不能仅以数量匹配替代覆盖。
   const actual=db.prepare('SELECT p.launch_id,p.intent_digest,p.service_boot_id FROM worker_launch_preparation p JOIN worker_launch_device d USING(launch_id) WHERE d.device_id=? ORDER BY p.launch_id').raw().all(operation.device_id)
    .map(([launch_id,launch_intent_digest,service_boot_id])=>({launch_id,launch_intent_digest,service_boot_id}));
   need(canonicalize(actual)===canonicalize(evidence.targets),'barrier_coverage');
   if(Number(db.pragma('user_version',{simple:true}))>=58)need(same(evidence.command_selection,classifyControlCommands(db,operation)),'command_barrier_changed');
  }
 });
}
