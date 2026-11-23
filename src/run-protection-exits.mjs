import {readRunFence} from './execution-run-fence.mjs';
import {controlNeed as need,controlHash as hash,controlSame as same,controlRead as document} from './device-control-value.mjs';

function confirmedRetirement(db,target,intent,runtimeId){
 const rows=db.prepare(`SELECT e.operation_id,e.body_jcs,e.body_digest,o.body_jcs,o.body_digest FROM control_barrier_target t
  JOIN control_barrier_evidence e USING(operation_id) JOIN control_change_commit c USING(commit_id)
  JOIN control_operation_revision o ON o.operation_id=e.operation_id AND o.commit_id=e.commit_id
  WHERE t.launch_id=? AND t.launch_intent_digest=? AND t.service_boot_id=? AND c.kind='effective' ORDER BY e.operation_id`)
  .raw().all(target.launch_id,target.launch_intent_digest,target.service_boot_id);
 const {service_boot_id,...key}=target;
 for(const [operationId,text,digest,operationText,operationDigest] of rows){
  const evidence=document(text,digest),operation=document(operationText,operationDigest);
  const index=evidence.targets.findIndex(value=>same(value,target)),receipt=evidence.receipts[index];
  need(evidence.format==='leafseamer-control-exit-retirement/1'&&evidence.operation_id===operationId&&
   operation.operation_id===operationId&&operation.state==='effective'&&same(operation.barrier_selection_ref,{id:evidence.selection_id,revision:'1',digest})&&
   receipt&&same(receipt.key,key),'run_protection_retirement');
  if(receipt.prior_barrier)continue;
  need(evidence.service_boot_id===service_boot_id,'run_protection_retirement');
  const {fence,record,retirement}=receipt;
  const saved=db.prepare(`SELECT s.body_jcs,s.body_digest,a.body_jcs FROM worker_fence_snapshot s JOIN worker_fence_ack a
   USING(service_boot_id,revision) WHERE s.service_boot_id=? AND s.revision=?`).raw().get(service_boot_id,Number(fence.revision));
  need(saved&&same(document(saved[0],saved[1]),fence),'run_protection_retirement');
  const fenceAck=JSON.parse(saved[2]),{digest:snapshotDigest,...snapshot}=fence;
  need(hash(snapshot)===snapshotDigest&&fenceAck.revision===fence.revision&&fenceAck.snapshot_digest===snapshotDigest&&fenceAck.journal_committed===true&&
   same(fence.scope.domain_ref,evidence.domain_ref)&&fence.scope.supervisor_instance_id===intent.supervisor_instance_id&&fence.scope.service_id===intent.service_id&&
   fence.items.some(item=>same(item,{...key,disposition:'deny'}))&&
   db.prepare('SELECT 1 FROM worker_launch_denial WHERE launch_id=?').pluck().get(key.launch_id),'run_protection_retirement');
  const barrier_ref={id:evidence.selection_id,revision:'1',digest},fence_ref={revision:fence.revision,digest:snapshotDigest};
  if(record===null&&retirement===null&&!runtimeId)return {state:'never_started',barrier_ref,fence_ref};
  if(!record||record.state!=='retired'||retirement?.result!=='confirmed_empty')continue;
  need(same(record.key,key)&&record.supervisor_instance_id===intent.supervisor_instance_id&&same(record.retirement_evidence,retirement)&&
   retirement.service_id===intent.service_id&&retirement.target_scope==='member_group'&&same(retirement.target_member_ids,[intent.member_id])&&
   same(retirement.containment_ref,intent.containment_ref)&&same(retirement.old_domain_ref,evidence.domain_ref)&&same(retirement.evaluator_domain_ref,evidence.domain_ref)&&
   retirement.launch_intake_closed===true&&retirement.os_observation_refs.length>0,'run_protection_retirement');
  return {state:'retired',barrier_ref,fence_ref,retirement_ref:{id:retirement.evidence_id,revision:'1',digest:hash(retirement)}};
 }
 return null;
}

function acknowledgedExit(db,deviceBinding,session,plan){
 const id=db.prepare(`SELECT x.record_id FROM execution_run_fence_frame x
  JOIN execution_run_fence_frame a ON a.request_record_id=x.record_id
  JOIN run_generation_denial d ON d.snapshot_revision=x.denial_revision
  WHERE x.device_binding_id=? AND x.phase='request' AND a.phase='ack' AND d.origin_service_id=? AND d.origin_database_instance_id=?
   AND d.run_id=? AND d.floor>=? ORDER BY d.deny_revision DESC LIMIT 1`).pluck().get(deviceBinding,plan.origin_scope.authority_service_id,
   plan.origin_scope.database_instance_id,plan.run_id,plan.deny_through_generation.padStart(20,'0'));
 if(!id)return null;
 const {request,ack}=readRunFence(db,session,id),{selector,all_write_exits_fenced}=ack.frame.body;
 need(request.bindingRef.id===deviceBinding&&all_write_exits_fenced&&same(selector.origin_scope,plan.origin_scope)&&selector.run_id===plan.run_id&&
  BigInt(selector.deny_through_generation)>=BigInt(plan.deny_through_generation),'run_protection_ack');
 return {ipc_session_id:session.ipc_session_id,request_ref:request.recordRef,ack_ref:ack.recordRef};
}

export function readRunProtectionExits(db,deviceId,plan){
 need(db.inTransaction,'run_protection_writer');
 const launches=db.prepare(`SELECT p.launch_id,p.intent_digest,p.service_boot_id,p.intent_jcs,r.runtime_id,s.binding_jcs,s.binding_digest
  FROM worker_launch_device d JOIN worker_launch_preparation p USING(launch_id)
  LEFT JOIN worker_runtime_binding r USING(launch_id) LEFT JOIN execution_session s USING(runtime_id)
  WHERE d.device_id=? ORDER BY p.launch_id COLLATE BINARY`).raw().all(deviceId);
 const exits=[],acknowledgements=[];
 for(const [launch_id,launch_intent_digest,service_boot_id,text,runtimeId,sessionText,sessionDigest] of launches){
  const target={launch_id,launch_intent_digest,service_boot_id},intent=document(text,launch_intent_digest);
  need(intent.launch_id===launch_id&&intent.object_scope.device_ids.includes(deviceId),'run_protection_launch');
  const retired=confirmedRetirement(db,target,intent,runtimeId);
  if(retired){exits.push({...target,...retired});continue;}
  const session=sessionText===null?null:document(sessionText,sessionDigest);
  const bindings=session?db.prepare('SELECT binding_id FROM device_execution_binding WHERE ipc_session_id=? AND device_id=? ORDER BY binding_id')
   .pluck().all(session.ipc_session_id,deviceId):[];
  const proofs=bindings.map(bindingId=>acknowledgedExit(db,bindingId,session,plan));
  const covered=proofs.filter(Boolean);acknowledgements.push(...covered);
  exits.push({...target,state:proofs.length>0&&covered.length===proofs.length?'fenced':'pending'});
 }
 return {device_id:deviceId,exits,acknowledgements,state:exits.length>0&&exits.every(exit=>exit.state!=='pending')?'acknowledged':'pending'};
}
