import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {readCommandRecord} from './command-record-store.mjs';
import {readRetiredPreparation} from './command-retired-history.mjs';
import {confirmedRetirement} from './run-protection-exits.mjs';
import {memoExecutionRead} from './execution-read-view.mjs';
import {currentControlSource} from './device-control-source.mjs';

const need=(ok,code)=>{if(!ok)throw new IdentityError('obs_prior_execution_'+code);};
const ref=(id,value)=>({id,revision:'1',digest:digest(value)});
function original(text,checksum){
 const value=JSON.parse(text);need(canonical(value)===text&&digest(value)===checksum,'integrity');return value;
}

function closedExecution(db,device,bindingId,activeSession,resource){
 return memoExecutionRead(db,'obs-prior-execution',[bindingId,activeSession,resource],()=>{
 const row=db.prepare(`SELECT b.body_jcs,b.body_digest,s.ipc_session_id,e.transaction_id,e.reason,p.launch_id,p.intent_digest,p.service_boot_id,
  p.intent_jcs,r.runtime_id,r.body_jcs,r.body_digest
  FROM device_execution_binding b JOIN execution_session s USING(ipc_session_id)
  JOIN execution_session_end e USING(ipc_session_id)
  JOIN worker_runtime_binding r ON r.runtime_id=s.runtime_id JOIN worker_launch_preparation p USING(launch_id)
  WHERE b.binding_id=? AND b.device_id=? AND s.ipc_session_id<>?`).raw().get(bindingId,device,activeSession);
 need(row,'ended');const [text,hash,session,endId,reason,launch,launchDigest,boot,intentText,runtimeId,runtimeText,runtimeHash]=row;
 const old=original(text,hash),intent=original(intentText,launchDigest),runtime=original(runtimeText,runtimeHash);
 need(old.binding_id===bindingId&&old.binding.device_id===device&&old.binding.ipc_session_id===session&&
  old.transport_profile.format==='leafseamer-obs-cut-transport/1'&&same(old.transport_profile.resource_ref,resource)&&
  runtime.runtime_binding_id===runtimeId&&runtime.service_boot_id===boot&&same(runtime.launch_intent,intent)&&
  runtime.admission_receipt.member_boot_id===old.binding.worker_boot_id&&same(old.runtime_binding_ref.digest,runtimeHash)&&
  intent.launch_id===launch&&intent.object_scope.device_ids.includes(device),'binding');
 const retirement=confirmedRetirement(db,{launch_id:launch,launch_intent_digest:launchDigest,service_boot_id:boot},intent,runtimeId);
 need(retirement?.state==='retired','retirement');
 const commands=db.prepare('SELECT command_id FROM command_admission_source WHERE binding_id=? ORDER BY command_id').pluck().all(bindingId)
  .map(id=>{
   const saved=readCommandRecord(db,id),{record,lifecycle}=saved;
   need(record.state.phase==='finished'&&record.state.resource_status==='clear'&&same(saved.source.binding,old.binding),'holds');
   let evidence=null;
   if(lifecycle?.reconciliation){
    evidence=lifecycle.reconciliation.evidence[2].source_ref;
    need(record.state.outcome==='unknown'&&db.prepare('SELECT 1 FROM command_hold_clearance WHERE command_id=?').pluck().get(id),'reconciled');
   }else if(lifecycle?.unsent){
    evidence=lifecycle.unsent.evidence[0].source_ref;
    need(record.state.effect_status==='not_sent'&&db.prepare('SELECT 1 FROM command_hold_clearance WHERE command_id=?').pluck().get(id),'unsent');
   }else if(lifecycle?.settlement?.succeeded){
    const stored=db.prepare('SELECT prepare_id,body_digest FROM command_preparation_retirement WHERE command_id=?').raw().get(id);
    need(stored,'preparation');evidence=readRetiredPreparation(db,{id:stored[0]+'.retirement',revision:'1',digest:stored[1]}).ref;
   }else need(record.attempts.length===0&&record.state.effect_status==='not_sent'&&lifecycle?.proof,'unsent');
   return {command_id:id,state_ref:record.state_ref,closure_ref:lifecycle.commit_ref,evidence_ref:evidence};
  });
 const holds=db.prepare(`SELECT h.command_id FROM command_device_hold h JOIN command_final_admission f USING(command_id)
  WHERE f.binding_id=? AND NOT EXISTS(SELECT 1 FROM command_hold_clearance c WHERE c.hold_id=h.hold_id)`).pluck().all(bindingId);
 need(holds.length===0,'holds');
 return {binding_ref:ref(bindingId,old),ipc_session_id:session,session_end:{transaction_id:endId,reason},retirement,commands};
 });
}

export function captureObsPriorExecution(db,device,activeSession,resource){
 need(db.inTransaction,'writer');
 const ids=db.prepare('SELECT binding_id FROM device_execution_binding WHERE device_id=? AND ipc_session_id<>? ORDER BY binding_id LIMIT 257')
  .pluck().all(device,activeSession);
 need(ids.length<=256,'capacity');
 return ids.map(id=>closedExecution(db,device,id,activeSession,resource));
}

export function verifyObsPriorExecution(db,device,activeSession,resource,values){
 need(db.inTransaction&&Array.isArray(values)&&values.length>0&&values.length<=256,'records');
 let previous='';
 for(const entry of values){
  const id=entry?.binding_ref?.id;
  need(typeof id==='string'&&id>previous&&same(entry,closedExecution(db,device,id,activeSession,resource)),'records');
  previous=id;
 }
}

export function selectObsLaunchReplacement(db,operation,intent,bootId,allowHistorical){
 need(db.inTransaction&&intent.object_scope.device_ids.length===1,'replacement_scope');
 const [device]=intent.object_scope.device_ids;
 const rows=db.prepare(`SELECT p.launch_id,p.intent_digest,p.service_boot_id,p.intent_jcs,r.runtime_id,b.body_jcs,b.body_digest,e.ipc_session_id,e.transaction_id
  FROM worker_launch_preparation p JOIN worker_runtime_binding r USING(launch_id)
  JOIN execution_session s ON s.runtime_id=r.runtime_id JOIN execution_session_end e USING(ipc_session_id)
  JOIN device_execution_binding b ON b.ipc_session_id=s.ipc_session_id AND b.device_id=?
  WHERE p.activation_operation_id=? AND NOT EXISTS(SELECT 1 FROM obs_worker_launch_replacement x WHERE x.previous_launch_id=p.launch_id)`)
  .raw().all(device,operation);
 need(rows.length===1,'replacement_previous');
 const [launch,launchDigest,boot,intentText,runtimeId,bindingText,bindingHash,session,end]=rows[0];
 const old=original(intentText,launchDigest),binding=original(bindingText,bindingHash);
 const historical=boot!==bootId;
 need(!historical||allowHistorical,'replacement_boot');
 const withoutIdentity=({launch_id,member_id,supervisor_instance_id,runtime_generation,containment_ref:{group_id,...containment},...value})=>
  ({...value,containment_ref:containment,...(!historical&&{supervisor_instance_id,runtime_generation})});
 need(same(withoutIdentity(old),withoutIdentity(intent))&&binding.transport_profile.format==='leafseamer-obs-cut-transport/1','replacement_binding');
 const {current,authority}=currentControlSource(db,device);
 const acquired=db.prepare(`SELECT o.operation_id,o.body_jcs,o.body_digest,e.body_jcs,e.body_digest FROM control_operation_revision o
  JOIN control_barrier_evidence e USING(operation_id,commit_id) WHERE o.commit_id=?`).raw().get(authority.ref.id);
 need(acquired&&current.value.mode==='manual'&&current.value.holder&&current.value.pending_operation_id===null&&
  current.value.gate_state==='protected','replacement_control');
 const [acquisitionId,text,hash,evidenceText,evidenceDigest]=acquired,acquisition=original(text,hash),evidence=original(evidenceText,evidenceDigest);
 need(acquisition.device_id===device&&acquisition.kind==='acquire'&&acquisition.state==='effective'&&
  acquisition.target.version===current.value.effective_version&&acquisition.target.holder?.principal_id===current.value.holder.principal_id,
  'replacement_control');
 const target={launch_id:launch,launch_intent_digest:launchDigest,service_boot_id:boot};
 const retirement=confirmedRetirement(db,target,old,runtimeId,acquisitionId);
 const receipt=evidence.receipts[evidence.targets.findIndex(value=>same(value,target))];
 need(retirement?.state==='retired'&&evidence.service_boot_id===bootId&&
  (!historical||receipt?.historical_observation?.receiving_service_boot_id===bootId),'replacement_retirement');
 return {format:'leafseamer-obs-worker-launch-replacement/1',activation_operation_id:operation,launch_id:intent.launch_id,
  launch_intent_digest:digest(intent),previous_launch_id:launch,previous_session_id:session,previous_end_transaction_id:end,
  control_operation_id:acquisitionId,control_ref:authority.ref,retirement};
}
