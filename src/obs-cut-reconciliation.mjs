import crypto from 'node:crypto';
import {IdentityError} from './identity-error.mjs';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {controlActor} from './device-control-value.mjs';
import {currentControlSource,readControlSource} from './device-control-source.mjs';
import {confirmedRetirement} from './run-protection-exits.mjs';
import {readCommandRecord,readCommandRevision,reconciledObsCutProjection} from './command-record-store.mjs';
import {evidenceRecord,readCommandClosure,readInterruptedObsCutEffect} from './command-settlement.mjs';

const need=(ok,code)=>{if(!ok)throw new IdentityError('obs_cut_reconciliation_'+code);};
const ref=(id,value)=>({id,revision:'1',digest:digest(value)});
const written=result=>need(result.changes===1,'storage');
const read=(text,hash)=>{const value=JSON.parse(text);need(canonical(value)===text&&digest(value)===hash,'integrity');return value;};
const resolver=(proof)=>({...controlActor(proof),session_id:proof.session_id,credential_id:proof.credential_id,authorization_digest:proof.authorization_digest});
const receipt=({command_id,state_ref,state})=>({command_id,state_ref,resolution_ref:state.resolution_ref,resource_evidence_refs:state.resource_evidence_refs});

function retiredWriter(db,previous,control,actor){
 const {source}=previous,device=source.binding.device_id;
 const row=db.prepare(`SELECT t.launch_id,t.launch_intent_digest,t.service_boot_id,p.intent_jcs,r.runtime_id,
  o.operation_id,o.body_jcs,o.body_digest,json_extract(e.body_jcs,'$.service_boot_id') FROM worker_launch_preparation p JOIN worker_runtime_binding r USING(launch_id)
  JOIN execution_session s ON s.runtime_id=r.runtime_id
  JOIN control_operation_revision o ON o.commit_id=? JOIN control_barrier_evidence e USING(operation_id,commit_id)
  JOIN control_barrier_target t ON t.operation_id=o.operation_id AND t.launch_id=p.launch_id
  WHERE s.ipc_session_id=? AND t.launch_intent_digest=p.intent_digest AND t.service_boot_id=p.service_boot_id`)
  .raw().get(control.ref.id,source.binding.ipc_session_id);
 need(row,'retirement');
 const [launch_id,launch_intent_digest,service_boot_id,intent,runtime,operationId,text,hash,bootId]=row;
 const operation=read(text,hash),holder=controlActor(actor);
 need(control.value.mode==='manual'&&control.value.gate_state==='protected'&&control.value.pending_operation_id===null&&control.value.holder&&
  operation.kind==='acquire'&&operation.state==='effective'&&operation.device_id===device&&operation.target.version===control.value.effective_version&&
  same(operation.target.holder,holder)&&same(controlActor(control.value.holder),holder),'control');
 const target={launch_id,launch_intent_digest,service_boot_id};
 const retirement=confirmedRetirement(db,target,read(intent,launch_intent_digest),runtime,operationId);
 need(retirement?.state==='retired','retirement');return {boot_id:bootId,control_ref:control.ref,operation_id:operationId,retirement};
}
function select(db,previous,closedWriter,actor,commit){
 const {source,record,lifecycle}=previous,id=record.command_id;
 need(record.revision==='5'&&record.state.outcome==='unknown'&&record.state.resource_status==='unresolved'&&lifecycle?.interruption&&
  record.origin==='manual'&&record.policy.max_attempts===1&&record.policy.retry_policy_ref===null&&
  source.policies.release.format==='fixed-obs-cut-release/1'&&source.policies.release.automatic_resends===false,'state');
 const permit=lifecycle.interruption.permit_id;
 need(lifecycle.interruption.report_ref&&lifecycle.interruption.evidence_ref&&
  db.prepare('SELECT 1 FROM command_closure_request WHERE permit_id=?').pluck().get(permit),'effect');
 const closed=readCommandClosure(db,permit),effect=readInterruptedObsCutEffect(db,closed);
 need(!closed.ack&&effect&&same(closed.source.initial.source.binding,source.binding)&&
  same(effect.report_ref,lifecycle.interruption.report_ref)&&same(effect.observation_ref,lifecycle.interruption.evidence_ref),'effect');
 const futureWrites={format:'fixed-obs-cut-retired-writer/1',binding:source.binding,cut_ref:closed.ref,
  end:lifecycle.interruption.end,writer:closedWriter,automatic_resends:false};
 const decision=evidenceRecord('decision',{evidence_id:id+'.reconcile-decision',command_id:id,scope:record.scope,kind:'resolution',
  policy_ref:record.policy.completion_policy_ref,retry_policy_ref:null,attempt_ids:record.state.attempt_ids,achieved:null,effect_status:'verified',resolved_outcome:'succeeded'});
 const body={resolution_id:id+'.resolution',command_id:id,scope:record.scope,original_terminal_revision:record.state.terminal_revision,
  revision:'1',resolved_outcome:'succeeded',evidence_refs:[decision.source_ref],resolver_ref:ref(commit+'.resolver',actor)};
 const unsigned={command_id:id,scope:record.scope,source_ref:ref(body.resolution_id,body),kind:'resolution',body:{...body,resolution_digest:digest(body)}};
 const resolution={...unsigned,view_digest:digest(unsigned)};
 const release=evidenceRecord('release',{evidence_id:id+'.reconcile-release',command_id:id,scope:record.scope,device_id:source.binding.device_id,
  hold_id:closed.source.dispatch.final.value.ids.hold,cut_ref:closed.ref,kind:'module_settled',policy_ref:record.policy.release_policy_ref,
  future_writes_closed_ref:ref(id+'.retired-writer',futureWrites),settlement_proof_ref:ref(id+'.reconciled-effect',effect)});
 const evidence=[decision,resolution,release],projection=reconciledObsCutProjection(previous,evidence);
 const value={format:'obs-cut-command-reconciliation/1',command_id:id,previous_state_ref:record.state_ref,
  previous_commit_ref:lifecycle.commit_ref,permit_id:permit,hold_id:release.body.hold_id,commit_id:commit,revision:'6',
  resolver:actor,effect,future_writes_closed:futureWrites,record_digest:projection.record.record_digest,state_digest:digest(projection.state),evidence};
 return {projection,value,audit:canonical({kind:'command_reconciled',command_id:id,revision:'6',commit_ref:ref(commit,value)})};
}

export function reconcileObsCut(db,request,proof,bootId,recheck){
 need(db.inTransaction&&request&&Object.keys(request).sort().join(',')==='command_id,expected_state_ref'&&
  typeof request.command_id==='string'&&request.command_id.length<=128,'input');
 const current=readCommandRecord(db,request.command_id),device=current.source.binding.device_id,{current:view,authority}=currentControlSource(db,device);
 need(view.value.mode==='manual'&&view.value.gate_state==='protected'&&view.value.pending_operation_id===null&&view.value.holder&&
  same(controlActor(view.value.holder),controlActor(proof)),'control');
 const actor=resolver(proof),old=current.lifecycle?.reconciliation;
 if(old){need(same(old.previous_state_ref,request.expected_state_ref)&&same(controlActor(old.resolver),controlActor(actor)),'conflict');return receipt(current.record);}
 need(same(current.record.state_ref,request.expected_state_ref),'conflict');
 const writer=retiredWriter(db,current,authority,actor);need(writer.boot_id===bootId,'retirement');
 const commit=crypto.randomUUID(),{projection:p,value:v,audit}=select(db,current,writer,actor,commit),body=canonical(v),hash=digest(v);
 recheck();
 written(db.prepare('INSERT INTO command_lifecycle_revision VALUES(?,6,?,?,?,?,?,?,?)')
  .run(v.command_id,canonical(p.record),v.record_digest,canonical(p.state),v.state_digest,canonical(p.manifest),digest(p.manifest),commit));
 written(db.prepare('INSERT INTO obs_cut_reconciliation VALUES(?,?,?,?,?,?,?)')
  .run(v.command_id,v.hold_id,v.permit_id,writer.operation_id,commit,body,hash));
 written(db.prepare('UPDATE command_lifecycle_head SET revision=6,commit_id=? WHERE command_id=? AND revision=5 AND commit_id=?')
  .run(commit,v.command_id,current.lifecycle.commit_ref.id));
 written(db.prepare('INSERT INTO command_lifecycle_commit VALUES(?,?,6,?,?,?,?,?)').run(commit,v.command_id,body,hash,audit,crypto.randomUUID(),audit));
 return receipt(readCommandRecord(db,v.command_id).record);
}

export function readObsCutReconciliation(db,initial,head,row){
 const id=initial.source.command_id,commit=head[1],previous=readCommandRevision(db,id,'5');
 const saved=db.prepare('SELECT hold_id,permit_id,operation_id,body_jcs,body_digest FROM obs_cut_reconciliation WHERE command_id=? AND commit_id=?').raw().get(id,commit);
 need(saved,'integrity');const original=read(saved[3],saved[4]);
 const control=readControlSource(db,previous.source.binding.device_id,original.future_writes_closed.writer.control_ref.revision);
 const writer=retiredWriter(db,previous,control,original.resolver);
 const {projection:p,value:v,audit}=select(db,previous,writer,original.resolver,commit);
 need(same(saved,[v.hold_id,v.permit_id,writer.operation_id,canonical(v),digest(v)])&&row[0]===canonical(p.record)&&row[1]===v.record_digest&&
  row[2]===canonical(p.state)&&row[3]===v.state_digest&&row[4]===canonical(p.manifest)&&row[5]===digest(p.manifest)&&
  row[6]===saved[3]&&row[7]===saved[4]&&row[8]===audit&&row[9]===audit,'integrity');
 return {...previous,record:p.record,lifecycle:{...previous.lifecycle,commit_ref:ref(commit,v),reconciliation:v}};
}
