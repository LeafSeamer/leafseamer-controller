import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError} from './device-execution-channel.mjs';
import {readCommandRevision,unsentCommandProjection} from './command-record-store.mjs';
import {readCommandDispatch} from './command-dispatch.mjs';
import {evidenceRecord} from './command-settlement.mjs';

const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('command_unsent_'+code);};
const ref=(id,value)=>({id,revision:'1',digest:digest(value)});
const written=result=>need(result.changes===1,'storage');

function select(db,previous,commit){
 const {record,source,lifecycle}=previous,command=record.command_id,binding=source.binding,session=binding.ipc_session_id;
 const final=lifecycle.final_admission,permit=final.value.permit,hold=final.value.hold.hold_id;
 need(record.revision==='2'&&record.state.phase==='queued'&&record.state.effect_status==='not_sent'&&record.state.resource_status==='held'&&
  record.policy.max_attempts===1&&record.policy.retry_policy_ref===null&&source.policies.release.automatic_resends===false&&
  ['fixed-obs-cut-release/1','fixed-memory-release/1'].includes(source.policies.release.format),'policy');
 const ended=db.prepare('SELECT transaction_id,reason FROM execution_session_end WHERE ipc_session_id=?').raw().get(session);
 need(ended&&!db.prepare('SELECT 1 FROM command_dispatch_write WHERE permit_id=?').pluck().get(permit.permit_id),'no_write');
 const request=db.prepare('SELECT 1 FROM command_dispatch_request WHERE permit_id=?').pluck().get(permit.permit_id);
 const dispatch=request?readCommandDispatch(db,permit.permit_id):null;
 if(dispatch)need(same(dispatch.final.ref,final.ref)&&!dispatch.write&&dispatch.request.frame.ipc_session_id===session,'dispatch');
 // Guard 安装不持设备报文消费权。唯一的 DISPATCH 写入前必须提交同事务的发送尝试。
 const writes=db.prepare(`SELECT w.attempt_id FROM execution_write_attempt w JOIN execution_frame_record f USING(record_id)
  WHERE f.direction='c2w' AND f.message_type='DISPATCH' AND
  (json_extract(f.frame_jcs,'$.body.permit.command_id')=? OR json_extract(f.frame_jcs,'$.body.permit.permit_id')=?) LIMIT 1`).pluck().get(command,permit.permit_id);
 need(!writes,'attempt');
 const end={transaction_id:ended[0],reason:ended[1]},cut={format:'command-unsent-cut/1',binding,command_id:command,
  permit_id:permit.permit_id,final_admission_ref:final.ref,dispatch_ref:dispatch?.ref??null,end},
  cutRef=ref(command+'.unsent-cut',cut),closed={format:'command-unsent-future-writes-closed/1',cut_ref:cutRef,automatic_resends:false};
 const release=evidenceRecord('release',{evidence_id:command+'.never-sent',command_id:command,scope:record.scope,device_id:binding.device_id,
  hold_id:hold,cut_ref:cutRef,kind:'never_sent',policy_ref:record.policy.release_policy_ref,
  future_writes_closed_ref:ref(command+'.unsent-closed',closed),settlement_proof_ref:null});
 const projection=unsentCommandProjection(previous,release);
 const value={format:'command-unsent-closure/1',command_id:command,commit_id:commit,revision:'3',cut,future_writes_closed:closed,
  previous_state_ref:record.state_ref,record_digest:projection.record.record_digest,state_digest:digest(projection.state),evidence:[release]};
 return {projection,value,audit:canonical({kind:'command_finished',command_id:command,revision:'3',commit_ref:ref(commit,value)})};
}

export function readUnsentCommand(db,initial,head,row){
 const id=initial.source.command_id,commit=head[1],previous=readCommandRevision(db,id,'2');
 const original=db.prepare(`SELECT hold_id,permit_id,ipc_session_id,end_transaction_id,end_reason,body_jcs,body_digest
  FROM command_unsent_closure WHERE command_id=? AND commit_id=?`).raw().get(id,commit);
 const {projection:p,value:v,audit}=select(db,previous,commit),body=canonical(v),hash=digest(v);
 need(same(original,[v.evidence[0].body.hold_id,v.cut.permit_id,v.cut.binding.ipc_session_id,v.cut.end.transaction_id,v.cut.end.reason,body,hash])&&
  row[0]===canonical(p.record)&&row[1]===p.record.record_digest&&row[2]===canonical(p.state)&&row[3]===v.state_digest&&
  row[4]===canonical(p.manifest)&&row[5]===digest(p.manifest)&&row[6]===body&&row[7]===hash&&row[8]===audit&&row[9]===audit,'integrity');
 return {...previous,record:p.record,lifecycle:{...previous.lifecycle,commit_ref:ref(commit,v),unsent:v}};
}

export function finishUnsentCommands(db){
 need(db.inTransaction,'writer');
 const pending=db.prepare(`SELECT h.command_id,h.commit_id FROM command_lifecycle_head h JOIN command_final_admission f USING(command_id)
  JOIN device_execution_binding b USING(binding_id) JOIN execution_session_end e USING(ipc_session_id)
  WHERE h.revision=2 AND h.commit_id=f.commit_id AND NOT EXISTS(SELECT 1 FROM command_dispatch_write w WHERE w.permit_id=f.permit_id)
  ORDER BY h.command_id LIMIT 16`).raw().all();
 for(const [id,previousCommit] of pending){
  const previous=readCommandRevision(db,id,'2'),commit=crypto.randomUUID();
  const {projection:p,value:v,audit}=select(db,previous,commit),body=canonical(v),hash=digest(v);
  written(db.prepare('INSERT INTO command_lifecycle_revision VALUES(?,3,?,?,?,?,?,?,?)')
   .run(id,canonical(p.record),p.record.record_digest,canonical(p.state),v.state_digest,canonical(p.manifest),digest(p.manifest),commit));
  written(db.prepare('INSERT INTO command_unsent_closure VALUES(?,?,?,?,?,?,?,?,?)').run(id,v.evidence[0].body.hold_id,v.cut.permit_id,
   v.cut.binding.ipc_session_id,v.cut.end.transaction_id,v.cut.end.reason,commit,body,hash));
  written(db.prepare('UPDATE command_lifecycle_head SET revision=3,commit_id=? WHERE command_id=? AND revision=2 AND commit_id=?')
   .run(commit,id,previousCommit));
  written(db.prepare('INSERT INTO command_lifecycle_commit VALUES(?,?,3,?,?,?,?,?)').run(commit,id,body,hash,audit,crypto.randomUUID(),audit));
 }
}
