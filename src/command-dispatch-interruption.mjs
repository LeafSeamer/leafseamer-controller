import crypto from 'node:crypto';
import {canonical,digest} from './auth-clock-value.mjs';
import {DeviceExecutionError} from './device-execution-channel.mjs';
import {interruptedCommandProjection,readCommandRevision} from './command-record-store.mjs';
import {commitCommandSettlement} from './command-settlement.mjs';

const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('command_interruption_'+code);};
const ref=(id,value)=>({id,revision:'1',digest:digest(value)});
const written=result=>need(result.changes===1,'storage');

function select(db,previous,commit){
 const {record,source,lifecycle}=previous,command=record.command_id,session=source.binding.ipc_session_id;
 const permit=lifecycle.final_admission.value.permit.permit_id,dispatch=lifecycle.dispatch;
 const ended=db.prepare('SELECT transaction_id,reason FROM execution_session_end WHERE ipc_session_id=?').raw().get(session);
 need(ended&&dispatch.write_ref&&Boolean(dispatch.report_ref)===(record.revision==='4'),'source');
 need(!db.prepare('SELECT 1 FROM command_closure_ack WHERE permit_id=?').pluck().get(permit),'closure_ack');
 const projection=interruptedCommandProjection(previous,record),{state}=projection;
 const value={format:'command-dispatch-interruption/1',command_id:command,permit_id:permit,ipc_session_id:session,
  end:{transaction_id:ended[0],reason:ended[1]},commit_id:commit,revision:state.revision,previous_state_ref:record.state_ref,
  dispatch_ref:dispatch.ref,write_ref:dispatch.write_ref,report_ref:dispatch.report_ref,evidence_ref:dispatch.evidence_ref,
  record_digest:projection.record.record_digest,state_digest:digest(state)};
 const audit=canonical({kind:'command_finished',command_id:command,revision:state.revision,commit_ref:ref(commit,value)});
 return {projection,value,audit};
}

export function readCommandInterruption(db,initial,head,row){
 const [revision,commit]=head,command=initial.source.command_id;
 const original=db.prepare(`SELECT permit_id,ipc_session_id,end_transaction_id,end_reason,previous_revision,body_jcs,body_digest
  FROM command_dispatch_interruption WHERE command_id=? AND commit_id=?`).raw().get(command,commit);
 need(original&&[4,5].includes(revision)&&original[4]===revision-1,'revision');
 const previous=readCommandRevision(db,command,String(original[4]));
 const {projection:p,value:v,audit}=select(db,previous,commit),body=canonical(v),hash=digest(v);
 need(original[0]===v.permit_id&&original[1]===v.ipc_session_id&&original[2]===v.end.transaction_id&&original[3]===v.end.reason&&
  original[5]===body&&original[6]===hash&&row[0]===canonical(p.record)&&row[1]===p.record.record_digest&&
  row[2]===canonical(p.state)&&row[3]===v.state_digest&&row[4]===canonical(p.manifest)&&row[5]===digest(p.manifest)&&
  row[6]===body&&row[7]===hash&&row[8]===audit&&row[9]===audit,'integrity');
 return {...previous,record:p.record,lifecycle:{...previous.lifecycle,commit_ref:ref(commit,v),interruption:v}};
}

export function finishInterruptedDispatches(db){
 need(db.inTransaction,'writer');
 const pending=db.prepare(`SELECT h.command_id,h.revision,h.commit_id,r.permit_id,a.permit_id
  FROM command_lifecycle_head h JOIN command_final_admission f USING(command_id)
  JOIN command_dispatch_request r USING(permit_id) JOIN execution_frame_record w ON w.record_id=r.record_id
  JOIN execution_session_end e USING(ipc_session_id) LEFT JOIN command_closure_ack a USING(permit_id)
  JOIN command_lifecycle_revision p ON p.command_id=h.command_id AND p.revision=h.revision
  WHERE h.revision IN (3,4) AND json_extract(p.state_jcs,'$.outcome')='pending' ORDER BY h.command_id LIMIT 16`).raw().all();
 for(const [command,revision,previousCommit,permit,ack] of pending){
  // 已持久保存的关闭回执仍按正常规则裁决。会话结束本身无法证明设备效果或资源释放。
  if(ack){commitCommandSettlement(db,{id:permit});continue;}
  const previous=readCommandRevision(db,command,String(revision)),commit=crypto.randomUUID();
  const {projection:p,value:v,audit}=select(db,previous,commit),next=revision+1,body=canonical(v),hash=digest(v);
  written(db.prepare('INSERT INTO command_lifecycle_revision VALUES(?,?,?,?,?,?,?,?,?)').run(command,next,canonical(p.record),
   p.record.record_digest,canonical(p.state),v.state_digest,canonical(p.manifest),digest(p.manifest),commit));
  written(db.prepare('INSERT INTO command_dispatch_interruption VALUES(?,?,?,?,?,?,?,?,?)')
   .run(command,permit,v.ipc_session_id,v.end.transaction_id,v.end.reason,revision,commit,body,hash));
  written(db.prepare('UPDATE command_lifecycle_head SET revision=?,commit_id=? WHERE command_id=? AND revision=? AND commit_id=?')
   .run(next,commit,command,revision,previousCommit));
  written(db.prepare('INSERT INTO command_lifecycle_commit VALUES(?,?,?,?,?,?,?,?)').run(commit,command,next,body,hash,audit,crypto.randomUUID(),audit));
 }
}
