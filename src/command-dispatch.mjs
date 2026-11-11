import {sqliteRow} from './sqlite-rows.mjs';
import {cacheVerifiedDocument} from './verified-document-cache.mjs';
import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {preparedFrame,insertFrame,executionTick} from './device-execution-handshake.mjs';
import {readCommandGuard,currentCommandGuard} from './command-guard.mjs';
import {readOriginalRecord,readCommandRecord,readPreparedCommandRecord,dispatchCommandProjection} from './command-record-store.mjs';
import {readCommandEncoding} from './command-encoding-store.mjs';
import {readInitialReady} from './device-initial-ready.mjs';
import {withExecutionReadView,memoExecutionRead} from './execution-read-view.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('command_dispatch_'+code);};
const ref=(id,v)=>({id,revision:'1',digest:digest(v)});
const parse=cacheVerifiedDocument((text,hash)=>{const v=JSON.parse(text);need(canonical(v)===text&&'sha256:'+crypto.createHash('sha256').update(text).digest('hex')===hash,'integrity');return v;});
const written=result=>need(result.changes===1,'storage');
const hash=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const row=sqliteRow;
function dispatchBody(db,guard){
 const v=guard.final.value,encoding=readCommandEncoding(db,v.prepare_id),initial=readOriginalRecord(db,v.command_id),ready=readInitialReady(db,initial.source.ready_ref.id);
 return {permit:v.permit,gate_token:ready.value.gate_after.gate_token,send_window:v.permit.transmission.send_window,request:encoding.request.frame.body.request,
  parameters_schema_digest:encoding.bound.action.parameters_schema_digest,guard_id:v.guard.guard_id,guard_digest:v.guard.guard_digest,
  prepare_id:encoding.value.prepare_id,packet:encoding.response.reply.frame.body.packet,resend_request_id:null};
}
function effect(db,item,id,phase,value,now){
 const domain={transaction_id:item.transaction,source_ref:ref(id+(phase==='request'?'':'.'+phase),value)},audit={kind:'command_dispatch_'+phase,permit_id:id,source_digest:digest(value)};
 const e={record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest},disposition:'applied',domain_commit_refs:[ref(item.transaction,domain)],
  audit_ref:ref(item.transaction+'.audit',audit),reply_record_refs:[],committed_tick_ns:String(now)};
 written(db.prepare('INSERT INTO execution_dispatch_frame(record_id,transaction_id,permit_id,phase,domain_jcs,domain_digest) VALUES(?,?,?,?,?,?)')
  .run(item.record.record_id,item.transaction,id,phase,canonical(domain),digest(domain)));
 written(db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(item.record.record_id,item.transaction,'applied',executionTick(now),canonical(audit),digest(audit),canonical(e),digest(e)));
}
function applied(db,id,permit,phase,value){
 const r=row(db,`SELECT f.*,e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest,e.committed_tick,x.domain_jcs,x.domain_digest,x.phase
  FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
  JOIN execution_dispatch_frame x USING(record_id,transaction_id) WHERE f.record_id=?`,id);need(r,'integrity');
 const frame=parse(r.frame_jcs,r.frame_digest),record=JSON.parse(r.record_jcs),{record_digest,...unsigned}=record,
  session=row(db,'SELECT binding_jcs,binding_digest FROM execution_session WHERE ipc_session_id=?',r.ipc_session_id);need(session,'integrity');
 const binding=parse(session.binding_jcs,session.binding_digest),type={request:'DISPATCH',report:'SEND_REPORT',evidence:'EVIDENCE_CANDIDATE',fence_request:'FENCE',fence_ack:'FENCE_ACK',deny_request:'DENY_ENCODING',deny_ack:'DENY_ENCODING_ACK',release_request:'RELEASE_ENCODING',release_ack:'RELEASE_ENCODING_ACK'}[phase],outgoing=['request','fence_request','deny_request','release_request'].includes(phase);
 need(canonical(record)===r.record_jcs&&digest(unsigned)===record_digest&&record_digest===r.record_digest&&
  r.wire.readUInt32BE(0)===r.wire.length-4&&hash(r.wire)===r.wire_digest&&same(JSON.parse(r.wire.subarray(4)),frame)&&
  r.domain_kind==='command_dispatch'&&r.phase===phase&&r.direction===(outgoing?'c2w':'w2c')&&frame.type===type&&
  r.message_type===type&&r.message_id===frame.message_id&&r.device_id===frame.device_id&&r.sequence===executionTick(BigInt(frame.seq))&&
  frame.journal_mode==='durable'&&(['fence_ack','deny_ack','release_ack'].includes(phase)?typeof frame.reply_to==='string'&&typeof r.reply_record_id==='string':frame.reply_to===null&&r.reply_record_id===null),'integrity');
 for(const key of ['ipc_version','ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'])need(frame[key]===binding[key],'binding');
 need(same(record,{record_id:id,session_ref:{id:binding.ipc_session_id,revision:'1',digest:session.binding_digest},direction:r.direction,sequence:frame.seq,
  message_id:frame.message_id,message_type:frame.type,frame_digest:r.frame_digest,wire_digest:r.wire_digest,wire_length:r.wire.length,
  frame_object_ref:{id:id+'.frame',revision:'1',digest:r.frame_digest},wire_object_ref:{id:id+'.wire',revision:'1',digest:r.wire_digest},record_digest}),'integrity');
 const domain=parse(r.domain_jcs,r.domain_digest),audit=parse(r.audit_jcs,r.audit_digest),e=parse(r.effect_jcs,r.effect_digest);
 need(same(domain,{transaction_id:r.transaction_id,source_ref:ref(permit+(phase==='request'?'':'.'+phase),value)})&&
  same(audit,{kind:'command_dispatch_'+phase,permit_id:permit,source_digest:digest(value)})&&
  same(e,{record_ref:{id,revision:'1',digest:record_digest},disposition:'applied',domain_commit_refs:[ref(r.transaction_id,domain)],
   audit_ref:ref(r.transaction_id+'.audit',audit),reply_record_refs:[],committed_tick_ns:String(BigInt(r.committed_tick))})&&r.committed_tick>=r.observed_tick,'integrity');
 return {frame,record,wire:Buffer.from(r.wire),transaction:r.transaction_id,observedTick:BigInt(r.observed_tick),committedTick:BigInt(r.committed_tick),replyRecord:r.reply_record_id};
}
function boundReply(frame,request){
 for(const key of ['ipc_version','ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','device_id'])need(frame[key]===request[key],'reply_binding');
 need(frame.reply_to===null,'reply_binding');
}
function validateReport(saved,frame,receivedTick){
 boundReply(frame,saved.request.frame);const r=frame.body,p=saved.final.value.permit,t=p.transmission;
 need(frame.type==='SEND_REPORT'&&r.permit_id===p.permit_id&&r.attempt_id===p.attempt_id&&r.dispatch_intent_id===p.dispatch_intent_id&&
  r.device_session_id===p.device_session_id&&r.transmission_id===t.transmission_id&&same(r.packet_ref,t.packet_ref)&&r.ordinal===t.ordinal&&
  receivedTick>=BigInt(saved.write.value.started_tick_ns),'report_binding');
 if(r.transport_entered_tick_ns!==null)need(BigInt(r.transport_entered_tick_ns)>=BigInt(saved.write.value.started_tick_ns)&&BigInt(r.transport_entered_tick_ns)<=receivedTick,'report_clock');
}
function validateEvidence(saved,frame,receivedTick){
 boundReply(frame,saved.request.frame);const e=frame.body,p=saved.final.value.permit,r=saved.report.reply.frame.body,v=e.payload,o=v?.observation;
 need(frame.type==='EVIDENCE_CANDIDATE'&&e.command_id===p.command_id&&e.attempt_id===p.attempt_id&&e.device_session_id===p.device_session_id&&
  e.evidence_kind==='module_observation'&&v?.format==='leafseamer-primitive-observation/1'&&same(v.binding,saved.final.value.seal.binding)&&
  same(v.send_report_ref,{object_id:r.report_id,digest:digest(r)})&&o&&e.observation_id===o.observation_id&&
  same(v.observation_ref,{object_id:o.observation_id,digest:digest(o)})&&same(r.socket_callback_observation_ref,v.observation_ref)&&
  o.permit_id===p.permit_id&&o.transmission_id===p.transmission.transmission_id&&same(o.packet_ref,p.transmission.packet_ref)&&
  Number.isSafeInteger(o.bytes_written)&&o.bytes_written>=0&&o.bytes_written<=8&&r.transport_entered_tick_ns!==null&&
  BigInt(o.observed_tick_ns)>=BigInt(r.transport_entered_tick_ns)&&BigInt(o.observed_tick_ns)<=receivedTick,'evidence_binding');
}
export function readCommandDispatch(db,id){return withExecutionReadView(db,()=>memoExecutionRead(db,'command-dispatch',id,()=>readDispatch(db,id)));}
function readDispatch(db,id){
 need(db.inTransaction,'writer');const r=row(db,'SELECT * FROM command_dispatch_request WHERE permit_id=?',id);need(r,'missing');
 const guard=readCommandGuard(db,r.guard_id),final=guard.final;need(final.value.permit.permit_id===id&&r.final_transaction_id===final.value.transaction_id&&guard.ack?.value.disposition==='installed','source');
 const value=parse(r.body_jcs,r.body_digest),request=applied(db,r.record_id,id,'request',value);
 need(same(value,{format:'command-dispatch-request/1',permit_id:id,final_admission_ref:final.ref,guard_ack_ref:guard.ack.ref,
  request_record_ref:{id:r.record_id,revision:'1',digest:request.record.record_digest}})&&same(request.frame.body,dispatchBody(db,guard)),'request');
 const saved={value,ref:ref(id,value),request,guard,final,write:null,report:null,evidence:null};
 const w=row(db,'SELECT * FROM command_dispatch_write WHERE permit_id=?',id);if(!w)return saved;
 const writeValue=parse(w.body_jcs,w.body_digest),attempt=row(db,'SELECT record_id,started_tick FROM execution_write_attempt WHERE attempt_id=?',w.write_attempt_id);
 need(attempt&&attempt.record_id===r.record_id&&same(writeValue,{format:'command-dispatch-write/1',permit_id:id,request_ref:saved.ref,write_attempt_id:w.write_attempt_id,
  started_tick_ns:String(BigInt(attempt.started_tick)),commit_id:w.commit_id})&&BigInt(attempt.started_tick)>=request.committedTick,'write');
 saved.write={value:writeValue,ref:ref(id+'.write',writeValue)};
 const t=row(db,'SELECT * FROM command_dispatch_report WHERE permit_id=?',id);if(!t)return saved;
 const reportValue=parse(t.body_jcs,t.body_digest),reply=applied(db,t.record_id,id,'report',reportValue);validateReport(saved,reply.frame,reply.observedTick);
 need(t.write_attempt_id===w.write_attempt_id&&same(reportValue,{format:'command-dispatch-report/1',permit_id:id,request_ref:saved.ref,write_ref:saved.write.ref,
  record_ref:{id:t.record_id,revision:'1',digest:reply.record.record_digest},commit_id:t.commit_id}),'report');
 saved.report={value:reportValue,ref:ref(id+'.report',reportValue),reply};
 const e=row(db,'SELECT * FROM command_dispatch_evidence WHERE permit_id=?',id);if(!e)return saved;
 const evidenceValue=parse(e.body_jcs,e.body_digest),evidenceReply=applied(db,e.record_id,id,'evidence',evidenceValue);validateEvidence(saved,evidenceReply.frame,evidenceReply.observedTick);
 need(same(evidenceValue,{format:'command-dispatch-evidence/1',permit_id:id,send_report_ref:saved.report.ref,
  record_ref:{id:e.record_id,revision:'1',digest:evidenceReply.record.record_digest}}),'evidence');
 saved.evidence={value:evidenceValue,ref:ref(id+'.evidence',evidenceValue),reply:evidenceReply};return saved;
}
export function selectCommandDispatch(db,{id,binding,provider,tick,features}){
 need(db.inTransaction&&[54,55,56,57,58].includes(Number(db.pragma('user_version',{simple:true}))),'writer');
 const prior=db.prepare('SELECT d.permit_id FROM command_dispatch_request d JOIN command_final_admission f ON f.transaction_id=d.final_transaction_id WHERE f.command_id=?').pluck().get(id);
 if(prior)return {saved:readCommandDispatch(db,prior)};
 const guardId=db.prepare('SELECT g.guard_id FROM command_guard_request g JOIN command_final_admission f ON f.transaction_id=g.final_transaction_id WHERE f.command_id=?').pluck().get(id);need(guardId,'guard');
 // 选帧只读取历史；没有写入或发送权。提交和实际写入前分别核验当前资格。
 const guard=readCommandGuard(db,guardId),v=guard.final.value;need(guard.ack?.value.disposition==='installed','guard');
 const previous=db.prepare("SELECT sequence FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' ORDER BY sequence DESC LIMIT 1").pluck().get(binding.ipc_session_id);
 const frame={ipc_version:deviceExecutionVersion,type:'DISPATCH',message_id:crypto.randomUUID(),reply_to:null,ipc_session_id:binding.ipc_session_id,
  controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:String(BigInt(previous)+1n),device_id:v.seal.binding.device_id,
  clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',body:dispatchBody(db,guard)};
 assertDeviceExecutionFeatures(frame,features);return {frame,guard_id:guardId};
}
export function commitCommandDispatch(db,{candidate,binding,provider,tick}){
 const guard=withExecutionReadView(db,()=>{const current=currentCommandGuard(db,{id:candidate.guard_id,binding,provider,tick,requireAck:true});
  need(same(candidate.frame.body,dispatchBody(db,current)),'changed');return current;}),v=guard.final.value,id=v.permit.permit_id;
 const item=preparedFrame(binding,candidate.frame,Buffer.from(JSON.stringify(candidate.frame)),'c2w',tick()),value={format:'command-dispatch-request/1',permit_id:id,
  final_admission_ref:guard.final.ref,guard_ack_ref:guard.ack.ref,request_record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest}};
 insertFrame(db,item,'command_dispatch');written(db.prepare('INSERT INTO command_dispatch_request VALUES(?,?,?,?,?,?,?)')
  .run(id,v.transaction_id,candidate.guard_id,item.record.record_id,item.transaction,canonical(value),digest(value)));
 effect(db,item,id,'request',value,tick());const saved=readCommandDispatch(db,id);need(tick()<BigInt(v.seal.send_window.before_tick_ns),'expired');return saved;
}
function stateBody(saved,commit,projection,previous,source){return {format:'command-dispatch-state/1',commit_id:commit,command_id:saved.final.value.command_id,
 revision:projection.state.revision,dispatch_ref:saved.ref,source_ref:source,previous_state_ref:previous.state_ref,record_digest:projection.record.record_digest,state_digest:digest(projection.state)};}
function saveState(db,saved,commit,revision,source){
 const id=saved.final.value.command_id,initial=readCommandRecord(db,id),previous=initial.record;
 need(BigInt(previous.state.revision)+1n===BigInt(revision),'state_order');
 const projection=dispatchCommandProjection(initial,saved.final,revision,revision==='4'?saved.report.reply.frame.body:null),body=stateBody(saved,commit,projection,previous,source),
  audit=canonical({kind:'command_dispatch_state',command_id:id,revision,commit_ref:ref(commit,body)});
 written(db.prepare('INSERT INTO command_lifecycle_revision VALUES(?,?,?,?,?,?,?,?,?)').run(id,Number(revision),canonical(projection.record),projection.record.record_digest,
  canonical(projection.state),digest(projection.state),canonical(projection.manifest),digest(projection.manifest),commit));
 written(db.prepare('UPDATE command_lifecycle_head SET revision=?,commit_id=? WHERE command_id=? AND revision=?').run(Number(revision),commit,id,Number(revision)-1));
 written(db.prepare('INSERT INTO command_lifecycle_commit VALUES(?,?,?,?,?,?,?,?)').run(commit,id,Number(revision),canonical(body),digest(body),audit,crypto.randomUUID(),audit));
 return readCommandRecord(db,id);
}
export function startCommandDispatchWrite(db,{id,binding,provider,tick}){
 const saved=withExecutionReadView(db,()=>{const current=readCommandDispatch(db,id);need(!current.write,'write_reuse');
  currentCommandGuard(db,{id:current.guard.value.guard_id,binding,provider,tick,requireAck:true});return current;});
 const attempt=crypto.randomUUID(),commit=crypto.randomUUID(),started=tick(),value={format:'command-dispatch-write/1',permit_id:id,request_ref:saved.ref,
  write_attempt_id:attempt,started_tick_ns:String(started),commit_id:commit};
 written(db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run(attempt,saved.request.record.record_id,executionTick(started)));
 written(db.prepare('INSERT INTO command_dispatch_write VALUES(?,?,?,?,?)').run(id,attempt,commit,canonical(value),digest(value)));
 saveState(db,saved,commit,'3',ref(id+'.write',value));need(tick()<BigInt(saved.final.value.seal.send_window.before_tick_ns),'expired');
 return {attempt_id:attempt,payload:saved.request.wire.subarray(4)};
}
export function acceptCommandDispatchReport(db,{binding,decoded,features,tick,receivedTick}){
 const {frame,payload}=decoded;assertDeviceExecutionFeatures(frame,features);const id=frame.body.permit_id,saved=readCommandDispatch(db,id);
 need(saved.request.frame.ipc_session_id===binding.ipc_session_id&&saved.write,'report_source');
 if(saved.report){need(saved.report.reply.wire.equals(executionWire(payload)),'replay_conflict');return saved;}
 validateReport(saved,frame,receivedTick);const item=preparedFrame(binding,frame,payload,'w2c',receivedTick),commit=crypto.randomUUID(),value={format:'command-dispatch-report/1',
  permit_id:id,request_ref:saved.ref,write_ref:saved.write.ref,record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest},commit_id:commit};
 insertFrame(db,item,'command_dispatch');written(db.prepare('INSERT INTO command_dispatch_report VALUES(?,?,?,?,?,?,?)')
  .run(id,item.record.record_id,item.transaction,saved.write.value.write_attempt_id,commit,canonical(value),digest(value)));
 effect(db,item,id,'report',value,tick());const result=readCommandDispatch(db,id);saveState(db,result,commit,'4',result.report.ref);return result;
}
export function acceptCommandDispatchEvidence(db,{binding,decoded,features,tick,receivedTick}){
 const {frame,payload}=decoded;assertDeviceExecutionFeatures(frame,features);
 const id=db.prepare('SELECT permit_id FROM command_final_admission WHERE command_id=? AND attempt_id=?').pluck().get(frame.body.command_id,frame.body.attempt_id);need(id,'evidence_source');
 const saved=readCommandDispatch(db,id);need(saved.report&&saved.request.frame.ipc_session_id===binding.ipc_session_id,'evidence_source');
 if(saved.evidence){need(saved.evidence.reply.wire.equals(executionWire(payload)),'replay_conflict');return saved;}
 validateEvidence(saved,frame,receivedTick);const item=preparedFrame(binding,frame,payload,'w2c',receivedTick),value={format:'command-dispatch-evidence/1',permit_id:id,
  send_report_ref:saved.report.ref,record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest}};
 insertFrame(db,item,'command_dispatch');written(db.prepare('INSERT INTO command_dispatch_evidence VALUES(?,?,?,?,?)').run(id,item.record.record_id,item.transaction,canonical(value),digest(value)));
 effect(db,item,id,'evidence',value,tick());return readCommandDispatch(db,id);
}
export function dispatchRiskFrame(db,recordId,binding,preparedRef){
 need(preparedRef,'prepared_source');const id=db.prepare('SELECT permit_id FROM command_dispatch_request WHERE record_id=?').pluck().get(recordId);need(id,'ledger');
 const saved=readCommandDispatch(db,id);need(same(saved.final.ref,preparedRef)&&same(saved.final.value.seal.binding,binding),'ledger');return saved.ref;
}
export function readDispatchLifecycle(db,initial,head,headRow){
 need([3,4].includes(head[0]),'state_revision');const id=initial.source.command_id,permit=db.prepare('SELECT permit_id FROM command_final_admission WHERE command_id=?').pluck().get(id),saved=readCommandDispatch(db,permit);
 let previous=readPreparedCommandRecord(db,initial,saved.final).record,expected,body;
 for(let revision=3;revision<=head[0];revision++){
  const r=revision===head[0]?headRow:db.prepare(`SELECT r.record_jcs,r.record_digest,r.state_jcs,r.state_digest,r.manifest_jcs,r.manifest_digest,c.body_jcs,c.body_digest,c.audit_jcs,c.notification_jcs,c.revision,c.command_id
   FROM command_lifecycle_revision r JOIN command_lifecycle_commit c USING(command_id,revision,commit_id) WHERE r.command_id=? AND r.revision=?`).raw().get(id,revision);
  const source=revision===3?saved.write:saved.report;need(r&&source,'state_source');const commit=source.value.commit_id;
  expected=dispatchCommandProjection(initial,saved.final,String(revision),revision===4?saved.report.reply.frame.body:null);body=stateBody(saved,commit,expected,previous,source.ref);
  const audit=canonical({kind:'command_dispatch_state',command_id:id,revision:String(revision),commit_ref:ref(commit,body)});
  need(r[0]===canonical(expected.record)&&r[1]===expected.record.record_digest&&r[2]===canonical(expected.state)&&r[3]===digest(expected.state)&&
   r[4]===canonical(expected.manifest)&&r[5]===digest(expected.manifest)&&r[6]===canonical(body)&&r[7]===digest(body)&&r[8]===audit&&r[9]===audit&&
   r[10]===revision&&r[11]===id&&(revision!==head[0]||head[1]===commit),'state_integrity');previous=expected.record;
 }
 return {...initial,record:expected.record,lifecycle:{commit_ref:ref(body.commit_id,body),final_admission:saved.final,dispatch:{ref:saved.ref,write_ref:saved.write.ref,report_ref:saved.report?.ref??null,evidence_ref:saved.evidence?.ref??null}}};
}
// 同一派发领域的关闭帧沿用完整共享帧、效果提交及摘要核验。
export {effect as dispatchEffect,applied as dispatchApplied};
