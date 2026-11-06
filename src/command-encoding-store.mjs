import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {preparedFrame,insertFrame,executionTick} from './device-execution-handshake.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
import {memoExecutionRead,withExecutionReadView} from './execution-read-view.mjs';
import {readInitialReady} from './device-initial-ready.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('execution_encoding_'+code);};
const ref=(id,value)=>({id,revision:'1',digest:digest(value)});
const hash=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const parse=(text,expected)=>{const v=JSON.parse(text);need(canonical(v)===text&&digest(v)===expected,'integrity');return v;};
const written=result=>need(result.changes===1,'storage');
function row(db,sql,...args){const q=db.prepare(sql),names=q.columns().map(v=>v.name),r=q.raw().get(...args);return r&&Object.fromEntries(names.map((n,i)=>[n,r[i]]));}
const reservation=(prepare,command)=>({format:'command-encoding-reservation/1',prepare_id:prepare,command_id:command,
 profile:{id:'leafseamer.simulator.encoding.limits.1',max_entries:256,max_bytes:2048},slots:1,max_bytes:8,state:'reserved'});
function authority(actual,prepare,attempt){
 const s=actual.command.source,b=actual.execution.value,r=reservation(prepare,s.command_id);
 const value={format_version:'encoding-authorization/0.1.0-draft.1',authorization_id:prepare+'.authorization',revision:'1',binding:b.binding,
  target:{kind:'ordinary',command_ref:{id:s.command_id,revision:'1',digest:s.initial_ref.digest},proposed_attempt_id:attempt,cancellation_ref:null,execution_ref:null},
  requester:{kind:'human',...actual.identity.actor},admission_source_ref:ref(s.command_id+'.admission-source',s),authorization_snapshot_ref:actual.snapshot_ref,
  capability_ref:b.capability_ref,primitive_id:b.primitive_plan.primitive_id,primitive_plan_ref:b.primitive_plan_ref,transport_profile_ref:b.transport_profile_ref,
  content_digest:s.metadata.request_identity.request_digest,encoding_reservation_ref:ref(prepare+'.reservation',r),max_bytes:8,
  created_tick_ns:actual.snapshot.authentication_window.selected_tick_ns,expires_tick_ns:actual.expires_tick_ns};
 return {...value,authorization_digest:digest(value)};
}
function requestBody(actual,prepare,attempt){const a=authority(actual,prepare,attempt);return {prepare_id:prepare,command_id:actual.command.source.command_id,
 attempt_id:attempt,primitive_id:a.primitive_id,device_session_id:a.binding.device_session_id,request:actual.request,
 primitive_plan_ref:{object_id:a.primitive_plan_ref.id,digest:a.primitive_plan_ref.digest},transport_profile_ref:{object_id:a.transport_profile_ref.id,digest:a.transport_profile_ref.digest},
 expires_tick_ns:a.expires_tick_ns,encoding_authorization:a};}
export function selectCommandEncoding(db,{binding,id,provider,features}){
 need(db.inTransaction&&provider&&Number(db.pragma('user_version',{simple:true}))>=51,'writer');
 const previous=db.prepare('SELECT prepare_id FROM command_encoding_request WHERE command_id=?').pluck().get(id);
 if(previous)return {saved:readCommandEncoding(db,previous)};
 const actual=withExecutionReadView(db,()=>provider.select(id)),b=actual.execution.value.binding;
 need(b.ipc_session_id===binding.ipc_session_id&&b.controller_boot_id===binding.controller_boot_id&&b.worker_boot_id===binding.worker_boot_id,'binding');
 const prepare=crypto.randomUUID(),attempt=crypto.randomUUID(),seq=db.prepare("SELECT sequence FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' ORDER BY sequence DESC LIMIT 1").pluck().get(binding.ipc_session_id);
 need(seq,'handshake');
 const frame={ipc_version:deviceExecutionVersion,type:'ENCODE_PACKET',message_id:crypto.randomUUID(),reply_to:null,ipc_session_id:binding.ipc_session_id,
  controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:String(BigInt(seq)+1n),device_id:b.device_id,
  clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest,journal_mode:'durable',body:requestBody(actual,prepare,attempt)};
 assertDeviceExecutionFeatures(frame,features);return {frame,snapshot:actual.snapshot};
}
export function commitCommandEncoding(db,{binding,candidate,provider,tick}){
 need(db.inTransaction,'writer');const frame=candidate.frame,id=frame.body.prepare_id;
 const actual=withExecutionReadView(db,()=>provider.current(frame.body.command_id,candidate.snapshot));
 need(same(frame.body,requestBody(actual,id,frame.body.attempt_id)),'changed');
 const item=preparedFrame(binding,frame,Buffer.from(JSON.stringify(frame)),'c2w',tick()),r=reservation(id,frame.body.command_id);
 const value={format:'command-encoding-request/1',prepare_id:id,command_id:frame.body.command_id,binding_ref:actual.execution.ref,
  authorization:frame.body.encoding_authorization,identity_snapshot:candidate.snapshot,reservation_ref:ref(id+'.reservation',r),
  request_record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest}};
 written(db.prepare('INSERT INTO command_encoding_reservation VALUES(?,?,8,?,?)').run(id,value.command_id,canonical(r),digest(r)));
 insertFrame(db,item,'command_encoding');
 written(db.prepare('INSERT INTO command_encoding_request VALUES(?,?,?,?,?,?,?)').run(id,value.command_id,actual.execution.ref.id,item.record.record_id,item.transaction,canonical(value),digest(value)));
 effect(db,item,id,'request',value,tick());const saved=readCommandEncoding(db,id);
 need(tick()<BigInt(frame.body.expires_tick_ns),'expired');return saved;
}
function effect(db,item,id,phase,value,now){
 const domain={transaction_id:item.transaction,source_ref:ref(id+(phase==='request'?'':'.response'),value)},audit={kind:'command_encoding_'+phase,prepare_id:id,source_digest:digest(value)};
 const e={record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest},disposition:'applied',domain_commit_refs:[ref(item.transaction,domain)],
  audit_ref:ref(item.transaction+'.audit',audit),reply_record_refs:[],committed_tick_ns:String(now)};
 written(db.prepare('INSERT INTO execution_encoding_frame(record_id,transaction_id,prepare_id,phase,domain_jcs,domain_digest) VALUES(?,?,?,?,?,?)')
  .run(item.record.record_id,item.transaction,id,phase,canonical(domain),digest(domain)));
 written(db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(item.record.record_id,item.transaction,'applied',executionTick(now),canonical(audit),digest(audit),canonical(e),digest(e)));
}
function applied(db,id,prepare,phase,value){
 const r=row(db,`SELECT f.*,e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest,e.committed_tick,x.domain_jcs,x.domain_digest,x.phase
  FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
  JOIN execution_encoding_frame x USING(record_id,transaction_id) WHERE f.record_id=?`,id);need(r,'integrity');
 const frame=parse(r.frame_jcs,r.frame_digest),record=JSON.parse(r.record_jcs),{record_digest,...unsigned}=record,
  session=row(db,'SELECT binding_jcs,binding_digest FROM execution_session WHERE ipc_session_id=?',r.ipc_session_id);need(session,'integrity');
 const binding=parse(session.binding_jcs,session.binding_digest);
 need(canonical(record)===r.record_jcs&&digest(unsigned)===record_digest&&record_digest===r.record_digest&&
  r.wire.readUInt32BE(0)===r.wire.length-4&&hash(r.wire)===r.wire_digest&&same(JSON.parse(r.wire.subarray(4)),frame)&&
  r.domain_kind==='command_encoding'&&r.phase===phase&&r.direction===(phase==='request'?'c2w':'w2c')&&
  (phase==='request'?frame.type==='ENCODE_PACKET':['PREPARE_PACKET','PACKET_ENCODING_FAILED'].includes(frame.type))&&
  r.message_type===frame.type&&r.message_id===frame.message_id&&r.device_id===frame.device_id&&r.sequence===executionTick(BigInt(frame.seq))&&frame.journal_mode==='durable','integrity');
 for(const key of ['ipc_version','ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'])need(frame[key]===binding[key],'binding');
 need(same(record,{record_id:id,session_ref:{id:binding.ipc_session_id,revision:'1',digest:session.binding_digest},direction:r.direction,sequence:frame.seq,
  message_id:frame.message_id,message_type:frame.type,frame_digest:r.frame_digest,wire_digest:r.wire_digest,wire_length:r.wire.length,
  frame_object_ref:{id:id+'.frame',revision:'1',digest:r.frame_digest},wire_object_ref:{id:id+'.wire',revision:'1',digest:r.wire_digest},record_digest}),'integrity');
 const domain=parse(r.domain_jcs,r.domain_digest),audit=parse(r.audit_jcs,r.audit_digest),e=parse(r.effect_jcs,r.effect_digest);
 need(same(domain,{transaction_id:r.transaction_id,source_ref:ref(prepare+(phase==='request'?'':'.response'),value)})&&
  same(audit,{kind:'command_encoding_'+phase,prepare_id:prepare,source_digest:digest(value)})&&
  same(e,{record_ref:{id,revision:'1',digest:record_digest},disposition:'applied',domain_commit_refs:[ref(r.transaction_id,domain)],
   audit_ref:ref(r.transaction_id+'.audit',audit),reply_record_refs:[],committed_tick_ns:String(BigInt(r.committed_tick))})&&r.committed_tick>=r.observed_tick,'integrity');
 return {frame,record,wire:Buffer.from(r.wire),transaction:r.transaction_id,observedTick:BigInt(r.observed_tick),committedTick:BigInt(r.committed_tick),replyRecord:r.reply_record_id};
}
function readRequest(db,id){return memoExecutionRead(db,'command-encoding-request',id,()=>{
 need(db.inTransaction,'writer');const r=row(db,'SELECT * FROM command_encoding_request WHERE prepare_id=?',id);need(r,'missing');
 const value=parse(r.body_jcs,r.body_digest),request=applied(db,r.record_id,id,'request',value),body=request.frame.body,a=body.encoding_authorization,{authorization_digest,...unsigned}=a;
 const reserve=row(db,'SELECT * FROM command_encoding_reservation WHERE prepare_id=?',id),source=row(db,'SELECT body_jcs,body_digest FROM command_admission_source WHERE command_id=?',r.command_id),
  binding=row(db,'SELECT body_jcs,body_digest FROM device_execution_binding WHERE binding_id=?',r.binding_id);need(reserve&&source&&binding,'source');
 const s=parse(source.body_jcs,source.body_digest),b=parse(binding.body_jcs,binding.body_digest),z=parse(reserve.body_jcs,reserve.body_digest);
 need(same(z,reservation(id,r.command_id))&&reserve.command_id===r.command_id&&reserve.max_bytes===8&&same(value.reservation_ref,ref(id+'.reservation',z))&&
  value.format==='command-encoding-request/1'&&value.prepare_id===id&&value.command_id===r.command_id&&same(value.authorization,a)&&
  same(value.binding_ref,ref(r.binding_id,b))&&same(s.binding_ref,value.binding_ref)&&same(s.binding,a.binding)&&
  same(value.request_record_ref,{id:r.record_id,revision:'1',digest:request.record.record_digest})&&request.transaction===r.transaction_id&&request.replyRecord===null&&request.frame.reply_to===null,'source');
 const snapshot=value.identity_snapshot,actor={issuer_id:s.metadata.actor.issuer_id,issuer_epoch:s.metadata.actor.issuer_epoch,principal_id:s.metadata.actor.principal_id};
 need(digest(unsigned)===authorization_digest&&a.format_version==='encoding-authorization/0.1.0-draft.1'&&a.authorization_id===id+'.authorization'&&a.revision==='1'&&
  a.target.kind==='ordinary'&&a.target.command_ref.id===s.command_id&&a.target.command_ref.revision==='1'&&a.target.command_ref.digest===s.initial_ref.digest&&
  a.target.proposed_attempt_id===body.attempt_id&&a.target.cancellation_ref===null&&a.target.execution_ref===null&&same(a.requester,{kind:'human',...actor})&&
  same(a.admission_source_ref,ref(s.command_id+'.admission-source',s))&&same(a.authorization_snapshot_ref,ref(s.command_id+'.encoding-identity',snapshot))&&
  snapshot.command_id===s.command_id&&snapshot.identity.token_id===s.token_id&&same(snapshot.identity.actor,actor)&&
  snapshot.identity.authorization_digest===s.authorization_digest&&same(snapshot.identity.ready_ref,s.ready_ref)&&same(snapshot.identity.binding_ref,s.binding_ref)&&
  same(a.capability_ref,b.capability_ref)&&same(a.primitive_plan_ref,b.primitive_plan_ref)&&same(a.transport_profile_ref,b.transport_profile_ref)&&a.primitive_id===b.primitive_plan.primitive_id&&
  same(a.encoding_reservation_ref,value.reservation_ref)&&a.max_bytes===8&&a.created_tick_ns===snapshot.authentication_window.selected_tick_ns&&a.expires_tick_ns===snapshot.authentication_window.before_tick_ns&&
  BigInt(a.created_tick_ns)<=request.observedTick&&request.committedTick<BigInt(a.expires_tick_ns)&&BigInt(a.expires_tick_ns)<=BigInt(s.deadline.queue_deadline_tick_ns),'authority');
 const {context_id,idempotency_key,...content}=body.request;
 need(context_id===s.context_id&&idempotency_key===s.metadata.request_identity.key.idempotency_key&&digest(content)===s.metadata.request_identity.request_digest&&
  a.content_digest===digest(content)&&body.prepare_id===id&&body.command_id===s.command_id&&body.device_session_id===b.binding.device_session_id&&body.primitive_id===a.primitive_id&&
  body.expires_tick_ns===a.expires_tick_ns&&same(body.primitive_plan_ref,{object_id:a.primitive_plan_ref.id,digest:a.primitive_plan_ref.digest})&&
  same(body.transport_profile_ref,{object_id:a.transport_profile_ref.id,digest:a.transport_profile_ref.digest}),'request');
 return {value,ref:ref(id,value),request,bound:b};
 });}
function packetBytes(saved,frame){
 const a=saved.value.authorization,body=frame.body;
 need(body.prepare_id===saved.value.prepare_id&&same(body.encoding_authorization_ref,{id:a.authorization_id,revision:'1',digest:a.authorization_digest}),'reply');
 if(frame.type==='PACKET_ENCODING_FAILED')return null;
 const p=body.packet,{packet_digest,...unsigned}=p,bytes=Buffer.from(body.bytes_hex,'hex'),b=saved.bound;
 need(bytes.length===8&&bytes.toString('hex')===body.bytes_hex&&digest(unsigned)===packet_digest&&
  p.command_id===saved.value.command_id&&p.attempt_id===a.target.proposed_attempt_id&&p.primitive_id===a.primitive_id&&
  p.writer_exit_id===a.binding.writer_exit_id&&p.device_session_id===a.binding.device_session_id&&p.socket_instance_id===b.exit.socket_instance_id&&p.protocol_session===b.exit.protocol_session&&
  p.wire_packet_id===null&&p.tracking_ids.length===0&&p.byte_length===bytes.length&&p.sha256===hash(bytes)&&same(p.immutable_bytes_ref,{object_id:'bytes_'+p.packet_id,digest:hash(bytes)})&&
  same(p.transport_profile_ref,saved.request.frame.body.transport_profile_ref)&&same(p.primitive_plan_ref,saved.request.frame.body.primitive_plan_ref)&&
  bytes.subarray(0,4).toString('hex')==='4c534d31'&&bytes.readInt32BE(4)===saved.request.frame.body.request.parameters.value,'packet');return bytes;
}
function evidence(saved,frame,bytes,received){
 if(!bytes)return null;
 const value={evidence_id:saved.value.prepare_id+'.evidence',revision:'1',binding:saved.value.authorization.binding,
  authorization_ref:{id:saved.value.authorization.authorization_id,revision:'1',digest:saved.value.authorization.authorization_digest},prepare_id:saved.value.prepare_id,
  request_message_id:saved.request.frame.message_id,request_digest:digest(saved.request.frame),response_message_id:frame.message_id,response_digest:digest(frame),
  packet_ref:{packet_id:frame.body.packet.packet_id,packet_digest:frame.body.packet.packet_digest},
  bytes_digest:hash(bytes),byte_length:bytes.length,received_tick_ns:String(received)};
 return {...value,evidence_digest:digest(value)};
}
export function readCommandEncoding(db,id){return memoExecutionRead(db,'command-encoding',id,()=>readEncoding(db,id));}
function readEncoding(db,id){
 const saved=readRequest(db,id),r=row(db,'SELECT * FROM command_encoding_response WHERE prepare_id=?',id);if(!r)return {...saved,response:null};
 const value=parse(r.body_jcs,r.body_digest),reply=applied(db,r.record_id,id,'response',value),bytes=packetBytes(saved,reply.frame),
  attempt=row(db,'SELECT record_id,started_tick FROM execution_write_attempt WHERE attempt_id=?',r.write_attempt_id);
 need(attempt&&attempt.record_id===saved.request.record.record_id&&BigInt(attempt.started_tick)<=reply.observedTick&&reply.frame.reply_to===saved.request.frame.message_id&&
  reply.replyRecord===saved.request.record.record_id&&reply.frame.device_id===saved.request.frame.device_id&&reply.frame.ipc_session_id===saved.request.frame.ipc_session_id&&
  (bytes?r.packet_bytes?.equals(bytes):r.packet_bytes===null)&&
  same(value,{format:'command-encoding-response/1',prepare_id:id,request_ref:saved.ref,record_ref:{id:r.record_id,revision:'1',digest:reply.record.record_digest},
   write_attempt_id:r.write_attempt_id,disposition:r.disposition,evidence:evidence(saved,reply.frame,bytes,reply.observedTick)})&&
  (r.disposition==='historical'||reply.committedTick<BigInt(saved.value.authorization.expires_tick_ns))&&
  (r.disposition!=='prepared'||bytes),'response');
 return {...saved,response:{value,ref:ref(id+'.response',value),reply,bytes}};
}
export function currentCommandEncoding(db,{id,provider}){
 return withExecutionReadView(db,()=>{const saved=readCommandEncoding(db,id),actual=provider.current(saved.value.command_id,saved.value.identity_snapshot);
  need(same(saved.request.frame.body,requestBody(actual,id,saved.value.authorization.target.proposed_attempt_id)),'changed');return saved;});
}
// T2的同步输入读取器。必须与最终写集共用writer；返回原件不等于已签发许可。
// 不复用接收时的资格，也不把历史编码、缺失写结果或已关闭会话变成可采用输入。
export function selectCommandFinalization(db,{id,provider,tick}){
 need(db.inTransaction&&provider&&typeof tick==='function','finalization_writer');
 return withExecutionReadView(db,()=>{
  const encoding=readCommandEncoding(db,id),response=encoding.response;
  need(response?.value.disposition==='prepared'&&response.bytes?.length===8,'finalization_prepared');
  const session=encoding.value.authorization.binding.ipc_session_id;
  need(!db.prepare('SELECT 1 FROM execution_session_end WHERE ipc_session_id=?').pluck().get(session),'finalization_session');
  const write=row(db,'SELECT result,completed_tick FROM execution_write_result WHERE attempt_id=?',response.value.write_attempt_id);
  need(write?.result==='complete','finalization_write');
  const actual=provider.current(encoding.value.command_id,encoding.value.identity_snapshot);
  need(same(encoding.request.frame.body,requestBody(actual,id,encoding.value.authorization.target.proposed_attempt_id)),'changed');
  // Guard主体的修订来自刚通过当前资格核验的令牌授权原件，不能用控制修订或常量补齐。
  const token=row(db,'SELECT authorization_body,authorization_digest,state FROM access_token WHERE token_id=?',actual.command.source.token_id);
  need(token?.state==='active','finalization_authorization');
  const grant=JSON.parse(token.authorization_body.toString()),{digest:grantDigest,...grantBody}=grant,p=actual.proof;
  need(canonical(grant)===token.authorization_body.toString()&&digest(grantBody)===grantDigest&&
   token.authorization_digest===grantDigest&&p.authorization_digest===grantDigest,'finalization_authorization');
  for(const key of ['issuer_id','issuer_epoch','principal_id','session_id','credential_id','audience','policy_revision','scope_digest'])
   need(grant[key]===p[key],'finalization_authorization');
  const authorizationBinding={issuer_id:grant.issuer_id,issuer_epoch:grant.issuer_epoch,audience:grant.audience,
   principal_kind:'human',principal_id:grant.principal_id,origin:'manual',session_id:grant.session_id,credential_id:grant.credential_id,
   subject_revision:grant.subject_revision,session_revision:grant.session_revision,policy_revision:grant.policy_revision,scope_digest:grant.scope_digest,
   grant_id:null,grant_revision:null,arm_generation:null,extension_instance_id:null,extension_approval_revision:null};
  const ready=readInitialReady(db,actual.command.source.ready_ref.id),opening=ready.dispatch.plan,b=actual.execution.value.binding;
  need(same(ready.ref,actual.command.source.ready_ref)&&same(ready.value.binding,b)&&
   same(opening.access.binding,b)&&opening.access.purpose==='ordinary'&&opening.access.protection===null&&
   opening.resource.holds.length===0&&opening.resource.reference_time_snapshot===null&&
   ready.value.gate_after.phase==='ready','finalization_ready');
  const selected=tick(),expires=BigInt(encoding.value.authorization.expires_tick_ns);
  need(BigInt(response.value.evidence.received_tick_ns)<=selected&&response.reply.committedTick<=selected&&
   BigInt(write.completed_tick)<=selected&&BigInt(actual.now.tick)<=selected&&selected<expires,'finalization_expired');
  // 时间窗沿用原授权的交集，不以本次读取时间续期。后续T2仍须末核再提交。
  const window={not_before_tick_ns:actual.snapshot.authentication_window.selected_tick_ns,before_tick_ns:String(expires)};
  return {encoding,actual,ready,opening,principal_authorization:{ref:{id:grant.id,revision:grant.revision,digest:grantDigest},value:grant,binding:authorizationBinding},
   selected_tick_ns:String(selected),send_window:window};
 });
}
export function acceptCommandEncoding(db,{binding,decoded,provider,features,tick,receivedTick}){
 const {frame,payload}=decoded;assertDeviceExecutionFeatures(frame,features);
 need(['PREPARE_PACKET','PACKET_ENCODING_FAILED'].includes(frame.type),'reply');
 const id=db.prepare(`SELECT p.prepare_id FROM command_encoding_request p JOIN execution_frame_record f USING(record_id)
  WHERE f.ipc_session_id=? AND f.message_id=?`).pluck().get(binding.ipc_session_id,frame.reply_to);need(id,'reply');
 const saved=readCommandEncoding(db,id);if(saved.response){need(saved.response.reply.wire.equals(executionWire(payload)),'replay_conflict');return saved;}
 for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','device_id'])need(frame[key]===saved.request.frame[key],'reply');
 const now=receivedTick,current=tick(),bytes=packetBytes(saved,frame),attempt=row(db,'SELECT a.attempt_id,a.started_tick,r.result FROM execution_write_attempt a LEFT JOIN execution_write_result r USING(attempt_id) WHERE a.record_id=?',saved.request.record.record_id);
 need(typeof now==='bigint'&&now<=current&&attempt&&BigInt(attempt.started_tick)<=now,'write');let disposition=bytes?'prepared':'failed';
 if(current>=BigInt(saved.value.authorization.expires_tick_ns)||attempt.result==='unknown')disposition='historical';
 else try{currentCommandEncoding(db,{id,provider});}catch(error){
  if(['command_encoding_state','command_encoding_permission','command_encoding_identity','command_encoding_control','command_encoding_binding','command_encoding_deadline',
   'command_encoding_changed','token_invalid','token_expired','authentication_window_expired','authentication_window_validity'].includes(error.code))disposition='historical';else throw error;
 }
 const item=preparedFrame(binding,frame,payload,'w2c',now,saved.request.record.record_id),committed=tick();
 if(committed>=BigInt(saved.value.authorization.expires_tick_ns))disposition='historical';
 const value={format:'command-encoding-response/1',prepare_id:id,request_ref:saved.ref,record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest},
  write_attempt_id:attempt.attempt_id,disposition,evidence:evidence(saved,frame,bytes,now)};
 insertFrame(db,item,'command_encoding');
 written(db.prepare('INSERT INTO command_encoding_response VALUES(?,?,?,?,?,?,?,?)').run(id,item.record.record_id,item.transaction,attempt.attempt_id,disposition,bytes,canonical(value),digest(value)));
 effect(db,item,id,'response',value,committed);const accepted=readCommandEncoding(db,id);
 // 完整写集和回读完成后的末次判断；跨过原截止不能提交可采用编码资格。
 need(disposition==='historical'||tick()<BigInt(saved.value.authorization.expires_tick_ns),'expired');return accepted;
}
// 精确编码账本只说明此帧没有设备I/O。准备槽仍占用，不能由此推导缓存已释放。
export function encodingOnlyFrame(db,recordId,binding,readyRef=null){
 need(Number(db.pragma('user_version',{simple:true}))>=51,'migration');
 const id=db.prepare('SELECT prepare_id FROM command_encoding_request WHERE record_id=?').pluck().get(recordId);need(id,'ledger');
 const saved=readCommandEncoding(db,id);
 need(same(saved.value.authorization.binding,binding)&&(!readyRef||same(saved.value.identity_snapshot.identity.ready_ref,readyRef)),'ledger');
 return saved.ref;
}
