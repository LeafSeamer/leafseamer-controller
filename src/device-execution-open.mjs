import {sqliteRow} from './sqlite-rows.mjs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {preparedFrame,insertFrame,executionTick} from './device-execution-handshake.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
import {memoExecutionRead,withExecutionReadView} from './execution-read-view.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('execution_open_'+code);};
const hash=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const digest=value=>hash(canonicalize(value)),same=(a,b)=>canonicalize(a)===canonicalize(b);
const ref=(id,digest)=>({id,revision:'1',digest});
const row=sqliteRow;
function document(text,expected){const value=JSON.parse(text);need(canonicalize(value)===text&&digest(value)===expected,'integrity');return value;}
function applied(db,id,openingId,phase,sourceDigest){
 const r=row(db,`SELECT f.*,e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest,e.committed_tick,x.domain_jcs,x.domain_digest,x.phase
 FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
 JOIN execution_open_frame x USING(record_id,transaction_id) WHERE f.record_id=?`,id);need(r,'integrity');
 const frame=document(r.frame_jcs,r.frame_digest),record=JSON.parse(r.record_jcs),{record_digest,...unsigned}=record;
 const session=row(db,'SELECT binding_jcs,binding_digest FROM execution_session WHERE ipc_session_id=?',r.ipc_session_id);need(session,'integrity');
 const binding=document(session.binding_jcs,session.binding_digest);
 need(canonicalize(record)===r.record_jcs&&record_digest===r.record_digest&&digest(unsigned)===record_digest&&r.wire.readUInt32BE(0)===r.wire.length-4&&
  hash(r.wire)===r.wire_digest&&same(JSON.parse(r.wire.subarray(4)),frame)&&r.domain_kind==='initial_open'&&r.phase===phase&&
  r.sequence===executionTick(BigInt(frame.seq))&&r.direction===(phase==='request'?'c2w':'w2c')&&r.message_type===(phase==='request'?'OPEN_GATE':'OPEN_GATE_ACK')&&
  frame.type===r.message_type&&frame.device_id===r.device_id&&frame.message_id===r.message_id&&frame.journal_mode==='durable','integrity');
 for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','ipc_version'])need(frame[key]===binding[key],'integrity');
 need(same(record,{record_id:id,session_ref:ref(binding.ipc_session_id,session.binding_digest),direction:r.direction,sequence:frame.seq,message_id:frame.message_id,
  message_type:frame.type,frame_digest:r.frame_digest,wire_digest:r.wire_digest,wire_length:r.wire.length,
  frame_object_ref:ref(id+'.frame',r.frame_digest),wire_object_ref:ref(id+'.wire',r.wire_digest),record_digest}),'integrity');
 const domain=document(r.domain_jcs,r.domain_digest),effect=document(r.effect_jcs,r.effect_digest),audit=document(r.audit_jcs,r.audit_digest);
 need(same(domain,{transaction_id:r.transaction_id,source_ref:ref(openingId+(phase==='request'?'.dispatch':'.ack'),sourceDigest)})&&
  same(audit,{kind:'initial_open_'+phase,opening_id:openingId,source_digest:sourceDigest})&&
  same(effect,{record_ref:ref(id,record_digest),disposition:'applied',domain_commit_refs:[ref(r.transaction_id,r.domain_digest)],
   audit_ref:ref(r.transaction_id+'.audit',r.audit_digest),reply_record_refs:[],committed_tick_ns:String(BigInt(r.committed_tick))})&&r.committed_tick>=r.observed_tick,'integrity');
 return {frame,record,wire:Buffer.from(r.wire),transaction:r.transaction_id,observedTick:BigInt(r.observed_tick),replyRecord:r.reply_record_id};
}
function effect(db,item,openingId,phase,value,tick){
 const sourceDigest=digest(value),domain={transaction_id:item.transaction,source_ref:ref(openingId+(phase==='request'?'.dispatch':'.ack'),sourceDigest)};
 const audit={kind:'initial_open_'+phase,opening_id:openingId,source_digest:sourceDigest};
 const body={record_ref:ref(item.record.record_id,item.record.record_digest),disposition:'applied',domain_commit_refs:[ref(item.transaction,digest(domain))],
  audit_ref:ref(item.transaction+'.audit',digest(audit)),reply_record_refs:[],committed_tick_ns:String(tick)};
 need(db.prepare('INSERT INTO execution_open_frame(record_id,transaction_id,opening_id,phase,domain_jcs,domain_digest) VALUES(?,?,?,?,?,?)')
  .run(item.record.record_id,item.transaction,openingId,phase,canonicalize(domain),digest(domain)).changes===1,'storage');
 need(db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(item.record.record_id,item.transaction,'applied',executionTick(tick),
  canonicalize(audit),digest(audit),canonicalize(body),digest(body)).changes===1,'storage');
}
function configured(db,bound){
 const selected=db.prepare(`SELECT a.message_id,a.frame_jcs,a.frame_digest,q.frame_jcs,q.frame_digest FROM device_module_frame a
 JOIN device_module_frame q ON q.message_id=a.reply_to WHERE a.channel_id=? AND a.message_type='EXECUTION_BOUND' AND a.direction='w2c'
 AND q.message_type='BIND_EXECUTION' AND q.direction='c2w' AND json_extract(a.frame_jcs,'$.body.execution_ref.id')=?
 ORDER BY length(a.sequence),a.sequence LIMIT 1`).raw().get(bound.catalog.channel_id,bound.ref.id);
 need(selected,'worker_binding');const ack=document(selected[1],selected[2]),request=document(selected[3],selected[4]);
 need(ack.version==='device-module/3'&&request.version===ack.version&&ack.sequence===request.sequence&&ack.reply_to===request.request_id&&
  same(ack.binding,request.binding)&&ack.body.device_id===bound.value.binding.device_id&&ack.body.device_session_id===bound.value.binding.device_session_id&&
  request.body.device_id===ack.body.device_id&&request.body.device_session_id===ack.body.device_session_id&&
  same(ack.body.execution_ref,bound.ref)&&same(request.body.execution,{ref:bound.ref,value:bound.value}),'worker_binding');
 return ref(selected[0],selected[2]);
}
export function readInitialOpenDispatch(db,id){return memoExecutionRead(db,'open-dispatch',id,()=>readDispatch(db,id));}
function readDispatch(db,id){
 need(db.inTransaction,'writer');const stored=row(db,'SELECT * FROM execution_initial_open_dispatch WHERE opening_id=?',id);if(!stored)return null;
 const value=document(stored.body_jcs,stored.body_digest),request=applied(db,stored.request_record_id,id,'request',stored.body_digest);
 const opening=row(db,'SELECT body_jcs,body_digest,resource_source_id FROM device_initial_open WHERE opening_id=?',id);need(opening,'integrity');
 const plan=JSON.parse(opening.body_jcs),{digest:planDigest,...unsigned}=plan;
 need(canonicalize(plan)===opening.body_jcs&&planDigest===opening.body_digest&&digest(unsigned)===planDigest&&
  same(value.opening_ref,ref(id,planDigest))&&value.dispatch_id===id+'.dispatch'&&value.format==='leafseamer-initial-open-dispatch/1'&&
  same(value.request_record_ref,ref(request.record.record_id,request.record.record_digest))&&request.transaction===stored.request_transaction_id&&
  request.frame.reply_to===null&&request.replyRecord===null&&same(request.frame.body,plan.plan.body)&&request.frame.device_id===plan.plan.binding.device_id&&
  value.worker_configuration_ref.id===stored.configuration_message_id,'integrity');
 const config=row(db,'SELECT frame_jcs,frame_digest FROM device_module_frame WHERE message_id=?',stored.configuration_message_id);need(config,'worker_binding');
 const configFrame=document(config.frame_jcs,config.frame_digest);
 need(value.worker_configuration_ref.revision==='1'&&value.worker_configuration_ref.digest===config.frame_digest&&configFrame.type==='EXECUTION_BOUND','integrity');
 // 装配引用的实际Binding通过资源原件的binding_ref定位；不把资源Ref误当执行Binding。
 const resource=row(db,'SELECT body_jcs,body_digest FROM device_initial_resource WHERE source_id=?',opening.resource_source_id);need(resource,'integrity');
 const source=JSON.parse(resource.body_jcs),{digest:sourceDigest,...sourceBody}=source;
 need(canonicalize(source)===resource.body_jcs&&digest(sourceBody)===sourceDigest&&sourceDigest===resource.body_digest&&
  same(plan.resource_source_ref,ref(opening.resource_source_id,sourceDigest))&&same(configFrame.body.execution_ref,source.inventory.binding_ref),'worker_binding');
 const ackRow=row(db,'SELECT * FROM execution_initial_open_ack WHERE opening_id=?',id);let confirmation=null,ack=null;
 if(ackRow){confirmation=document(ackRow.body_jcs,ackRow.body_digest);ack=applied(db,ackRow.record_id,id,'ack',ackRow.body_digest);
  need(confirmation.confirmation_id===id+'.ack'&&confirmation.format==='leafseamer-initial-open-confirmation/1'&&confirmation.gate_state==='open_observed'&&
   same(confirmation.dispatch_ref,ref(id+'.dispatch',stored.body_digest))&&same(confirmation.record_ref,ref(ack.record.record_id,ack.record.record_digest))&&
   confirmation.write_attempt_id===ackRow.write_attempt_id&&ack.transaction===ackRow.transaction_id&&ack.replyRecord===request.record.record_id&&
   ack.frame.reply_to===request.frame.message_id&&same(ack.frame.body,expectedAck(request.frame.body)),'integrity');
 }
 return {value,ref:ref(id+'.dispatch',stored.body_digest),opening,plan,request,confirmation,confirmation_ref:ackRow?ref(id+'.ack',ackRow.body_digest):null,ack};
}
function expectedAck(body){return {gate_token:body.gate_token,gate_revision:body.gate_revision,state:'open',
 run_deny_snapshot_revision:body.run_deny_snapshot.snapshot_revision,run_deny_snapshot_digest:body.run_deny_snapshot.snapshot_digest,
 command_deny_snapshot_revision:body.command_deny_snapshot.snapshot_revision,command_deny_snapshot_digest:body.command_deny_snapshot.snapshot_digest,
 reference_time_snapshot_ref:null,gate_access_ref:{id:body.gate_access.access_id,revision:body.gate_access.revision,digest:body.gate_access.access_digest}};}
export function currentInitialOpenDispatch(db,{binding,runtime,id,provider}){
 return withExecutionReadView(db,()=>{
 const saved=readInitialOpenDispatch(db,id);need(saved&&saved.request.frame.ipc_session_id===binding.ipc_session_id,'missing');
 const opening=provider.current(saved.value.opening_ref,saved.ref),bound=currentDeviceExecutionBinding(db,runtime,saved.request.frame.device_id,binding.ipc_session_id);
 need(same(opening.value,saved.plan)&&same(opening.value.plan.binding,bound.value.binding)&&same(configured(db,bound),saved.value.worker_configuration_ref),'changed');return saved;
 });
}
export function prepareInitialOpenDispatch(db,{binding,runtime,reference,features,tick,provider}){
 need(db.inTransaction&&provider,'writer');const old=readInitialOpenDispatch(db,reference?.id);
 if(old){need(same(old.value.opening_ref,reference),'reference');return currentInitialOpenDispatch(db,{binding,runtime,id:reference.id,provider});}
 const opening=provider.current(reference),device=opening.value.plan.binding.device_id,bound=currentDeviceExecutionBinding(db,runtime,device,binding.ipc_session_id);
 need(same(opening.value.plan.binding,bound.value.binding)&&opening.value.plan.body.reference_time_snapshot===null,'binding');
 const configuration=configured(db,bound),previous=db.prepare("SELECT sequence FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' ORDER BY sequence DESC LIMIT 1").pluck().get(binding.ipc_session_id);
 const frame={ipc_version:deviceExecutionVersion,type:'OPEN_GATE',message_id:crypto.randomUUID(),reply_to:null,ipc_session_id:binding.ipc_session_id,
  controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:String(BigInt(previous)+1n),device_id:device,
  clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',body:opening.value.plan.body};
 assertDeviceExecutionFeatures(frame,features);const item=preparedFrame(binding,frame,Buffer.from(JSON.stringify(frame)),'c2w',tick());
 const value={format:'leafseamer-initial-open-dispatch/1',dispatch_id:reference.id+'.dispatch',opening_ref:reference,
  worker_configuration_ref:configuration,request_record_ref:ref(item.record.record_id,item.record.record_digest)};
 insertFrame(db,item,'initial_open');
 need(db.prepare('INSERT INTO execution_initial_open_dispatch VALUES(?,?,?,?,?,?)').run(reference.id,item.record.record_id,item.transaction,configuration.id,canonicalize(value),digest(value)).changes===1,'storage');
 effect(db,item,reference.id,'request',value,tick());const saved=readInitialOpenDispatch(db,reference.id);
 need(tick()<BigInt(frame.body.lease_until_tick_ns),'expired');return saved;
}
export function acceptInitialOpenAck(db,{binding,runtime,decoded,features,tick,provider}){
 const {frame,payload}=decoded,id=db.prepare(`SELECT p.opening_id FROM execution_initial_open_dispatch p JOIN execution_frame_record f ON f.record_id=p.request_record_id
 WHERE f.ipc_session_id=? AND f.message_id=?`).pluck().get(binding.ipc_session_id,frame.reply_to);need(id,'reply');
 const saved=currentInitialOpenDispatch(db,{binding,runtime,id,provider});
 if(saved.ack){need(saved.ack.wire.equals(executionWire(payload)),'replay_conflict');return saved;}
 assertDeviceExecutionFeatures(frame,features);const request=saved.request.frame,now=tick();
 for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','device_id'])need(frame[key]===request[key],'reply');
 const attempt=row(db,`SELECT a.attempt_id,a.started_tick,r.result FROM execution_write_attempt a LEFT JOIN execution_write_result r USING(attempt_id) WHERE a.record_id=?`,saved.request.record.record_id);
 need(frame.type==='OPEN_GATE_ACK'&&attempt&&attempt.result!=='unknown'&&BigInt(attempt.started_tick)<=now&&now<BigInt(request.body.lease_until_tick_ns)&&same(frame.body,expectedAck(request.body)),'reply');
 const item=preparedFrame(binding,frame,payload,'w2c',now,saved.request.record.record_id),value={format:'leafseamer-initial-open-confirmation/1',confirmation_id:id+'.ack',
  dispatch_ref:saved.ref,record_ref:ref(item.record.record_id,item.record.record_digest),write_attempt_id:attempt.attempt_id,gate_state:'open_observed'};
 insertFrame(db,item,'initial_open');
 need(db.prepare('INSERT INTO execution_initial_open_ack VALUES(?,?,?,?,?,?)').run(id,item.record.record_id,item.transaction,attempt.attempt_id,canonicalize(value),digest(value)).changes===1,'storage');
 effect(db,item,id,'ack',value,tick());const confirmed=readInitialOpenDispatch(db,id);
 need(tick()<BigInt(request.body.lease_until_tick_ns),'expired');return confirmed;
}
