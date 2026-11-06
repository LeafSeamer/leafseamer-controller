import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {preparedFrame,insertFrame,executionTick} from './device-execution-handshake.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {deviceRegistryReader} from './device-registry-store.mjs';
import {currentControlSource,readControlSource} from './device-control-source.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
import {memoExecutionRead} from './execution-read-view.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
const hash=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const digest=value=>hash(canonicalize(value));
const ref=(id,hash)=>({id,revision:'1',digest:hash});
const same=(a,b)=>canonicalize(a)===canonicalize(b);
function read(text,expected){const value=JSON.parse(text);need(canonicalize(value)===text&&digest(value)===expected,'execution_control_integrity');return value;}
function row(db,sql,...args){const q=db.prepare(sql),names=q.columns().map(c=>c.name),values=q.raw().get(...args);return values&&Object.fromEntries(names.map((n,i)=>[n,values[i]]));}
function source(db,binding,runtime,device){
 need(db.inTransaction,'execution_control_writer');
 const bound=currentDeviceExecutionBinding(db,runtime,device,binding.ipc_session_id);
 const control=deviceRegistryReader(db,{...binding,schema_revision:'31'}).control(device);
 need(control.mode==='manual'&&control.holder&&control.pending_change===null&&control.gate_state==='protected'&&
  control.in_flight_command_ids.length===0&&control.unresolved_command_ids.length===0,'execution_control_source');
 need(!db.prepare("SELECT 1 FROM ca_adjudication a JOIN ca_request_key k USING(key_id) WHERE k.device_id=? AND a.decision!='rejected'").pluck().get(device),'execution_control_command_cut');
 const source=Number(db.pragma('user_version',{simple:true}))>=32?currentControlSource(db,device):null;
 if(source)need(source.current.value.clock_domain_id===binding.clock_domain_id&&source.current.value.descriptor_digest===binding.descriptor_digest&&
  source.current.value.revision===control.revision&&same(source.current.ref,source.authority.ref),'execution_control_source');
 return {bound,control,source};
}
function frame(db,id,phase,sourceId,sourceDigest){
 const stored=row(db,`SELECT f.*,e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest,e.committed_tick,
  x.domain_jcs,x.domain_digest,x.phase FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
  JOIN execution_control_frame x USING(record_id,transaction_id) WHERE f.record_id=?`,id);need(stored,'execution_control_integrity');
 const value=read(stored.frame_jcs,stored.frame_digest),record=JSON.parse(stored.record_jcs),{record_digest,...unsigned}=record;
 const session=row(db,'SELECT binding_jcs,binding_digest FROM execution_session WHERE ipc_session_id=?',stored.ipc_session_id);need(session,'execution_control_integrity');
 const binding=read(session.binding_jcs,session.binding_digest);
 need(canonicalize(record)===stored.record_jcs&&record_digest===stored.record_digest&&digest(unsigned)===record_digest&&
  stored.wire.readUInt32BE(0)===stored.wire.length-4&&hash(stored.wire)===stored.wire_digest&&same(JSON.parse(stored.wire.subarray(4)),value)&&
  stored.domain_kind==='initial_control'&&stored.phase===phase&&stored.sequence===executionTick(BigInt(value.seq))&&
  stored.direction===(phase==='request'?'c2w':'w2c')&&stored.message_type===(phase==='request'?'FENCE':'FENCE_ACK')&&
  value.type===stored.message_type&&value.device_id===stored.device_id&&value.message_id===stored.message_id&&value.journal_mode==='durable','execution_control_integrity');
 for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','ipc_version'])need(value[key]===binding[key],'execution_control_integrity');
 need(same(record,{record_id:id,session_ref:ref(binding.ipc_session_id,session.binding_digest),direction:stored.direction,sequence:value.seq,message_id:value.message_id,
  message_type:value.type,frame_digest:stored.frame_digest,wire_digest:stored.wire_digest,wire_length:stored.wire.length,
  frame_object_ref:ref(id+'.frame',stored.frame_digest),wire_object_ref:ref(id+'.wire',stored.wire_digest),record_digest}),'execution_control_integrity');
 const domain=read(stored.domain_jcs,stored.domain_digest),effect=read(stored.effect_jcs,stored.effect_digest),audit=read(stored.audit_jcs,stored.audit_digest);
 need(same(domain,{transaction_id:stored.transaction_id,source_ref:ref(sourceId,sourceDigest)})&&
  same(audit,{kind:'initial_control_'+phase,fence_id:phase==='request'?sourceId:sourceId.slice(0,-4),source_digest:sourceDigest})&&
  same(effect,{record_ref:ref(id,record_digest),disposition:'applied',domain_commit_refs:[ref(stored.transaction_id,stored.domain_digest)],
   audit_ref:ref(stored.transaction_id+'.audit',stored.audit_digest),reply_record_refs:[],committed_tick_ns:String(BigInt(stored.committed_tick))})&&
  stored.committed_tick>=stored.observed_tick,'execution_control_integrity');
 return {frame:value,wire:Buffer.from(stored.wire),record,transaction:stored.transaction_id,observedTick:BigInt(stored.observed_tick),replyRecord:stored.reply_record_id};
}
function effect(db,item,fenceId,phase,value,committedTick){
 const sourceId=phase==='request'?fenceId:fenceId+'.ack',sourceDigest=digest(value),domain={transaction_id:item.transaction,source_ref:ref(sourceId,sourceDigest)};
 const audit={kind:'initial_control_'+phase,fence_id:fenceId,source_digest:sourceDigest};
 const body={record_ref:ref(item.record.record_id,item.record.record_digest),disposition:'applied',domain_commit_refs:[ref(item.transaction,digest(domain))],
  audit_ref:ref(item.transaction+'.audit',digest(audit)),reply_record_refs:[],committed_tick_ns:String(committedTick)};
 need(db.prepare('INSERT INTO execution_control_frame(record_id,transaction_id,fence_id,phase,domain_jcs,domain_digest) VALUES(?,?,?,?,?,?)')
  .run(item.record.record_id,item.transaction,fenceId,phase,canonicalize(domain),digest(domain)).changes===1,'execution_control_storage');
 need(db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(item.record.record_id,item.transaction,'applied',executionTick(committedTick),
  canonicalize(audit),digest(audit),canonicalize(body),digest(body)).changes===1,'execution_control_storage');
}
export function readInitialFence(db,id){return memoExecutionRead(db,'initial-fence',id,()=>readFence(db,id));}
function readFence(db,id){
 const stored=row(db,'SELECT * FROM execution_initial_fence WHERE fence_id=?',id);if(!stored)return null;
 const value=read(stored.body_jcs,stored.body_digest),request=frame(db,stored.request_record_id,'request',id,stored.body_digest);
 const control=row(db,'SELECT body_jcs,body_digest FROM control_record_revision WHERE device_id=? AND revision=?',stored.control_device_id,stored.control_revision);
 const bound=row(db,'SELECT body_jcs,body_digest FROM device_execution_binding WHERE binding_id=?',stored.binding_id);
 need(control&&bound&&same(value.control_record,read(control.body_jcs,control.body_digest))&&same(value.binding_ref,ref(stored.binding_id,bound.body_digest))&&
  same(value.request_record_ref,ref(request.record.record_id,request.record.record_digest))&&value.fence_id===id&&request.frame.body.barrier_id===id&&
  request.transaction===stored.request_transaction_id&&request.frame.reply_to===null&&request.replyRecord===null&&value.gate_state==='closed','execution_control_integrity');
 if(value.control_source_ref)need(same(value.control_source_ref,readControlSource(db,stored.control_device_id,stored.control_revision).ref),'execution_control_integrity');
 const ackRow=row(db,'SELECT * FROM execution_initial_fence_ack WHERE fence_id=?',id);let confirmation=null,ack=null;
 if(ackRow){confirmation=read(ackRow.body_jcs,ackRow.body_digest);ack=frame(db,ackRow.record_id,'ack',id+'.ack',ackRow.body_digest);
  need(same(confirmation.fence_ref,ref(id,stored.body_digest))&&same(confirmation.record_ref,ref(ack.record.record_id,ack.record.record_digest))&&
   confirmation.confirmation_id===id+'.ack'&&confirmation.gate_state==='closed'&&ack.transaction===ackRow.transaction_id&&ack.replyRecord===request.record.record_id&&
   ack.frame.reply_to===request.frame.message_id,'execution_control_integrity');
 }
 return {value,ref:ref(id,stored.body_digest),request,confirmation,confirmation_ref:ackRow?ref(id+'.ack',ackRow.body_digest):null,ack};
}
export function prepareInitialFence(db,{binding,runtime,device,features,tick}){
 const {bound,control,source:controlSource}=source(db,binding,runtime,device);
 const old=db.prepare('SELECT fence_id FROM execution_initial_fence WHERE binding_id=?').pluck().get(bound.ref.id);
 if(old){const result=readInitialFence(db,old);need(same(result.value.control_record,control),'execution_control_changed');return result;}
 const id=crypto.randomUUID(),body={barrier_id:id,operation_id:id+'.operation',control_epoch:control.control_epoch,target_version:control.effective_version,target_gate_revision:'1',issued_cut_revision:'0',
  ledger_digest:digest([]),open_intents:[],transmission_ledger_digest:digest([]),open_transmission_intents:[],cancel_transmissions:[],cancel_ledger_digest:digest([])};
 const {barrier_id,...cut}=body;
 body.attempt_binding={cut_id:id+'_cut',cut_digest:digest({type:'FENCE',target_exit_id:bound.value.binding.writer_exit_id,body:cut}),target_exit_id:bound.value.binding.writer_exit_id,attempt_ordinal:'1',previous_barrier_id:null};
 const previous=db.prepare("SELECT sequence FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' ORDER BY sequence DESC LIMIT 1").pluck().get(binding.ipc_session_id);
 const outgoing={ipc_version:deviceExecutionVersion,type:'FENCE',message_id:crypto.randomUUID(),reply_to:null,ipc_session_id:binding.ipc_session_id,
  controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:String(BigInt(previous)+1n),device_id:device,
  clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',body};
 assertDeviceExecutionFeatures(outgoing,features);
 const item=preparedFrame(binding,outgoing,Buffer.from(JSON.stringify(outgoing)),'c2w',tick());
 const value={format:'leafseamer-initial-control-fence/1',fence_id:id,binding_ref:bound.ref,control_record:control,
  request_record_ref:ref(item.record.record_id,item.record.record_digest),gate_state:'closed',...(controlSource?{control_source_ref:controlSource.current.ref}:{})};
 insertFrame(db,item,'initial_control');
 need(db.prepare('INSERT INTO execution_initial_fence VALUES(?,?,?,?,?,?,?,?)').run(id,bound.ref.id,device,Number(control.revision),item.record.record_id,item.transaction,canonicalize(value),digest(value)).changes===1,'execution_control_storage');
 effect(db,item,id,'request',value,tick());return readInitialFence(db,id);
}
export function currentInitialFence(db,{binding,runtime,id}){
 const stored=readInitialFence(db,id);need(stored&&stored.request.frame.ipc_session_id===binding.ipc_session_id,'execution_control_missing');
 const current=source(db,binding,runtime,stored.request.frame.device_id);
 need(same(stored.value.binding_ref,current.bound.ref)&&same(stored.value.control_record,current.control),'execution_control_changed');return stored;
}
export function acceptInitialFenceAck(db,{binding,runtime,decoded,features,tick}){
 const {frame:incoming,payload}=decoded;
 const found=db.prepare(`SELECT p.fence_id FROM execution_initial_fence p JOIN execution_frame_record f ON f.record_id=p.request_record_id
  WHERE f.ipc_session_id=? AND f.message_id=?`).pluck().get(binding.ipc_session_id,incoming.reply_to);need(found,'execution_control_reply');
 const stored=currentInitialFence(db,{binding,runtime,id:found});
 if(stored.ack){need(stored.ack.wire.equals(executionWire(payload)),'execution_replay_conflict');return stored;}
 assertDeviceExecutionFeatures(incoming,features);const request=stored.request.frame,b=request.body,now=tick();
 for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','device_id'])need(incoming[key]===request[key],'execution_control_reply');
 const attempt=row(db,'SELECT started_tick FROM execution_write_attempt WHERE record_id=?',stored.request.record.record_id);
 need(incoming.type==='FENCE_ACK'&&attempt&&BigInt(incoming.body.effective_tick_ns)>=BigInt(attempt.started_tick)&&BigInt(incoming.body.effective_tick_ns)<=now,'execution_control_observation');
 need(same(incoming.body,{ack:{barrier_id:b.barrier_id,operation_id:b.operation_id,device_id:request.device_id,controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,
  control_epoch:b.control_epoch,installed_version:b.target_version,discarded_permit_ids:[],in_flight_command_ids:[],unresolved_command_ids:[],all_write_exits_fenced:true,
  clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest},issued_cut_revision:'0',ledger_digest:b.ledger_digest,gate_revision:'1',coverage:[],transmission_coverage:[],
  attempt_binding:b.attempt_binding,transmission_ledger_digest:b.transmission_ledger_digest,effective_tick_ns:incoming.body.effective_tick_ns,cancel_coverage:[],cancel_ledger_digest:b.cancel_ledger_digest}),'execution_control_reply');
 const item=preparedFrame(binding,incoming,payload,'w2c',now,stored.request.record.record_id),value={format:'leafseamer-initial-control-confirmation/1',confirmation_id:found+'.ack',
  fence_ref:stored.ref,record_ref:ref(item.record.record_id,item.record.record_digest),gate_state:'closed'};
 insertFrame(db,item,'initial_control');
 need(db.prepare('INSERT INTO execution_initial_fence_ack VALUES(?,?,?,?,?)').run(found,item.record.record_id,item.transaction,canonicalize(value),digest(value)).changes===1,'execution_control_storage');
 effect(db,item,found,'ack',value,tick());return readInitialFence(db,found);
}
