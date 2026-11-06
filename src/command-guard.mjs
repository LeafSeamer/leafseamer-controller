import {withExecutionReadView,memoExecutionRead} from './execution-read-view.mjs';
import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {preparedFrame,insertFrame} from './device-execution-handshake.mjs';
import {executionTick} from './device-execution-handshake.mjs';
import {currentPreparedCommand,readCommandFinalAdmission} from './command-final-admission.mjs';
import {readOriginalRecord} from './command-record-store.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('command_guard_'+code);};
const ref=(id,v)=>({id,revision:'1',digest:digest(v)});
const hash=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const parse=(text,hash)=>{const v=JSON.parse(text);need(canonical(v)===text&&'sha256:'+crypto.createHash('sha256').update(text).digest('hex')===hash,'integrity');return v;};
const written=result=>need(result.changes===1,'storage');
function row(db,sql,...args){const q=db.prepare(sql),names=q.columns().map(v=>v.name),values=q.raw().get(...args);return values&&Object.fromEntries(names.map((n,i)=>[n,values[i]]));}
const body=v=>({guard:v.guard,content_digest:v.permit.content_digest,schedule_guard:null,reference_context:null});
function expectedAck(v){const g=v.guard;return {guard_id:g.guard_id,guard_digest:g.guard_digest,content_digest:v.permit.content_digest,
 permit_id:g.permit_id,command_id:g.command_id,installed_authorization_revision:g.authorization_revision,state:'installed',
 panel_binding_digest:null,automation_binding_digest:null,reference_time_digest:null,schedule_guard_digest:null,gate_access_ref:g.gate_access_ref,ownership_ref:g.ownership_ref};}
function effect(db,item,id,phase,value,now){
 const domain={transaction_id:item.transaction,source_ref:ref(id+(phase==='request'?'':'.response'),value)},audit={kind:'command_guard_'+phase,guard_id:id,source_digest:digest(value)};
 const e={record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest},disposition:'applied',domain_commit_refs:[ref(item.transaction,domain)],
  audit_ref:ref(item.transaction+'.audit',audit),reply_record_refs:[],committed_tick_ns:String(now)};
 written(db.prepare('INSERT INTO execution_guard_frame(record_id,transaction_id,guard_id,phase,domain_jcs,domain_digest) VALUES(?,?,?,?,?,?)')
  .run(item.record.record_id,item.transaction,id,phase,canonical(domain),digest(domain)));
 written(db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(item.record.record_id,item.transaction,'applied',executionTick(now),canonical(audit),digest(audit),canonical(e),digest(e)));
}
function applied(db,id,prepare,phase,value){
 const r=row(db,`SELECT f.*,e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest,e.committed_tick,x.domain_jcs,x.domain_digest,x.phase
  FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
  JOIN execution_guard_frame x USING(record_id,transaction_id) WHERE f.record_id=?`,id);need(r,'integrity');
 const frame=parse(r.frame_jcs,r.frame_digest),record=JSON.parse(r.record_jcs),{record_digest,...unsigned}=record,
  session=row(db,'SELECT binding_jcs,binding_digest FROM execution_session WHERE ipc_session_id=?',r.ipc_session_id);need(session,'integrity');
 const binding=parse(session.binding_jcs,session.binding_digest);
 need(canonical(record)===r.record_jcs&&digest(unsigned)===record_digest&&record_digest===r.record_digest&&
  r.wire.readUInt32BE(0)===r.wire.length-4&&hash(r.wire)===r.wire_digest&&same(JSON.parse(r.wire.subarray(4)),frame)&&
  r.domain_kind==='command_guard'&&r.phase===phase&&r.direction===(phase==='request'?'c2w':'w2c')&&
  (phase==='request'?frame.type==='GUARD_INSTALL':frame.type==='GUARD_ACK')&&
  r.message_type===frame.type&&r.message_id===frame.message_id&&r.device_id===frame.device_id&&r.sequence===executionTick(BigInt(frame.seq))&&frame.journal_mode==='durable','integrity');
 for(const key of ['ipc_version','ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'])need(frame[key]===binding[key],'binding');
 need(same(record,{record_id:id,session_ref:{id:binding.ipc_session_id,revision:'1',digest:session.binding_digest},direction:r.direction,sequence:frame.seq,
  message_id:frame.message_id,message_type:frame.type,frame_digest:r.frame_digest,wire_digest:r.wire_digest,wire_length:r.wire.length,
  frame_object_ref:{id:id+'.frame',revision:'1',digest:r.frame_digest},wire_object_ref:{id:id+'.wire',revision:'1',digest:r.wire_digest},record_digest}),'integrity');
 const domain=parse(r.domain_jcs,r.domain_digest),audit=parse(r.audit_jcs,r.audit_digest),e=parse(r.effect_jcs,r.effect_digest);
 need(same(domain,{transaction_id:r.transaction_id,source_ref:ref(prepare+(phase==='request'?'':'.response'),value)})&&
  same(audit,{kind:'command_guard_'+phase,guard_id:prepare,source_digest:digest(value)})&&
  same(e,{record_ref:{id,revision:'1',digest:record_digest},disposition:'applied',domain_commit_refs:[ref(r.transaction_id,domain)],
   audit_ref:ref(r.transaction_id+'.audit',audit),reply_record_refs:[],committed_tick_ns:String(BigInt(r.committed_tick))})&&r.committed_tick>=r.observed_tick,'integrity');
 return {frame,record,wire:Buffer.from(r.wire),transaction:r.transaction_id,observedTick:BigInt(r.observed_tick),committedTick:BigInt(r.committed_tick),replyRecord:r.reply_record_id};
}

export function readCommandGuard(db,id){return withExecutionReadView(db,()=>memoExecutionRead(db,'command-guard',id,()=>readGuard(db,id)));}
function readGuard(db,id){
 need(db.inTransaction,'writer');const r=row(db,'SELECT * FROM command_guard_request WHERE guard_id=?',id);need(r,'missing');
 const source=row(db,'SELECT command_id,body_digest FROM command_final_admission WHERE transaction_id=?',r.final_transaction_id);need(source,'final_source');
 const commandId=source.command_id,initial=readOriginalRecord(db,commandId),final=readCommandFinalAdmission(db,initial,{id:r.final_transaction_id,revision:'1',digest:source.body_digest});
 need(final&&final.value.guard.guard_id===id,'final_source');
 const value=parse(r.body_jcs,r.body_digest),request=applied(db,r.record_id,id,'request',value);
 need(same(value,{format:'command-guard-install/1',guard_id:id,final_admission_ref:final.ref,request_record_ref:{id:r.record_id,revision:'1',digest:request.record.record_digest}})&&
  same(request.frame.body,body(final.value))&&request.frame.ipc_session_id===final.value.seal.binding.ipc_session_id&&
  request.frame.device_id===final.value.seal.binding.device_id,'request');
 const saved={value,ref:ref(id,value),request,final,command_id:commandId};
 const a=row(db,'SELECT * FROM command_guard_ack WHERE guard_id=?',id);if(!a)return {...saved,ack:null};
 const acknowledgement=parse(a.body_jcs,a.body_digest),reply=applied(db,a.record_id,id,'response',acknowledgement),
  write=row(db,'SELECT record_id,started_tick FROM execution_write_attempt WHERE attempt_id=?',a.write_attempt_id);
 need(write&&write.record_id===r.record_id&&BigInt(write.started_tick)<=reply.observedTick&&reply.replyRecord===r.record_id&&
  reply.frame.reply_to===request.frame.message_id&&reply.frame.ipc_session_id===request.frame.ipc_session_id&&reply.frame.device_id===request.frame.device_id&&
  same(reply.frame.body,expectedAck(final.value))&&same(acknowledgement,{format:'command-guard-ack/1',guard_id:id,request_ref:saved.ref,
   record_ref:{id:a.record_id,revision:'1',digest:reply.record.record_digest},write_attempt_id:a.write_attempt_id,disposition:a.disposition})&&
  (a.disposition==='historical'||reply.committedTick<BigInt(final.value.seal.send_window.before_tick_ns)),'ack');
 return {...saved,ack:{value:acknowledgement,ref:ref(id+'.response',acknowledgement),reply}};
}
export function selectCommandGuard(db,{id,binding,provider,tick,features}){
 need(db.inTransaction&&[53,54,55].includes(Number(db.pragma('user_version',{simple:true}))),'writer');
 const prior=db.prepare('SELECT g.guard_id FROM command_guard_request g JOIN command_final_admission f ON f.transaction_id=g.final_transaction_id WHERE f.command_id=?').pluck().get(id);
 if(prior)return {saved:readCommandGuard(db,prior)};
 const actual=currentPreparedCommand(db,{id,binding,provider,tick}),v=actual.final.value;
 const previous=db.prepare("SELECT sequence FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' ORDER BY sequence DESC LIMIT 1").pluck().get(binding.ipc_session_id);
 const frame={ipc_version:deviceExecutionVersion,type:'GUARD_INSTALL',message_id:crypto.randomUUID(),reply_to:null,ipc_session_id:binding.ipc_session_id,
  controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:String(BigInt(previous)+1n),device_id:v.seal.binding.device_id,
  clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',body:body(v)};
 assertDeviceExecutionFeatures(frame,features);return {frame,id};
}
export function commitCommandGuard(db,{candidate,binding,provider,tick}){
 const actual=currentPreparedCommand(db,{id:candidate.id,binding,provider,tick}),v=actual.final.value;
 need(same(candidate.frame.body,body(v)),'changed');const item=preparedFrame(binding,candidate.frame,Buffer.from(JSON.stringify(candidate.frame)),'c2w',tick()),id=v.guard.guard_id;
 const value={format:'command-guard-install/1',guard_id:id,final_admission_ref:actual.final.ref,request_record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest}};
 insertFrame(db,item,'command_guard');
 written(db.prepare('INSERT INTO command_guard_request VALUES(?,?,?,?,?,?)').run(id,v.transaction_id,item.record.record_id,item.transaction,canonical(value),digest(value)));
 effect(db,item,id,'request',value,tick());const saved=readCommandGuard(db,id);
 need(tick()<BigInt(v.seal.send_window.before_tick_ns),'expired');return saved;
}
export function currentCommandGuard(db,options){return withExecutionReadView(db,()=>currentGuard(db,options));}
function currentGuard(db,{id,binding,provider,tick,requireAck=false}){
 const saved=readCommandGuard(db,id),current=currentPreparedCommand(db,{id:saved.command_id,binding,provider,tick});
 need(same(current.final.ref,saved.final.ref),'changed');
 if(requireAck){const result=saved.ack&&db.prepare('SELECT result FROM execution_write_result WHERE attempt_id=?').pluck().get(saved.ack.value.write_attempt_id);
  need(saved.ack?.value.disposition==='installed'&&result==='complete','not_installed');}
 return {...saved,qualification:{command_id:saved.command_id,final_admission_ref:current.final.ref,resource:current.final.value.resource_after,
  permit_id:current.final.value.permit.permit_id,observation:current.observation,selected_tick_ns:current.selected_tick_ns,send_window:current.final.value.seal.send_window}};
}
export function acceptCommandGuard(db,{binding,decoded,provider,tick,features,receivedTick}){
 const {frame,payload}=decoded;assertDeviceExecutionFeatures(frame,features);
 const id=db.prepare(`SELECT g.guard_id FROM command_guard_request g JOIN execution_frame_record f ON f.record_id=g.record_id
  WHERE f.ipc_session_id=? AND f.message_id=?`).pluck().get(binding.ipc_session_id,frame.reply_to);need(id,'reply');
 const saved=readCommandGuard(db,id),request=saved.request.frame;
 if(saved.ack){need(saved.ack.reply.wire.equals(executionWire(payload)),'replay_conflict');return saved;}
 for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','device_id'])need(frame[key]===request[key],'reply');
 need(frame.type==='GUARD_ACK'&&same(frame.body,expectedAck(saved.final.value)),'reply');
 const write=row(db,'SELECT attempt_id,started_tick FROM execution_write_attempt WHERE record_id=?',saved.request.record.record_id);
 need(write&&BigInt(write.started_tick)<=receivedTick,'write');let disposition='installed';
 try{currentCommandGuard(db,{id,binding,provider,tick});
  need(db.prepare('SELECT result FROM execution_write_result WHERE attempt_id=?').pluck().get(write.attempt_id)!=='unknown','write');
 }catch{disposition='historical';}
 const item=preparedFrame(binding,frame,payload,'w2c',receivedTick,saved.request.record.record_id),value={format:'command-guard-ack/1',guard_id:id,
  request_ref:saved.ref,record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest},write_attempt_id:write.attempt_id,disposition};
 insertFrame(db,item,'command_guard');written(db.prepare('INSERT INTO command_guard_ack VALUES(?,?,?,?,?,?,?)').run(id,item.record.record_id,item.transaction,write.attempt_id,disposition,canonical(value),digest(value)));
 effect(db,item,id,'response',value,tick());const result=readCommandGuard(db,id);
 need(disposition==='historical'||tick()<BigInt(saved.final.value.seal.send_window.before_tick_ns),'expired');return result;
}
// Guard安装自身不触发设备I/O。只排除逐字验证且属于该精确T2的帧，不能排除DISPATCH。
export function guardOnlyFrame(db,recordId,binding,preparedRef){
 need(preparedRef,'prepared_source');const id=db.prepare('SELECT guard_id FROM command_guard_request WHERE record_id=?').pluck().get(recordId);need(id,'ledger');
 const saved=readCommandGuard(db,id);need(same(saved.final.ref,preparedRef)&&same(saved.final.value.seal.binding,binding),'ledger');return saved.ref;
}
