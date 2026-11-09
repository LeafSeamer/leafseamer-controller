import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {preparedFrame,insertFrame,executionTick} from './device-execution-handshake.mjs';
import {dispatchEffect,dispatchApplied} from './command-dispatch.mjs';
import {readCommandRecord} from './command-record-store.mjs';
import {readCommandEncoding} from './command-encoding-store.mjs';
import {readCommandClosure} from './command-settlement.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {withExecutionReadView,memoExecutionRead} from './execution-read-view.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('preparation_cleanup_'+code);};
const ref=(id,value)=>({id,revision:'1',digest:digest(value)});
const parse=(text,hash)=>{const value=JSON.parse(text);need(canonical(value)===text&&'sha256:'+crypto.createHash('sha256').update(text).digest('hex')===hash,'integrity');return value;};
const written=result=>need(result.changes===1,'storage');
const phases=['deny_request','deny_ack','release_request','release_ack'];
const types={deny_request:'DENY_ENCODING',deny_ack:'DENY_ENCODING_ACK',release_request:'RELEASE_ENCODING',release_ack:'RELEASE_ENCODING_ACK'};
function row(db,sql,...args){const q=db.prepare(sql),names=q.columns().map(v=>v.name),values=q.raw().get(...args);return values&&Object.fromEntries(names.map((n,i)=>[n,values[i]]));}
function source(db,id){
 need(db.inTransaction,'writer');const command=db.prepare('SELECT command_id FROM command_settlement WHERE permit_id=?').pluck().get(id);need(command,'terminal_required');
 const saved=readCommandRecord(db,command),terminal=saved.lifecycle?.settlement,final=saved.lifecycle?.final_admission;
 need(terminal&&final&&saved.record.state.phase==='finished'&&saved.record.revision==='5'&&final.value.permit.permit_id===id,'terminal_required');
 const encoding=readCommandEncoding(db,final.value.prepare_id),closure=readCommandClosure(db,id);
 need(encoding.value.command_id===command&&closure.ack&&same(terminal.value.ack_ref,closure.ack.ref),'encoding');return {saved,terminal,final,encoding,closure};
}
function retirement(selected,tick){return {format:'command-preparation-retirement/1',command_id:selected.saved.source.command_id,
 permit_id:selected.final.value.permit.permit_id,prepare_id:selected.encoding.value.prepare_id,binding:selected.saved.source.binding,
 state_ref:selected.saved.record.state_ref,settlement_ref:selected.terminal.ref,encoding_ref:selected.encoding.ref,
 encoding_authorization_ref:selected.encoding.response.value.evidence.authorization_ref,
 selected_tick_ns:String(tick),reason:'command_finished'};}
function current(db,id,binding,runtime){
 need([56,57].includes(Number(db.pragma('user_version',{simple:true}))),'version');const selected=source(db,id),b=selected.saved.source.binding,
  actual=currentDeviceExecutionBinding(db,runtime,b.device_id,b.ipc_session_id);
 need(binding.ipc_session_id===b.ipc_session_id&&same(actual.ref,selected.saved.source.binding_ref)&&same(actual.value.binding,b)&&
  !db.prepare('SELECT 1 FROM execution_session_end WHERE ipc_session_id=?').pluck().get(b.ipc_session_id),'binding');return selected;
}
function requestBody(selected,value,phase){
 const encoding=selected.encoding,id=value.permit_id,key=phase==='deny_request'?'deny_id':'release_id';
 const body={[key]:id+(phase==='deny_request'?'.encoding-deny':'.encoding-release'),revision:'1',binding:value.binding,prepare_id:value.prepare_id,
  encoding_authorization_ref:value.encoding_authorization_ref,encode_message_id:encoding.request.frame.message_id,encode_frame_digest:digest(encoding.request.frame),
  revocation_ref:ref(value.prepare_id+'.retirement',value),selected_tick_ns:value.selected_tick_ns};
 return {...body,request_digest:digest(body)};
}
function expectedAck(request,phase,tick){
 const denied=phase==='deny_ack',r=request.frame,b=r.body,body={
  [denied?'deny_ref':'release_ref']:{id:b[denied?'deny_id':'release_id'],revision:'1',digest:b.request_digest},binding:b.binding,prepare_id:b.prepare_id,
  [denied?'deny_message_id':'release_message_id']:r.message_id,[denied?'deny_frame_digest':'release_frame_digest']:digest(r),
  [denied?'effective_tick_ns':'disposed_tick_ns']:tick,state:denied?'denied':'released'};
 return {...body,...(denied?{future_use_denied:true}:{encoder_quiescent:true,consumers_quiescent:true,cache_empty:true})};
}
export function readCommandPreparationCleanup(db,id){return withExecutionReadView(db,()=>memoExecutionRead(db,'command-preparation-cleanup',id,()=>readCleanup(db,id)));}
function readCleanup(db,id){
 const r=row(db,'SELECT * FROM command_preparation_retirement WHERE permit_id=?',id);need(r,'missing');const selected=source(db,id),value=parse(r.body_jcs,r.body_digest);
 need(r.command_id===value.command_id&&r.prepare_id===value.prepare_id&&same(value,retirement(selected,BigInt(value.selected_tick_ns)))&&
  BigInt(value.selected_tick_ns)>=selected.closure.ack.reply.committedTick,'retirement');
 const saved={source:selected,value,ref:ref(value.prepare_id+'.retirement',value),steps:{}};
 for(const phase of phases){
  const step=row(db,'SELECT * FROM command_preparation_cleanup WHERE permit_id=? AND phase=?',id,phase);if(!step)continue;
  const original=parse(step.body_jcs,step.body_digest),frame=dispatchApplied(db,step.record_id,id,phase,original),isRequest=phase.endsWith('_request');
  need(same(original,{format:'command-preparation-cleanup/1',permit_id:id,phase,retirement_ref:saved.ref,
   write_attempt_id:step.write_attempt_id,record_ref:{id:step.record_id,revision:'1',digest:frame.record.record_digest}}),'step');
  const b=frame.frame;
  for(const k of ['ipc_session_id','controller_boot_id','worker_boot_id','device_id','clock_domain_id','descriptor_digest'])need(b[k]===value.binding[k],'binding');
  if(isRequest){need(same(b.body,requestBody(selected,value,phase))&&(phase==='deny_request'||saved.steps.deny_ack),'request');}
  else{const request=saved.steps[phase==='deny_ack'?'deny_request':'release_request'];need(request,'ack_request');
   const attempt=row(db,'SELECT record_id,started_tick FROM execution_write_attempt WHERE attempt_id=?',step.write_attempt_id),tick=b.body[phase==='deny_ack'?'effective_tick_ns':'disposed_tick_ns'];
   need(attempt&&attempt.record_id===request.frame.record.record_id&&frame.replyRecord===attempt.record_id&&b.reply_to===request.frame.frame.message_id&&
    BigInt(tick)>=BigInt(attempt.started_tick)&&BigInt(tick)<=frame.observedTick&&same(b.body,expectedAck(request.frame,phase,tick)),'ack');
  }
  saved.steps[phase]={value:original,ref:ref(id+'.'+phase,original),frame};
 }
 return saved;
}
export function selectCommandPreparationCleanup(db,{id,phase,binding,runtime,tick,features}){
 need(['deny_request','release_request'].includes(phase),'phase');
 return withExecutionReadView(db,()=>{
  const selected=current(db,id,binding,runtime),old=db.prepare('SELECT 1 FROM command_preparation_retirement WHERE permit_id=?').pluck().get(id),
   previous=old?readCommandPreparationCleanup(db,id):null;
  if(previous?.steps[phase])return {saved:previous};
  need(phase==='deny_request'||previous?.steps.deny_ack,'deny_required');
  const value=previous?.value??retirement(selected,tick()),seq=db.prepare("SELECT sequence FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' ORDER BY sequence DESC LIMIT 1").pluck().get(binding.ipc_session_id),
   frame={ipc_version:deviceExecutionVersion,type:types[phase],message_id:crypto.randomUUID(),reply_to:null,ipc_session_id:binding.ipc_session_id,
    controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:String(BigInt(seq)+1n),device_id:value.binding.device_id,
    clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',body:requestBody(selected,value,phase)};
  assertDeviceExecutionFeatures(frame,features);return {id,phase,value,frame};
 });
}
export function commitCommandPreparationCleanup(db,{candidate,binding,runtime,tick}){
 const {id,phase,value,frame}=candidate,selected=withExecutionReadView(db,()=>current(db,id,binding,runtime));
 need(same(value,retirement(selected,BigInt(value.selected_tick_ns)))&&same(frame.body,requestBody(selected,value,phase)),'changed');
 if(!db.prepare('SELECT 1 FROM command_preparation_retirement WHERE permit_id=?').pluck().get(id))
  written(db.prepare('INSERT INTO command_preparation_retirement VALUES(?,?,?,?,?)').run(id,value.prepare_id,value.command_id,canonical(value),digest(value)));
 const saved=readCommandPreparationCleanup(db,id);need(same(saved.value,value)&&!saved.steps[phase]&&(phase==='deny_request'||saved.steps.deny_ack),'order');
 const item=preparedFrame(binding,frame,Buffer.from(JSON.stringify(frame)),'c2w',tick()),body={format:'command-preparation-cleanup/1',permit_id:id,phase,retirement_ref:saved.ref,
  write_attempt_id:null,record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest}};
 insertFrame(db,item,'command_dispatch');written(db.prepare('INSERT INTO command_preparation_cleanup VALUES(?,?,?,?,?,?,?)').run(id,phase,item.record.record_id,item.transaction,null,canonical(body),digest(body)));
 dispatchEffect(db,item,id,phase,body,tick());return readCommandPreparationCleanup(db,id);
}
export function currentCommandPreparationCleanup(db,{id,phase,binding,runtime}){
 return withExecutionReadView(db,()=>{current(db,id,binding,runtime);const saved=readCommandPreparationCleanup(db,id);need(saved.steps[phase],'request');return saved;});
}
export function acceptCommandPreparationCleanup(db,{binding,decoded,features,tick,receivedTick}){
 const {frame,payload}=decoded;assertDeviceExecutionFeatures(frame,features);const phase=Object.keys(types).find(p=>p.endsWith('_ack')&&types[p]===frame.type);need(phase,'ack_type');
 const requestPhase=phase==='deny_ack'?'deny_request':'release_request',id=db.prepare(`SELECT c.permit_id FROM command_preparation_cleanup c JOIN execution_frame_record f USING(record_id)
 WHERE c.phase=? AND f.ipc_session_id=? AND f.message_id=?`).pluck().get(requestPhase,binding.ipc_session_id,frame.reply_to);need(id,'ack_source');
 const saved=readCommandPreparationCleanup(db,id);if(saved.steps[phase]){need(saved.steps[phase].frame.wire.equals(executionWire(payload)),'replay_conflict');return saved;}
 const request=saved.steps[requestPhase].frame,attempt=row(db,'SELECT attempt_id,started_tick FROM execution_write_attempt WHERE record_id=?',request.record.record_id),at=frame.body[phase==='deny_ack'?'effective_tick_ns':'disposed_tick_ns'];
 for(const k of ['ipc_version','ipc_session_id','controller_boot_id','worker_boot_id','device_id','clock_domain_id','descriptor_digest'])need(frame[k]===request.frame[k],'binding');
 need(attempt&&BigInt(at)>=BigInt(attempt.started_tick)&&BigInt(at)<=receivedTick&&same(frame.body,expectedAck(request,phase,at)),'ack');
 const item=preparedFrame(binding,frame,payload,'w2c',receivedTick,request.record.record_id),body={format:'command-preparation-cleanup/1',permit_id:id,phase,retirement_ref:saved.ref,
  write_attempt_id:attempt.attempt_id,record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest}};
 insertFrame(db,item,'command_dispatch');written(db.prepare('INSERT INTO command_preparation_cleanup VALUES(?,?,?,?,?,?,?)').run(id,phase,item.record.record_id,item.transaction,attempt.attempt_id,canonical(body),digest(body)));
 dispatchEffect(db,item,id,phase,body,tick());return readCommandPreparationCleanup(db,id);
}
