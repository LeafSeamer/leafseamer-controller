import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {DeviceExecutionError} from './device-execution-channel.mjs';
import {readInitialOpenDispatch,currentInitialOpenDispatch} from './device-execution-open.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {deviceControlRepository} from './device-control-repository.mjs';
import {currentControlSource,readControlSource,controlSourceBody} from './device-control-source.mjs';
import {memoExecutionRead,withExecutionReadView} from './execution-read-view.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('initial_ready_'+code);};
const hash=v=>'sha256:'+crypto.createHash('sha256').update(canonicalize(v)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const seal=(v,field='digest')=>({...v,[field]:hash(v)});
const ref=(id,revision,digest)=>({id,revision,digest});
const sourceRef=v=>ref(v.change_id,v.revision,v.record_digest);
const gateRef=v=>ref(v.gate_id,v.revision,v.record_digest);
function decode(text,digest){const value=JSON.parse(text),{digest:actual,...body}=value;
 need(canonicalize(value)===text&&actual===digest&&hash(body)===digest,'integrity');return value;}
function source(db,reference,device){const value=readControlSource(db,device,reference.revision);need(same(value.ref,reference),'control');return value.value;}
function transition(before,after){
 const expected=controlSourceBody({...before,revision:String(BigInt(before.revision)+1n),pending_change:null,gate_state:'ready'},after.change_id,'ready',
  {ref:{clock_domain_id:before.clock_domain_id,descriptor_digest:before.descriptor_digest},tick:after.observed_tick_ns});
 need(before.gate_state==='protected'&&before.pending_operation_id===null&&before.mode==='manual'&&before.holder&&
  BigInt(after.observed_tick_ns)>=BigInt(before.observed_tick_ns)&&same(after,expected),'control_transition');
}
function body(id,dispatch,before,after,gateId,tick){
 const p=dispatch.plan,access=p.access;
 const {record_digest:_old,...gateBody}=p.gate;
 const afterGate=seal({...gateBody,gate_id:gateId,revision:String(BigInt(p.gate.revision)+1n),phase:'ready',
  activation_id:p.plan.basis.record_ref.id,confirmation_ref:dispatch.confirmation_ref},'record_digest');
 return seal({format:'initial-device-ready/1',id,revision:'1',binding:p.plan.binding,opening_ref:dispatch.value.opening_ref,
  dispatch_ref:dispatch.ref,confirmation_ref:dispatch.confirmation_ref,authorization_evidence_ref:p.authorization_evidence_ref,
  eligibility_refs:{control_authority:access.control_authority_ref,authorization:access.authorization_ref,
   resource_safety:access.resource_safety_ref,gate_safety:access.gate_safety_ref},
  control_before_ref:sourceRef(before),control_after_ref:sourceRef(after),gate_before_ref:gateRef(p.gate),gate_after:afterGate,
  selected_tick_ns:tick,expires_tick_ns:p.plan.expires_tick_ns});
}
function stored(db,id){need(db.inTransaction,'writer');const row=db.prepare('SELECT body_jcs,body_digest,opening_id,control_source_id,audit_jcs FROM device_initial_ready WHERE ready_id=?').raw().get(id);
 need(row,'missing');const value=decode(row[0],row[1]);need(value.id===id&&value.opening_ref.id===row[2]&&value.control_after_ref.id===row[3]&&
  row[4]===canonicalize({kind:'initial_device_ready',ready_ref:ref(id,'1',row[1])}),'integrity');return {value,ref:ref(id,'1',row[1])};}
// 保存control_source时提交尚未封口，验证精确后继，不把ready解释为新控制授权。
export function assertInitialReadyTransition(db,after){
 const row=db.prepare('SELECT ready_id FROM device_initial_ready WHERE control_source_id=?').pluck().get(after.change_id);need(row,'missing');
 const saved=stored(db,row),before=source(db,saved.value.control_before_ref,after.device_id);
 transition(before,after);need(same(saved.value.control_after_ref,sourceRef(after)),'control');
}
export function readInitialReady(db,id){return memoExecutionRead(db,'initial-ready',id,()=>readReady(db,id));}
function readReady(db,id){
 const saved=stored(db,id),v=saved.value,dispatch=readInitialOpenDispatch(db,v.opening_ref.id);
 need(dispatch?.confirmation&&dispatch.ack,'confirmation');
 const before=source(db,v.control_before_ref,v.binding.device_id),after=source(db,v.control_after_ref,v.binding.device_id);
 transition(before,after);need(same(dispatch.plan.plan.state_refs.control,v.control_before_ref)&&
  same(v,body(id,dispatch,before,after,v.gate_after.gate_id,v.selected_tick_ns))&&
  v.selected_tick_ns===after.observed_tick_ns&&BigInt(v.selected_tick_ns)>=dispatch.ack.observedTick&&
  BigInt(v.selected_tick_ns)<BigInt(v.expires_tick_ns),'integrity');
 const commit=db.prepare('SELECT kind,members,audit_jcs,notification_jcs FROM control_change_commit WHERE commit_id=?').raw().get(after.change_id);
 need(commit&&commit[0]==='ready'&&commit[1]===1&&commit[2]===canonicalize({kind:'ready',actor:null,acquisition_ref:null})&&
  commit[3]===canonicalize({kind:'ready',commit_id:after.change_id}),'commit');
 const write=db.prepare('SELECT result FROM execution_write_result WHERE attempt_id=?').pluck().get(dispatch.confirmation.write_attempt_id);
 need(write==='complete','write');return {...saved,dispatch,before,after};
}
// 只允许该精确Ready后继继承前态取证；保护、重连及任何控制变更都不匹配。
export function currentControlReference(db,control,reference){
 if(same(control.ref,reference))return true;
 if(Number(db.pragma('user_version',{simple:true}))<48||control.value.change_kind!=='ready')return false;
 const id=db.prepare('SELECT ready_id FROM device_initial_ready WHERE control_source_id=?').pluck().get(control.ref.id);if(!id)return false;
 // 这里仅证明人员取证的控制身份连续性，不签发Ready资格。
 // 实际Ready消费者仍通过readInitialReady核验完整OPEN/ACK链。
 const saved=stored(db,id),before=source(db,saved.value.control_before_ref,control.value.device_id);
 transition(before,control.value);return same(saved.value.control_after_ref,control.ref)&&same(saved.value.control_before_ref,reference);
}
export function currentInitialReady(db,{binding,runtime,id,provider,tick,preparedRef=null}){
 return withExecutionReadView(db,()=>{
 const saved=readInitialReady(db,id),v=saved.value;
 need(v.binding.ipc_session_id===binding.ipc_session_id&&provider?.currentReady,'binding');
 const control=currentControlSource(db,v.binding.device_id);need(same(control.current.ref,v.control_after_ref),'changed');
 const opening=provider.currentReady(v.opening_ref,v.dispatch_ref,saved.ref,preparedRef);
 const execution=currentDeviceExecutionBinding(db,runtime,v.binding.device_id,binding.ipc_session_id);
 need(same(opening.value,saved.dispatch.plan)&&same(execution.value.binding,v.binding),'changed');
 need(!preparedRef||same(opening.prepared_resource?.final_admission_ref,preparedRef),'prepared_resource');
 need(tick()<BigInt(v.expires_tick_ns),'expired');return {...saved,...(opening.prepared_resource?{prepared_resource:opening.prepared_resource}:{})};
 });
}
export function commitInitialReady(db,{binding,runtime,id,provider,tick,validatedDispatch=null}){
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=48,'writer');
 const old=db.prepare('SELECT ready_id FROM device_initial_ready WHERE opening_id=?').pluck().get(id);
 if(old)return currentInitialReady(db,{binding,runtime,id:old,provider,tick});
 // ACK采用者可在同一writer事务内传入刚完成当前来源核验的原件；没有跨事务缓存资格。
 const dispatch=validatedDispatch??currentInitialOpenDispatch(db,{binding,runtime,id,provider}),p=dispatch.plan;
 need(dispatch.value.opening_ref.id===id&&p.plan.binding.ipc_session_id===binding.ipc_session_id,'binding');
 need(dispatch.confirmation&&dispatch.ack,'confirmation');
 need(db.prepare('SELECT result FROM execution_write_result WHERE attempt_id=?').pluck().get(dispatch.confirmation.write_attempt_id)==='complete','write');
 const control=currentControlSource(db,p.plan.binding.device_id);need(same(control.current.ref,p.plan.state_refs.control),'changed');
 const now=String(tick()),domain={ref:{clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest},tick:now};
 const repository=deviceControlRepository(db,null,()=>domain);repository.capacity();
 const commit=crypto.randomUUID(),record=repository.current('record',p.plan.binding.device_id);
 const publicAfter=repository.touch('record',{...record,gate_state:'ready'},commit),after=controlSourceBody(publicAfter,commit,'ready',domain);
 transition(control.current.value,after);
 const value=body(crypto.randomUUID(),dispatch,control.current.value,after,crypto.randomUUID(),now),reference=ref(value.id,'1',value.digest);
 need(db.prepare('INSERT INTO device_initial_ready VALUES(?,?,?,?,?,?,?)').run(value.id,id,commit,Number(after.revision),canonicalize(value),value.digest,
  canonicalize({kind:'initial_device_ready',ready_ref:reference})).changes===1,'storage');
 repository.commit(commit,'ready',null,1,null);const saved=readInitialReady(db,value.id);
 need(tick()<BigInt(value.expires_tick_ns),'expired');return saved;
}
// 执行会话关闭时将仍指向本Ready的公开控制投影撤回；已发生其他控制变更时不覆盖新头。
export function protectInitialReadies(db,binding,tick){
 if(Number(db.pragma('user_version',{simple:true}))<48)return;
 const ids=db.prepare(`SELECT r.ready_id FROM device_initial_ready r JOIN control_record_head h ON h.revision=r.control_revision
  JOIN control_state_source s ON s.source_id=r.control_source_id AND s.device_id=h.device_id
  WHERE json_extract(r.body_jcs,'$.binding.ipc_session_id')=?`).pluck().all(binding.ipc_session_id);
 for(const id of ids){const saved=readInitialReady(db,id),v=saved.value,domain={ref:{clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest},tick:String(tick())};
  const repository=deviceControlRepository(db,null,()=>domain),commit=crypto.randomUUID();repository.capacity();
  repository.touch('record',{...repository.current('record',v.binding.device_id),gate_state:'protected'},commit);
  repository.commit(commit,'gate_protect',null,1,null);
 }
}
