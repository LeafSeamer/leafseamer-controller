import {dispatchRiskFrame} from './command-dispatch.mjs';
import {guardOnlyFrame} from './command-guard.mjs';
import {encodingOnlyFrame} from './command-encoding-store.mjs';
import {retiredCommandHistory,readRetiredPreparation} from './command-retired-history.mjs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {seal,ref,digest,same,checked} from './auth-clock-value.mjs';
import {currentControlSource} from './device-control-source.mjs';
import {readInitialFence} from './device-execution-control.mjs';
import {captureInitialDenials,readInitialDenials} from './device-initial-denials.mjs';
import {readInitialOpenDispatch} from './device-execution-open.mjs';
import {readInitialReady} from './device-initial-ready.mjs';
import {memoExecutionRead,withExecutionReadView} from './execution-read-view.mjs';
import {pendingInitialCommands,readCommandRecord} from './command-record-store.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('initial_resource_'+code);};
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const objectRef=(id,v)=>({id,revision:'1',digest:digest(v)});
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(v);
function decode(text,hash){const v=checked(JSON.parse(text));need(canonicalize(v)===text&&v.digest===hash,'integrity');return v;}

// 初始来源原件保持空库存；精确T2后继另返回非空资源当前资格，不能替代hold释放或恢复。
// 全部输入取自同一writer内的实际运行、已批准固定模块、原始采样、屏障与命令/出站账本。
export function deviceInitialResource({db,service,writer,evidenceCurrent,executionCurrent,domain,attachCurrent,attachRead}){
 function sources(device,ownOpen=null,ready=null,preparedRef=null){
  need(db.inTransaction,'writer');const authorization=evidenceCurrent(device),execution=executionCurrent(device),b=execution.value.binding;
  need(same(b,authorization.value.requirement.binding),'binding');
  const q=execution.catalog.qualification,p=execution.value.transport_profile,sample=execution.baseline;
  need(q.qualification==='fixed_memory_control_catalog/1'&&p.format==='leafseamer-memory-transport/1'&&p.transport==='memory'&&
   p.automatic_resends===false&&p.max_in_flight===1&&same(p.external_resources,[])&&p.module_digest===q.module_digest&&
   p.policy_digest===q.protocol_io_policy_digest,'qualification');
  const history=Number(service.schema_revision)>=57?retiredCommandHistory(db,b):null,last=history?.latest;
  need(sample.device_id===device&&sample.device_session_id===b.device_session_id&&
   (last?sample.value.write_sequence===last.observation.write_sequence&&sample.value.value===last.observation.value&&
    BigInt(sample.captured_tick_ns)>=last.steps.release_ack.frame.committedTick:sample.value.write_sequence==='0'&&sample.value.value===0),'observed_write');
  const control=currentControlSource(db,device);
  const controlRef=ready?ready.value.control_before_ref:control.current.ref;
  need(control.current.value.pending_operation_id===null&&
   (ready?control.current.value.gate_state==='ready'&&same(control.current.ref,ready.value.control_after_ref):control.current.value.gate_state==='protected')&&
   same(controlRef,authorization.value.requirement.control_state_ref)&&same(control.authority.ref,authorization.value.requirement.control_authority_ref),'control');
  const fenceId=db.prepare('SELECT fence_id FROM execution_initial_fence WHERE binding_id=?').pluck().get(execution.ref.id);
  const fence=fenceId&&readInitialFence(db,fenceId);need(fence?.confirmation&&same(fence.value.binding_ref,execution.ref)&&
   (last?same(last.source.closure.value.control_ref,controlRef):same(fence.value.control_source_ref,controlRef))&&fence.ack.frame.body.issued_cut_revision==='0'&&
   fence.ack.frame.body.coverage.length===0&&fence.ack.frame.body.transmission_coverage.length===0&&
   fence.ack.frame.body.cancel_coverage.length===0,'fence');
  // 同Ready下的排队claim不产生attempt或hold；schema51编码帧另须精确持久准备账本。
  // 编码只占独立缓存预留，派发或其他历史仍拒绝；此路径不证明非空hold释放。
  const admissions=[49,50,51,52,53,54,55,56,57].includes(Number(service.schema_revision))?pendingInitialCommands(db,ready,preparedRef,history?.commandIds):[];
  if(![49,50,51,52,53,54,55,56,57].includes(Number(service.schema_revision)))need(!db.prepare('SELECT 1 FROM ca_command_initial c JOIN ca_request_key k USING(key_id) WHERE k.device_id=? LIMIT 1').pluck().get(device),'command_history');
  let sent=db.prepare(`SELECT record_id,record_digest,message_type,sequence FROM execution_frame_record
   WHERE ipc_session_id=? AND direction='c2w' AND (device_id=? OR device_id IS NULL) ORDER BY sequence`).raw().all(b.ipc_session_id,device).filter(v=>v[0]!==ownOpen?.id);
  sent=sent.filter(v=>{const old=history?.outgoing.get(v[0]);if(!old)return true;need(old.digest===v[1],'retired_frame');return false;});
  const encoding=sent.filter(v=>v[2]==='ENCODE_PACKET').map(v=>{need(ready,'encoding_ready');return encodingOnlyFrame(db,v[0],b,ready.ref);});
  const guards=sent.filter(v=>v[2]==='GUARD_INSTALL').map(v=>guardOnlyFrame(db,v[0],b,preparedRef));
  const dispatches=sent.filter(v=>v[2]==='DISPATCH').map(v=>dispatchRiskFrame(db,v[0],b,preparedRef));
  sent=sent.filter(v=>!['ENCODE_PACKET','GUARD_INSTALL','DISPATCH'].includes(v[2]));
  need(sent.length>0&&sent.every(v=>v[2]==='HELLO_ACK'||v[2]==='FENCE'),'execution_history');
  const now=domain();need(now.ref.clock_domain_id===b.clock_domain_id&&now.ref.descriptor_digest===b.descriptor_digest&&
   same(sample.clock_domain_descriptor.clock_domain_id,b.clock_domain_id)&&sample.clock_domain_descriptor.descriptor_digest===b.descriptor_digest&&
   BigInt(sample.captured_tick_ns)<=BigInt(now.tick),'clock');
  return {authorization,execution,control,fence,now,admissions,encoding,guards,dispatches,history,denials:captureInitialDenials(db,service,device,ownOpen,ready,preparedRef,history),inventory:{binding_ref:execution.ref,authorization_evidence_ref:authorization.ref,
   authorization_state_ref:authorization.value.state_ref,control_state_ref:controlRef,control_authority_ref:control.authority.ref,
   catalog_ref:execution.value.catalog_approval_ref,baseline_ref:objectRef(sample.sample_id,sample),
   initial_fence_ref:fence.ref,initial_confirmation_ref:fence.confirmation_ref,
   command_ids:admissions.map(v=>v.id),outgoing_records:sent.map(v=>({record_ref:{id:v[0],revision:'1',digest:v[1]},type:v[2],sequence:String(BigInt(v[3]))})),
   module_digest:q.module_digest,protocol_io_policy_digest:q.protocol_io_policy_digest,transport_profile_ref:execution.value.transport_profile_ref,
   observed_write_sequence:sample.value.write_sequence,external_resources:[],
   ...(last?{retired_preparation_refs:history.refs,closing_ref:last.source.closure.ref,closing_ack_ref:last.source.closure.ack.ref}: {})}};
 }
 function read(reference){return withExecutionReadView(db,()=>memoExecutionRead(db,'initial-resource',reference,()=>readOriginal(reference)));}
 function readOriginal(reference){
  need(db.inTransaction,'writer');const row=db.prepare(`SELECT r.body_jcs,r.body_digest,r.request_id,r.request_digest,r.request_jcs,
   r.binding_id,r.evidence_id,r.fence_id,r.sample_id,r.commit_id,c.body_jcs,c.body_digest,c.audit_jcs
   FROM device_initial_resource r JOIN device_initial_resource_commit c USING(commit_id) WHERE r.source_id=?`).raw().get(reference?.id);
  need(row,'missing');const value=decode(row[0],row[1]),commit=decode(row[10],row[11]),request=JSON.parse(row[4]);
  const successor=value.format==='leafseamer-device-resource-successor/1';
  need((successor||['leafseamer-initial-resource-source/1','leafseamer-initial-resource-source/2'].includes(value.format))&&value.provider===(successor?'fixed_memory_control_successor/1':'fixed_memory_control_initial/1')&&
   commit.format==='initial-device-resource-commit/1'&&same(ref(value),reference)&&request.request_id===row[2]&&request.device_id===value.binding.device_id&&
   same(request.expected_evidence_ref,value.inventory.authorization_evidence_ref)&&
   canonicalize(request)===row[4]&&digest(request)===row[3]&&same(commit.request,request)&&same(commit.source_ref,reference)&&commit.id===row[9]&&
   value.inventory.binding_ref.id===row[5]&&value.inventory.authorization_evidence_ref.id===row[6]&&value.inventory.initial_fence_ref.id===row[7]&&
   value.inventory.baseline_ref.id===row[8]&&row[12]===canonicalize({kind:'initial_device_resource_selected',source_ref:reference,commit_ref:ref(commit)}),'integrity');
  const i=value.inventory,original=(table,column,reference)=>{
   const row=db.prepare(`SELECT body_jcs,body_digest FROM ${table} WHERE ${column}=?`).raw().get(reference.id);need(row,'source_missing');
   const v=JSON.parse(row[0]);need(reference.revision==='1'&&reference.digest===row[1]&&canonicalize(v)===row[0]&&digest(v)===row[1],'source_integrity');return v;
  };
  const binding=original('device_execution_binding','binding_id',i.binding_ref),sample=original('device_baseline_sample','sample_id',i.baseline_ref);
  const authorizationRow=db.prepare('SELECT body_jcs,body_digest FROM device_authorization_evidence WHERE evidence_id=?').raw().get(i.authorization_evidence_ref.id);
  need(authorizationRow,'source_missing');const authorization=JSON.parse(authorizationRow[0]),{evidence_digest,...unsigned}=authorization;
  need(canonicalize(authorization)===authorizationRow[0]&&digest(unsigned)===evidence_digest&&evidence_digest===authorizationRow[1]&&
   same(i.authorization_evidence_ref,{id:authorization.evidence_id,revision:authorization.revision,digest:evidence_digest})&&
   same(authorization.requirement.binding,value.binding)&&same(authorization.state_ref,i.authorization_state_ref)&&
   same(authorization.requirement.control_state_ref,i.control_state_ref)&&same(authorization.requirement.control_authority_ref,i.control_authority_ref)&&
   value.expires_tick_ns===authorization.requirement.expires_tick_ns&&BigInt(authorization.requirement.selected_tick_ns)<=BigInt(value.selected_tick_ns)&&
   BigInt(value.selected_tick_ns)<BigInt(value.expires_tick_ns),'source_binding');
  const fence=readInitialFence(db,i.initial_fence_ref.id);
  const retired=successor?i.retired_preparation_refs.map(reference=>readRetiredPreparation(db,reference)):[],last=retired.at(-1);
  if(successor)need(last&&retired.every(v=>same(v.value.binding,value.binding))&&same(i.closing_ref,last.source.closure.ref)&&
   same(i.closing_ack_ref,last.source.closure.ack.ref)&&same(i.control_state_ref,last.source.closure.value.control_ref)&&
   sample.value.write_sequence===last.observation.write_sequence&&sample.value.value===last.observation.value&&
   BigInt(sample.captured_tick_ns)>=last.steps.release_ack.frame.committedTick,'retired_source');
  need(same(value.binding,binding.binding)&&same(i.catalog_ref,binding.catalog_approval_ref)&&same(sample.catalog_approval_ref.digest,i.catalog_ref.digest)&&
   sample.device_session_id===value.binding.device_session_id&&(successor||sample.value.write_sequence==='0'&&sample.value.value===0)&&
   same(fence?.ref,i.initial_fence_ref)&&same(fence.confirmation_ref,i.initial_confirmation_ref)&&same(fence.value.binding_ref,i.binding_ref)&&
   same(i.command_ids,[])&&same(i.external_resources,[])&&i.observed_write_sequence===sample.value.write_sequence,'source_binding');
  for(const sent of i.outgoing_records){
   const row=db.prepare('SELECT record_digest,message_type,sequence,ipc_session_id,direction FROM execution_frame_record WHERE record_id=?').raw().get(sent.record_ref.id);
   need(row&&row[0]===sent.record_ref.digest&&sent.record_ref.revision==='1'&&row[1]===sent.type&&String(BigInt(row[2]))===sent.sequence&&
    row[3]===value.binding.ipc_session_id&&row[4]==='c2w'&&['HELLO_ACK','FENCE'].includes(sent.type),'source_binding');
  }
  if(successor||value.format==='leafseamer-initial-resource-source/2')readInitialDenials(db,service,value.binding.device_id,value.deny_snapshots);
  return {ref:reference,value,commit};
 }
 function currentInside(reference,dispatchRef=null,readyRef=null,preparedRef=null){
  const saved=read(reference);let ownOpen=null,ready=null;
  // 基线头变化即永久淘汰这份初始快照；先拒绝已知变化，不必遍历短期授权链。
  // 相等只通过此项检查，后续仍核验完整当前来源与授权。
  const latest=db.prepare('SELECT sample_id,body_digest FROM device_baseline_sample WHERE approval_id=? ORDER BY length(sample_sequence) DESC,sample_sequence DESC LIMIT 1')
   .raw().get(saved.value.inventory.catalog_ref.id);
  need(latest&&latest[0]===saved.value.inventory.baseline_ref.id&&latest[1]===saved.value.inventory.baseline_ref.digest,'changed');
  if(dispatchRef){
   need(Number(service.schema_revision)>=47&&typeof dispatchRef.id==='string'&&dispatchRef.id.endsWith('.dispatch'),'dispatch');
   const dispatch=readInitialOpenDispatch(db,dispatchRef.id.slice(0,-9));
   need(dispatch&&same(dispatch.ref,dispatchRef)&&same(dispatch.plan.resource_source_ref,reference)&&
    same(dispatch.plan.plan.binding,saved.value.binding),'dispatch');
   ownOpen=dispatch.value.request_record_ref;
   if(readyRef){ready=readInitialReady(db,readyRef.id);need(same(ready.ref,readyRef)&&same(ready.value.dispatch_ref,dispatchRef)&&
    same(ready.value.binding,saved.value.binding),'ready');}
  }
  need(!readyRef||ready,'ready');
  let successor=null;
  if(preparedRef){
   need(ready&&[52,53,54,55,56,57].includes(Number(service.schema_revision)),'prepared_version');
   const held=db.prepare(`SELECT command_id,transaction_id FROM command_device_hold h WHERE device_id=?
    ${Number(service.schema_revision)>=57?'AND NOT EXISTS(SELECT 1 FROM command_hold_release r WHERE r.hold_id=h.hold_id)':''}`).raw().all(saved.value.binding.device_id);
   need(held.length===1&&held[0][1]===preparedRef.id,'prepared_hold');
   const command=readCommandRecord(db,held[0][0]),final=command.lifecycle?.final_admission;
   need(final&&same(final.ref,preparedRef)&&same(command.source.ready_ref,readyRef)&&same(command.source.binding,saved.value.binding)&&
    (command.record.state.phase==='queued'||command.lifecycle.dispatch&&['dispatching','awaiting_evidence'].includes(command.record.state.phase))&&command.record.state.resource_status==='held'&&command.record.attempts.length===1,'prepared_source');
   const after=final.value.resource_after;
   need(same(after.provider_source_ref,reference)&&same(after.binding,saved.value.binding)&&same(after.control_state_ref,ready.value.control_after_ref)&&
    after.holds.length===1&&after.holds[0].hold_ref.id===final.value.hold.hold_id&&after.holds[0].classification==='active','prepared_resource');
   successor={final_admission_ref:final.ref,resource:after};
  }
  const actual=sources(saved.value.binding.device_id,ownOpen,ready,preparedRef),now=BigInt(actual.now.tick);
  // 不改写旧空库存原件。当前资格明确附带所有排队受理Ref，且逐项核验其同Ready来源。
  const inventory={...actual.inventory,command_ids:[]},denials=['initial-manual-deny-snapshots/2','initial-manual-deny-snapshots/3'].includes(actual.denials.format)?
   {...actual.denials,accepted_command_count:0,pending_admission_refs:[]}:actual.denials;
  need(same(saved.value.binding,actual.execution.value.binding)&&same(saved.value.inventory,inventory),'changed');
  need(['leafseamer-initial-resource-source/2','leafseamer-device-resource-successor/1'].includes(saved.value.format)&&same(saved.value.deny_snapshots,denials),'deny_snapshots_changed');
  need(BigInt(saved.value.selected_tick_ns)<=now&&now<BigInt(saved.value.expires_tick_ns),'expired');return {...saved,pending_admission_refs:actual.admissions,
   ...(actual.encoding.length?{encoding_preparation_refs:actual.encoding}:{}),...(actual.guards.length?{guard_installation_refs:actual.guards}:{}),...(actual.dispatches.length?{active_dispatch_refs:actual.dispatches}:{}),...(successor?{prepared_resource:successor}:{})};
 }
 attachCurrent?.(currentInside);attachRead?.(read);
 return Object.freeze({
  select(request){need(request&&Object.keys(request).sort().join(',')==='device_id,expected_evidence_ref,request_id'&&uuid(request.request_id),'input');
   const fixed=structuredClone(request);return freeze(writer(()=>{
    const old=db.prepare('SELECT source_id,body_digest,request_digest FROM device_initial_resource WHERE request_id=?').raw().get(fixed.request_id);
    if(old){need(old[2]===digest(fixed),'conflict');return read({id:old[0],revision:'1',digest:old[1]});}
    const actual=withExecutionReadView(db,()=>sources(fixed.device_id));need(same(actual.authorization.ref,fixed.expected_evidence_ref),'authorization_changed');
    need(db.prepare('SELECT count(*) FROM device_initial_resource').pluck().get()<16384,'capacity');
    const successor=Boolean(actual.history?.latest);
    const value=seal({format:successor?'leafseamer-device-resource-successor/1':'leafseamer-initial-resource-source/2',id:crypto.randomUUID(),revision:'1',binding:actual.execution.value.binding,
     provider:successor?'fixed_memory_control_successor/1':'fixed_memory_control_initial/1',inventory:actual.inventory,deny_snapshots:actual.denials,selected_tick_ns:actual.now.tick,
     expires_tick_ns:actual.authorization.value.requirement.expires_tick_ns});
    const commit=seal({format:'initial-device-resource-commit/1',id:crypto.randomUUID(),revision:'1',source_ref:ref(value),request:fixed});
    const audit=canonicalize({kind:'initial_device_resource_selected',source_ref:ref(value),commit_ref:ref(commit)}),written=v=>need(v.changes===1,'storage');
    written(db.prepare('INSERT INTO device_initial_resource VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(value.id,fixed.request_id,digest(fixed),canonicalize(fixed),
     value.inventory.binding_ref.id,value.inventory.authorization_evidence_ref.id,value.inventory.initial_fence_ref.id,value.inventory.baseline_ref.id,
     value.binding.device_id,canonicalize(value),value.digest,commit.id));
    written(db.prepare('INSERT INTO device_initial_resource_commit VALUES(?,?,?,?,?,?)').run(commit.id,value.id,canonicalize(commit),commit.digest,audit,audit));
    const saved=read(ref(value));need(same(saved.value,value)&&same(saved.commit,commit),'readback');
    need(BigInt(domain().tick)<BigInt(value.expires_tick_ns),'expired');return saved;
   }));
  },
  current(reference){return freeze(writer(()=>currentInside(reference)));},
  lookup(reference){return freeze(writer(()=>read(reference)));}
 });
}
