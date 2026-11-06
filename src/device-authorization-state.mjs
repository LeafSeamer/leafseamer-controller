import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {checked,ref as objectRef,digest} from './auth-clock-value.mjs';
import {currentControlSource} from './device-control-source.mjs';
import {currentControlReference} from './device-initial-ready.mjs';
import {readDeviceRecoveryRequest} from './device-authorization-recovery.mjs';
import {memoExecutionRead} from './execution-read-view.mjs';
import {controlNeed as need,controlHash as hash,controlSeal as seal,controlSame as same} from './device-control-value.mjs';
const reference=v=>({id:v.state_id,revision:v.revision,digest:v.state_digest});
const sourceRef=v=>({id:v.change_id,revision:v.revision,digest:v.record_digest});
const identity=(scope,device,revision)=>'device_auth_'+hash({scope,device_id:device}).slice(7)+'_r'+revision;
const context=v=>({scope:v.scope,device_id:v.device_id,control_authority_ref:sourceRef(v),control_epoch:v.control_epoch,
 control_version:v.effective_version,mode:v.mode,holder:v.holder?{issuer_id:v.holder.issuer_id,issuer_epoch:v.holder.issuer_epoch,principal_id:v.holder.principal_id}:null,
 purpose:'ordinary',evaluator_lineage:null,evaluator_policy_ref:null,device_scope_ref:null,holder_lineage:null,cancel_scope_ref:null,cancel_lineage_ref:null});

// 恢复采用者的受信输入读取器；不保存新状态，也不创建恢复授权或发送资格。
export function currentManualAuthorizationContext(db,service,request,{manual,evaluator,coreSource}){
 const require=(value,code)=>{if(!value)throw new IdentityError('device_authorization_'+code);};
 require(db.inTransaction&&Number(service.schema_revision)>=39,'writer');
 require(request&&Object.keys(request).sort().join(',')==='device_id,evaluator_source_ref,manual_source_ref'&&
  typeof request.device_id==='string'&&request.manual_source_ref&&request.evaluator_source_ref,'input');
 const m=manual(request.manual_source_ref);if(m.denied)return m;
 const e=evaluator(request.evaluator_source_ref);if(e.denied)return e;
 const holder=m.value,serviceSource=e.value,device=request.device_id;
 require(holder.binding.device_id===device&&serviceSource.device_id===device,'device');
 const control=currentControlSource(db,device),state=currentDeviceAuthorization(db,device),c=context(control.authority.value);
 require(c.mode==='manual'&&c.holder&&same(holder.holder,c.holder)&&currentControlReference(db,control.current,holder.control_state_ref)&&
  same(holder.control_authority_ref,control.authority.ref)&&(Number(service.schema_revision)>=41||same(holder.authorization_state_ref,state.ref)),'control');
 const holderRuntime=coreSource.currentCoreSource(holder.core_runtime_source_ref).value,
  evaluatorRuntime=coreSource.currentCoreSource(serviceSource.core_runtime_source_ref).value;
 const session=db.prepare('SELECT service_boot_id,controller_boot_id,worker_boot_id FROM execution_session WHERE ipc_session_id=?').raw().get(holder.binding.ipc_session_id);
 require(same(holderRuntime.core,evaluatorRuntime.core)&&holderRuntime.service_boot_id===evaluatorRuntime.service_boot_id&&
  session&&session[0]===holderRuntime.service_boot_id&&session[1]===holder.binding.controller_boot_id&&session[2]===holder.binding.worker_boot_id&&
  holderRuntime.core.receipt.member_boot_id===holder.binding.controller_boot_id&&same(holderRuntime.domain_ref,evaluatorRuntime.domain_ref)&&
  same(serviceSource.domain_ref,holderRuntime.domain_ref),'runtime');
 const row=db.prepare('SELECT body_jcs,body_digest FROM device_evaluator_policy WHERE policy_id=?').raw().get(serviceSource.policy_ref.id);
 require(row,'scope');const policy=checked(JSON.parse(row[0]));
 require(canonicalize(policy)===row[0]&&policy.digest===row[1]&&same(objectRef(policy),serviceSource.policy_ref)&&
  policy.device_ids.includes(device)&&policy.service_id===service.service_id&&policy.database_instance_id===service.database_instance_id,'scope');
 const a=holder.authorization;
 c.evaluator_lineage={principal:{issuer_id:serviceSource.issuer_id,issuer_epoch:serviceSource.issuer_epoch,principal_id:serviceSource.principal_id},
  principal_kind:'service',credential_id:serviceSource.credential_ref.id,session_id:null,subject_revision:serviceSource.subject_ref.revision,
  session_revision:null,policy_revision:policy.revision,scope_digest:digest({scope:c.scope,device_ids:policy.device_ids})};
 c.evaluator_policy_ref=serviceSource.policy_ref;c.device_scope_ref=serviceSource.policy_ref;
 c.holder_lineage={principal:holder.holder,principal_kind:'human',credential_id:holder.credential_id,session_id:holder.session_id,
  subject_revision:String(a.subject_revision),session_revision:a.session_revision,policy_revision:a.policy_revision,scope_digest:a.scope_digest};
 const windows=[{role:'evaluator',evidence_ref:e.ref,not_before_tick_ns:serviceSource.selected_tick_ns,before_tick_ns:serviceSource.expires_tick_ns},
  {role:'holder',evidence_ref:m.ref,not_before_tick_ns:holder.selected_tick_ns,before_tick_ns:holder.expires_tick_ns}];
 const now=coreSource.domain();require(same(now.ref,holderRuntime.domain_ref),'runtime');
 const expires=windows.reduce((min,v)=>BigInt(v.before_tick_ns)<min?BigInt(v.before_tick_ns):min,BigInt(windows[0].before_tick_ns));
 require(windows.every(v=>BigInt(v.not_before_tick_ns)<=BigInt(now.tick))&&BigInt(now.tick)<expires,'expired');
 return {context:c,context_digest:digest(c),binding:holder.binding,state_ref:state.ref,
  source_refs:{holder:m.ref,evaluator:e.ref,holder_runtime:holder.core_runtime_source_ref,evaluator_runtime:serviceSource.core_runtime_source_ref},
  windows,selected_tick_ns:now.tick,expires_tick_ns:String(expires),
  authorization_dependencies:[serviceSource.authorization_dependencies,holder.authorization_dependencies]};
}
function decode(text,digest,field){const value=JSON.parse(text);need(canonicalize(value)===text&&same(seal(value,field),value)&&value[field]===digest,'authorization_state_integrity');return value;}
function original(db,id){
 return memoExecutionRead(db,'device-authorization-state',id,()=>readOriginal(db,id));
}
function readOriginal(db,id){
 const row=db.prepare(`SELECT s.device_id,s.revision,s.parent_id,s.control_source_id,s.body_jcs,s.body_digest,s.commit_id,
  c.parent_commit_id,c.body_jcs,c.body_digest,c.audit_jcs,c.protection_jcs,c.state_id,c.device_id,
  p.body_jcs,p.body_digest FROM device_authorization_state s
  JOIN device_authorization_commit c ON c.commit_id=s.commit_id JOIN control_state_source p ON p.source_id=s.control_source_id WHERE s.state_id=?`).raw().get(id);
 need(row,'authorization_state_missing');const value=decode(row[4],row[5],'state_digest'),control=decode(row[14],row[15],'record_digest'),receipt=decode(row[8],row[9],'receipt_digest');
 need(value.state_id===id&&id===identity(value.context.scope,row[0],value.revision)&&value.revision.padStart(20,'0')===row[1]&&
  (value.parent_ref?.id??null)===row[2]&&value.context.control_authority_ref.id===row[3]&&
  value.format_version==='device-authorization-state/0.1.0-draft.1'&&row[12]===id&&row[13]===row[0]&&
  receipt.commit_id===row[6]&&same(receipt.state_ref,reference(value))&&
  same(receipt.control_authority_ref,sourceRef(control))&&/^(0|[1-9][0-9]{0,19})$/.test(receipt.sampled_tick_ns)&&
  BigInt(receipt.sampled_tick_ns)>=BigInt(control.observed_tick_ns)&&receipt.clock_domain_id===control.clock_domain_id&&receipt.descriptor_digest===control.descriptor_digest,'authorization_state_integrity');
 let recovery=null;
 if(value.status==='protected'){
  need(same(value.context,context(control))&&value.recovery_ref===null&&value.reasons.length===1&&
   (row[2]?['control_changed','runtime_changed','credential_changed','evidence_expired','revoked','source_unavailable'].includes(value.reasons[0]):value.reasons[0]==='initial')&&
   receipt.format_version==='device-authorization-protection-commit/1'&&row[10]===canonicalize({kind:'device_authorization_protected',receipt})&&
   row[11]===canonicalize({kind:'device_authorization_protection_intent',device_id:row[0],state_ref:reference(value),control_authority_ref:sourceRef(control)}),'authorization_state_integrity');
 }else{
  need(value.status==='policy_selected'&&value.recovery_ref&&value.reasons.length===0,'authorization_state_integrity');
  const used=db.prepare('SELECT authorization_id,request_id,commit_id,body_jcs,body_digest FROM device_recovery_consumption WHERE state_id=?').raw().get(id);
  need(used,'authorization_consumption_missing');const consumption=checked(JSON.parse(used[3])),saved=readDeviceRecoveryRequest(db,used[1]),a=saved.authorization;
  const aRef={id:a.authorization_id,revision:a.revision,digest:a.authorization_digest};
  need(consumption.format==='device-authorization-recovery-consumption/1'&&consumption.id===a.authorization_id&&consumption.revision==='1'&&
   canonicalize(consumption)===used[3]&&consumption.digest===used[4]&&used[0]===a.authorization_id&&used[2]===row[6]&&
   same(value.recovery_ref,aRef)&&same(value.context,saved.receipt.selection.context)&&same(value.parent_ref,a.protected_state_ref)&&
   same(value.context.control_authority_ref,sourceRef(control))&&same(consumption.state_ref,reference(value))&&same(consumption.authorization_ref,aRef)&&
   same(consumption.request_receipt_ref,objectRef(saved.receipt))&&consumption.commit_id===row[6]&&consumption.selected_tick_ns===receipt.sampled_tick_ns&&
   same(consumption.binding,a.binding)&&consumption.binding.device_id===row[0]&&same(consumption.binding.scope,value.context.scope)&&
   consumption.binding.clock_domain_id===receipt.clock_domain_id&&consumption.binding.descriptor_digest===receipt.descriptor_digest&&
   BigInt(a.issued_tick_ns)<=BigInt(receipt.sampled_tick_ns)&&BigInt(receipt.sampled_tick_ns)<BigInt(a.expires_tick_ns)&&
   receipt.format_version==='device-authorization-selection-commit/1'&&same(receipt.recovery_ref,aRef)&&
   row[10]===canonicalize({kind:'device_authorization_policy_selected',receipt})&&
   row[11]===canonicalize({kind:'device_authorization_recovery_intent',device_id:row[0],state_ref:reference(value),recovery_ref:aRef}),'authorization_consumption_integrity');
  recovery={...saved,consumption};
 }
 if(row[2]){
  const parent=db.prepare('SELECT device_id,revision,body_jcs,body_digest,commit_id FROM device_authorization_state WHERE state_id=?').raw().get(row[2]);
  need(parent,'authorization_state_parent');const p=decode(parent[2],parent[3],'state_digest');
  need(parent[0]===row[0]&&BigInt(parent[1])+1n===BigInt(value.revision)&&same(reference(p),value.parent_ref)&&
   row[7]===parent[4]&&receipt.parent_commit_id===parent[4]&&same(receipt.previous_state_ref,reference(p)),'authorization_state_parent');
  if(recovery)need(p.status==='protected','authorization_state_parent');
 }else need(value.revision==='1'&&row[7]===null&&receipt.parent_commit_id===null&&receipt.previous_state_ref===null,'authorization_state_parent');
 return {value,ref:reference(value),commit_id:row[6],...(recovery?{recovery}:{})};
}
export function readDeviceAuthorizationState(db,reference){need(db.inTransaction,'authorization_state_writer');const result=original(db,reference.id);need(same(result.ref,reference),'authorization_state_reference');return result;}
export function currentDeviceAuthorization(db,device,{optional=false}={}){
 need(db.inTransaction,'authorization_state_writer');
 const row=db.prepare('SELECT state_id,commit_id FROM device_authorization_head WHERE device_id=?').raw().get(device);
 if(!row){need(optional,'authorization_state_missing');return null;}
 const result=original(db,row[0]);need(result.commit_id===row[1]&&result.value.context.device_id===device,'authorization_state_integrity');return result;
}
// 真实控制变更事务中的保护写集。来源不齐时显式留空，绝不生成policy_selected或发送资格。
export function protectControlAuthorization(db,control,observed={ref:{clock_domain_id:control.clock_domain_id,descriptor_digest:control.descriptor_digest},tick:control.observed_tick_ns},reason='control_changed'){
 need(db.inTransaction,'authorization_state_writer');
 need(observed.ref.clock_domain_id===control.clock_domain_id&&observed.ref.descriptor_digest===control.descriptor_digest&&
  /^(0|[1-9][0-9]{0,19})$/.test(observed.tick)&&BigInt(observed.tick)>=BigInt(control.observed_tick_ns),'authorization_state_clock');
 const old=currentDeviceAuthorization(db,control.device_id,{optional:true}),c=context(control);
 if(old&&same(old.value.context,c))return old;
 need(!old||BigInt(old.value.revision)<99999999999999999999n,'authorization_state_exhausted');
 need(db.prepare('SELECT count(*) FROM device_authorization_state').pluck().get()<16384,'authorization_state_capacity');
 const revision=String(old?BigInt(old.value.revision)+1n:1n),id=crypto.randomUUID();
 const value=seal({format_version:'device-authorization-state/0.1.0-draft.1',state_id:identity(c.scope,c.device_id,revision),revision,context:c,
  status:'protected',reasons:[old?reason:'initial'],parent_ref:old?.ref??null,recovery_ref:null},'state_digest');
 const stateRef=reference(value),receipt=seal({format_version:'device-authorization-protection-commit/1',commit_id:id,
  parent_commit_id:old?.commit_id??null,previous_state_ref:old?.ref??null,state_ref:stateRef,control_authority_ref:sourceRef(control),
  clock_domain_id:observed.ref.clock_domain_id,descriptor_digest:observed.ref.descriptor_digest,sampled_tick_ns:observed.tick},'receipt_digest');
 need(db.prepare('INSERT INTO device_authorization_state VALUES(?,?,?,?,?,?,?,?)').run(value.state_id,c.device_id,revision.padStart(20,'0'),old?.ref.id??null,
  control.change_id,canonicalize(value),value.state_digest,id).changes===1,'authorization_state_storage');
 need(db.prepare('INSERT INTO device_authorization_commit VALUES(?,?,?,?,?,?,?,?,?)').run(id,c.device_id,value.state_id,old?.commit_id??null,canonicalize(receipt),receipt.receipt_digest,
  canonicalize({kind:'device_authorization_protected',receipt}),crypto.randomUUID(),canonicalize({kind:'device_authorization_protection_intent',device_id:c.device_id,state_ref:stateRef,control_authority_ref:sourceRef(control)})).changes===1,'authorization_state_storage');
 const changed=old?db.prepare('UPDATE device_authorization_head SET state_id=?,commit_id=? WHERE device_id=? AND state_id=?').run(value.state_id,id,c.device_id,old.ref.id):
  db.prepare('INSERT INTO device_authorization_head VALUES(?,?,?)').run(c.device_id,value.state_id,id);
 need(changed.changes===1,'authorization_state_storage');const result=currentDeviceAuthorization(db,c.device_id);
 need(same(result.value,value),'authorization_state_readback');return result;
}

export function selectDeviceRecoveryAuthorization(db,saved,selected){
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=41,'authorization_selection_writer');
 const a=saved.authorization,old=currentDeviceAuthorization(db,a.binding.device_id),c=selected.context;
 need(old.value.status==='protected'&&same(old.ref,a.protected_state_ref)&&same(selected.state_ref,old.ref)&&
  same(c,saved.receipt.selection.context)&&hash(c)===a.proposed_context_digest&&same(selected.binding,a.binding)&&
  BigInt(a.issued_tick_ns)<=BigInt(selected.selected_tick_ns)&&BigInt(selected.selected_tick_ns)<BigInt(a.expires_tick_ns),'authorization_selection_binding');
 need(BigInt(old.value.revision)<99999999999999999999n&&db.prepare('SELECT count(*) FROM device_authorization_state').pluck().get()<16384,'authorization_state_capacity');
 const revision=String(BigInt(old.value.revision)+1n),id=crypto.randomUUID(),recoveryRef={id:a.authorization_id,revision:a.revision,digest:a.authorization_digest};
 const value=seal({format_version:'device-authorization-state/0.1.0-draft.1',state_id:identity(c.scope,c.device_id,revision),revision,context:c,
  status:'policy_selected',reasons:[],parent_ref:old.ref,recovery_ref:recoveryRef},'state_digest'),stateRef=reference(value);
 const receipt=seal({format_version:'device-authorization-selection-commit/1',commit_id:id,parent_commit_id:old.commit_id,previous_state_ref:old.ref,state_ref:stateRef,
  control_authority_ref:c.control_authority_ref,recovery_ref:recoveryRef,clock_domain_id:a.binding.clock_domain_id,descriptor_digest:a.binding.descriptor_digest,sampled_tick_ns:selected.selected_tick_ns},'receipt_digest');
 const consumptionBody={format:'device-authorization-recovery-consumption/1',id:a.authorization_id,revision:'1',authorization_ref:recoveryRef,request_receipt_ref:objectRef(saved.receipt),state_ref:stateRef,
  commit_id:id,binding:a.binding,selected_tick_ns:selected.selected_tick_ns},consumption={...consumptionBody,digest:hash(consumptionBody)};
 need(db.prepare('INSERT INTO device_recovery_consumption VALUES(?,?,?,?,?,?)').run(a.authorization_id,saved.receipt.id,value.state_id,id,canonicalize(consumption),consumption.digest).changes===1,'authorization_selection_storage');
 need(db.prepare('INSERT INTO device_authorization_state VALUES(?,?,?,?,?,?,?,?)').run(value.state_id,c.device_id,revision.padStart(20,'0'),old.ref.id,
  c.control_authority_ref.id,canonicalize(value),value.state_digest,id).changes===1,'authorization_selection_storage');
 need(db.prepare('INSERT INTO device_authorization_commit VALUES(?,?,?,?,?,?,?,?,?)').run(id,c.device_id,value.state_id,old.commit_id,canonicalize(receipt),receipt.receipt_digest,
  canonicalize({kind:'device_authorization_policy_selected',receipt}),crypto.randomUUID(),canonicalize({kind:'device_authorization_recovery_intent',device_id:c.device_id,state_ref:stateRef,recovery_ref:recoveryRef})).changes===1,'authorization_selection_storage');
 need(db.prepare('UPDATE device_authorization_head SET state_id=?,commit_id=? WHERE device_id=? AND state_id=? AND commit_id=?').run(value.state_id,id,c.device_id,old.ref.id,old.commit_id).changes===1,'authorization_selection_storage');
 const result=currentDeviceAuthorization(db,c.device_id);need(same(result.value,value)&&same(result.recovery.consumption,consumption),'authorization_selection_readback');return result;
}
