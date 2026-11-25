import {IdentityError} from './identity-crypto.mjs';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {readCommandRecord,commandPolicyInput,automationActionPolicy} from './command-record-store.mjs';
import {selectAuthenticationWindow,currentAuthenticationWindow} from './authentication-window.mjs';
import {deviceExecutionCapabilities} from './sdk/device-execution.mjs';
import {readInitialReady} from './device-initial-ready.mjs';
const need=(value,code)=>{if(!value)throw new IdentityError('command_encoding_'+code);};
const reference=(id,value)=>({id,revision:'1',digest:digest(value)});

export function automationCommandExecutionSource({db,service,devices,executionCurrent,deviceAutomationCurrent,coreSource,time,queueCommand}){
 const active=new Map();
 function current(verified,preparedRef=null){
  const {target,grant_ref,action_binding_ref,not_before_ns,eligible_before_ns}=verified;
  need(db.inTransaction&&verified.principal.principal_kind==='service'&&grant_ref.kind==='grant'&&
   verified.arm_generation!=='0'&&action_binding_ref&&typeof action_binding_ref.id==='string'&&
   action_binding_ref.revision==='1'&&/^sha256:[0-9a-f]{64}$/.test(action_binding_ref.digest),'automation_origin');
  const control=devices.control(target.device_id);
  need(control.mode==='automatic'&&control.holder===null&&control.pending_change===null&&control.gate_state==='ready','automation_control');
  let execution,registered;
  try{
   execution=executionCurrent(target.device_id,{requireReady:true,...(preparedRef&&{preparedRef})});
   registered=deviceAutomationCurrent(target.device_id);
  }
  catch(error){
   if(!['DeviceExecutionError','WorkerLaunchError'].includes(error?.name))throw error;
   throw Object.assign(new IdentityError('command_encoding_automation_ready'),{cause:error});
  }
  const {ready,ref,value,negotiation}=execution;
  need(ready&&ready.value.gate_after.phase==='ready'&&same(ready.value.binding,value.binding)&&
   deviceExecutionCapabilities.automation.every(feature=>negotiation?.selected_features.includes(feature)),'automation_ready');
  const schedule=verified.schedule_binding;
  if(schedule)need(readInitialReady(db,ready.ref.id).dispatch.plan.resource.reference_time_snapshot&&
   deviceExecutionCapabilities.reference.every(feature=>negotiation?.selected_features.includes(feature)),'automation_reference');
  const action=registered.bindings.find(item=>item.kind==='action'&&same(item.content_ref,action_binding_ref));
  need(registered.registration.device_session_id===value.binding.device_session_id&&action?.value.device_id===target.device_id&&
   action.value.capability_id===target.action_id&&registered.registration.capability_version===target.capability_version&&
   same(action.value.parameter_schema_ref,verified.parameter_schema_ref),'automation_registration');
  const now=coreSource.domain();
  need(same(now.ref,{clock_domain_id:value.binding.clock_domain_id,descriptor_digest:value.binding.descriptor_digest})&&
   BigInt(now.tick)>=BigInt(ready.value.selected_tick_ns)&&BigInt(now.tick)<BigInt(ready.value.expires_tick_ns),'automation_clock');
  const basis={binding_ref:ref,binding:value.binding,ready_ref:ready.ref,
   control_binding:{epoch:control.control_epoch,version:control.effective_version},
   control_authority_ref:ready.value.eligibility_refs.control_authority,authorization_ref:ready.value.eligibility_refs.authorization,
   origin:{execution_ref:verified.execution_ref,step_id:verified.step_id,parameters_ref:verified.parameters_ref,
    action_binding_ref,registration_ref:registered.registration_ref,grant_ref,
    run_id:verified.run_id,arm_generation:verified.arm_generation,definition_version:verified.definition_version},
   action_policy:automationActionPolicy(verified,execution),...(schedule&&{schedule_binding:schedule})};
  return {basis,execution,now,readyExpires:ready.value.expires_tick_ns,validFrom:not_before_ns,validBefore:eligible_before_ns};
 }
 function input(value,core,acquisition,selectedTick,capTick){
  return {db,service,coreRuntime:core,domain:value.now.ref,acquisitionRef:acquisition,selectedTick,capTick,
   validFrom:value.validFrom,validBefore:value.validBefore};
 }
 return Object.freeze({activate(id,verify){
  active.set(id,verify);
  setTimeout(()=>active.delete(id),5000).unref();
  queueCommand(id);
 },current(id,preparedRef=null){
  const verify=active.get(id);need(verify,'automation_observation');return verify(preparedRef);
 },select(verified,pairingRef){
  const value=current(verified),core=coreSource.selectCoreSource(),{acquisition}=time();
  const cap=BigInt(value.readyExpires)<BigInt(core.value.expires_tick_ns)?value.readyExpires:core.value.expires_tick_ns;
  const window=selectAuthenticationWindow(input(value,core,acquisition,value.now.tick,cap));
  const original={format:'automation-command-execution-basis/1',...value.basis,pairing_ref:pairingRef,
   core_source_ref:core.ref,authentication_window:window};
  function currentExecution(latest,preparedRef=null){
   const selected=current(latest,preparedRef);
   need(same(verified,latest),'automation_changed');
   need(same(selected.basis,value.basis)&&selected.readyExpires===value.readyExpires,'automation_changed');
   const core=coreSource.currentCoreSource(original.core_source_ref);
   currentAuthenticationWindow(input(selected,core,window.acquisition_ref,window.selected_tick_ns,window.cap_tick_ns),window,selected.now.tick);
   return selected.execution;
  }
  return Object.freeze({original,execution:value.execution,currentExecution,assertCurrentInTransaction(latest){currentExecution(latest);return original;}});
 }});
}

// 仅核心装配持有此提供者。命令ID定位同库已受理来源，不能从HTTP提交身份快照或授权正文。
export function commandEncodingSource({db,service,currentRecordedToken,devices,executionCurrent,coreSource,automationExecution=null,clockReference=null}){
 function automated(command,preparedRef){
  need(automationExecution,'automation_observation');
  const s=command.source,execution=automationExecution.current(s.command_id,preparedRef),actor=s.metadata.actor,now=coreSource.domain();
  need(same(execution.ref,s.binding_ref)&&same(execution.ready.ref,s.ready_ref),'automation_changed');
  need(same(now.ref,s.deadline.accepted.domain)&&BigInt(now.tick)<BigInt(s.deadline.queue_deadline_tick_ns),'deadline');
  const identity={token_id:null,actor:{issuer_id:actor.issuer_id,issuer_epoch:actor.issuer_epoch,principal_id:actor.principal_id},
   authorization_digest:s.authorization_digest,binding_ref:s.binding_ref,ready_ref:s.ready_ref};
  const snapshot={format:'command-encoding-identity/1',command_id:s.command_id,identity,authentication_window:s.authentication_window};
  return {command,request:s.execution_request,execution,identity,now,snapshot,snapshot_ref:reference(s.command_id+'.encoding-identity',snapshot),
   expires_tick_ns:s.deadline.queue_deadline_tick_ns};
 }
 function collect(id,preparedRef=null){
  need(db.inTransaction,'writer');const command=readCommandRecord(db,id),s=command.source,m=s.metadata;
  need((command.record.state.phase==='queued'||preparedRef&&command.lifecycle?.dispatch&&['dispatching','awaiting_evidence'].includes(command.record.state.phase))&&(preparedRef?command.record.attempts.length===1&&command.record.state.resource_status==='held'&&same(command.lifecycle?.final_admission?.ref,preparedRef):command.record.attempts.length===0),'state');
  if(m.origin==='automation')return automated(command,preparedRef);
  const proof=currentRecordedToken(s.token_id,service.service_id);
  need(!proof.denied&&proof.principal_kind==='human'&&proof.permissions.includes('device.command'),'permission');
  const actor={issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch,principal_id:proof.principal_id};
  need(same(actor,{issuer_id:m.actor.issuer_id,issuer_epoch:m.actor.issuer_epoch,principal_id:m.actor.principal_id})&&
   proof.session_id===m.actor.session_id&&proof.policy_revision===m.actor.authorization_revision&&
   proof.authorization_digest===s.authorization_digest&&proof.scope_digest===s.scope_digest,'identity');
  const control=devices.control(s.binding.device_id);
  need(control.mode==='manual'&&control.gate_state==='ready'&&control.pending_change===null&&same(control.holder,actor)&&
   same(m.control_binding,{epoch:control.control_epoch,version:control.effective_version}),'control');
  const execution=executionCurrent(s.binding.device_id,{requireReady:true,preparedRef});
  need(same(execution.ref,s.binding_ref)&&same(execution.value.binding,s.binding)&&same(execution.ready.ref,s.ready_ref),'binding');
  const row=db.prepare('SELECT k.content_body,k.request_digest FROM ca_request_key k JOIN command_admission_source s USING(key_id) WHERE s.command_id=?').raw().get(id);
  need(row,'request');const content=JSON.parse(row[0].toString());
  need(canonical(content)===row[0].toString()&&digest(content)===row[1]&&row[1]===m.request_identity.request_digest,'request');
  const request={context_id:s.context_id,idempotency_key:m.request_identity.key.idempotency_key,...content};
  commandPolicyInput(request,execution);
  const now=coreSource.domain();need(same(now.ref,s.deadline.accepted.domain)&&BigInt(now.tick)<BigInt(s.deadline.queue_deadline_tick_ns),'deadline');
  const identity={token_id:s.token_id,actor,session_id:proof.session_id,credential_id:proof.credential_id,audience:proof.audience,
   permissions:proof.permissions,authorization_digest:proof.authorization_digest,scope_digest:proof.scope_digest,policy_revision:proof.policy_revision,
   authorization_revision:proof.authorization_revision,expires_ns:proof.expires_ns,session_not_before_ns:proof.session_not_before_ns,
   binding_ref:execution.ref,ready_ref:execution.ready.ref};
  return {command,request,execution,proof,now,identity};
 }
 function windowInput(actual,core,acquisition,selected,cap){return {db,service,coreRuntime:core,domain:actual.now.ref,acquisitionRef:acquisition,
  selectedTick:selected,validFrom:actual.proof.session_not_before_ns,validBefore:actual.proof.expires_ns,capTick:cap};}
 function current(id,snapshot,preparedRef=null){
   const actual=collect(id,preparedRef);need(snapshot.format==='command-encoding-identity/1'&&snapshot.command_id===id&&same(snapshot.identity,actual.identity),'changed');
   if(actual.command.source.metadata.origin==='automation'){need(same(snapshot,actual.snapshot),'changed');return actual;}
   const core=coreSource.currentCoreSource(snapshot.core_source_ref),window=snapshot.authentication_window;
   currentAuthenticationWindow(windowInput(actual,core,window.acquisition_ref,window.selected_tick_ns,window.cap_tick_ns),window,actual.now.tick);
   need(BigInt(window.before_tick_ns)<=BigInt(actual.command.source.deadline.queue_deadline_tick_ns)&&
    BigInt(window.before_tick_ns)<=BigInt(actual.execution.ready.value.expires_tick_ns),'deadline');
   return {...actual,snapshot,snapshot_ref:reference(id+'.encoding-identity',snapshot),expires_tick_ns:window.before_tick_ns};
  }
 return Object.freeze({
  ...(clockReference&&{readCommandReference:clockReference.readFirst,isCommandReferenceCurrent:clockReference.isCurrent}),
  select(id){
   const actual=collect(id);if(actual.command.source.metadata.origin==='automation')return actual;
   const core=coreSource.selectCoreSource();
   const cap=String([BigInt(actual.command.source.deadline.queue_deadline_tick_ns),BigInt(actual.execution.ready.value.expires_tick_ns),BigInt(core.value.expires_tick_ns)].reduce((a,b)=>a<b?a:b));
   const window=selectAuthenticationWindow(windowInput(actual,core,actual.proof.acquisition_ref,actual.now.tick,cap));
   const snapshot={format:'command-encoding-identity/1',command_id:id,identity:actual.identity,core_source_ref:core.ref,authentication_window:window};
   return {...actual,snapshot,snapshot_ref:reference(id+'.encoding-identity',snapshot),expires_tick_ns:window.before_tick_ns};
  },
  current(id,snapshot){return current(id,snapshot);},
  currentPrepared(id,snapshot,preparedRef){need(preparedRef,'prepared_source');return current(id,snapshot,preparedRef);},
 });
}
