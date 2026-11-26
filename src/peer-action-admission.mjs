import {digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingInteger as integer,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {isPreparationDigest as hash} from './peer-run-arm-plan.mjs';
export {actionAdmissionRequest} from './peer-action-binding.mjs';
import {assertEndorsementParameters,endorsementScope} from './run-endorsement-scope.mjs';
import {scheduledDispatch} from './command-reference-time.mjs';

function reference(ref,kind,scope,id){
 fields(ref,'kind,scope,object_id,revision,digest');
 need(ref.kind===kind&&same(ref.scope,scope)&&ref.object_id===id&&ref.revision==='1'&&hash(ref.digest),'action_reference');
}

function scheduleOrigin(value,execution,executionRef,stepId,planRequest,plan){
 fields(value,'admission,step_window,window_index');
 const {admission,step_window,window_index}=value,{scope,execution_id,run_id,admission_ref,artifact_ref}=execution;
 need(admission?.format==='leafseamer.schedule-admission/1'&&same(admission.scope,scope)&&
  admission.execution_id===execution_id&&admission.run_id===run_id&&same(admission.artifact_ref,artifact_ref)&&
  same(artifact_ref,planRequest.artifact_ref)&&digest(admission)===admission_ref?.digest,'action_schedule_admission');
 reference(admission_ref,'schedule_admission',scope,admission.occurrence_id);
 need(hash(admission.occurrence_plan_digest)&&Array.isArray(window_index)&&window_index.length>0&&window_index.length<=256&&
  window_index.every(item=>item&&typeof item.step_id==='string'&&hash(item.step_window_digest))&&
  new Set(window_index.map(item=>item.step_id)).size===window_index.length&&digest(window_index)===admission.step_window_index_digest,
  'action_schedule_occurrence');
 need(step_window&&hash(step_window.step_window_digest),'action_schedule_step');
 const windows=window_index.filter(item=>item.step_id===stepId);
 const {step_window_digest,...step}=step_window,binding=plan.payload.binding;
 need(windows.length===1&&same(windows[0],{step_id:stepId,step_window_digest})&&step.step_id===stepId&&
  digest(step)===step_window_digest&&step.action_binding_id===binding.action_binding_ref.id&&
  (admission.first_step_id!==stepId||same(admission.step_window_ref,{id:step.step_window_id,revision:'1',digest:step_window_digest})),
  'action_schedule_step');
 const selected={format:'leafseamer.schedule-step-binding/1',execution_ref:executionRef,
  occurrence_ref:{id:admission.occurrence_id,revision:'1',digest:admission.occurrence_plan_digest},
  admission_ref:{id:admission_ref.object_id,revision:admission_ref.revision,digest:admission_ref.digest},
  definition_artifact_ref:{id:artifact_ref.object_id,revision:artifact_ref.revision,digest:artifact_ref.digest},
  schedule_version:admission.schedule_version_ref.revision,activation_ref:admission.activation_ref,
  step_id:stepId,step_window_ref:{id:step.step_window_id,revision:'1',digest:step_window_digest},window:step.window};
 // Validate the same narrow dispatch policy later consumed by command admission and guard installation.
 scheduledDispatch(selected,{step_id:stepId,execution_binding_ref:{...executionRef,kind:'execution_binding'}},1);
 return selected;
}

function recoveryOrigin(value,execution,planRequest,plan,body,receipt,peerBindingId){
 fields(value,'binding,source_parameters,source_step_plan,start');
 const {binding,start,source_step_plan:source,source_parameters}=value;
 const {scope,execution_id,arm_generation,definition_version,reservation_ref,binding_ref,start_ref,origin_digest,grant_basis}=execution;
 const operation=planRequest.operation_ref;
 reference(reservation_ref,'execution',scope,execution_id);
 reference(binding_ref,'recovery_execution_binding',scope,execution_id);
 reference(start_ref,'recovery_start',scope,operation.object_id);
 need(execution.format==='leafseamer.recovery-action-execution/1'&&definition_version===planRequest.definition_version&&
  execution_id===planRequest.execution_id&&origin_digest===start_ref.digest&&digest(start)===start_ref.digest&&
  digest(binding)===binding_ref.digest,'action_recovery_execution');
 need(binding.format==='leafseamer.recovery-execution-binding/1'&&start.format==='leafseamer.recovery-start/1'&&
  same(start.binding_ref,binding_ref)&&same(start.operation_ref,operation)&&same(binding.operation_ref,operation)&&
  same(start.execution_ref,reservation_ref)&&same(binding.execution_ref,reservation_ref)&&
  same(binding.approval_ref,planRequest.approval_ref)&&same(start.approval_ref,binding.approval_ref)&&
  start.arm_generation===arm_generation&&binding.arm_generation===arm_generation&&start.previous_run_revision===binding.run_revision&&
  integer(start.run_revision)===integer(binding.run_revision)+1n&&start.state==='start_recorded'&&
  start.dispatch_eligible===false&&binding.dispatch_eligible===false&&
  start.service_boot_id===execution.service_boot_id&&binding.service_boot_id===execution.service_boot_id,'action_recovery_start');
 const member=binding.grants?.find(item=>same(item.grant_ref,receipt.grant_ref));
 need(member&&same(binding.grants,grant_basis.map(({eligible_before_ns,...item})=>item))&&
  same(member.endorsement_ref,receipt.grant.endorsement_ref),'action_recovery_grant');
 // 接收端核验自己的配对原件。绑定正文保存的是 Seamer 侧配对引用。
 fields(member.pairing_ref,'id,revision,digest');
 need(member.pairing_ref.id===peerBindingId&&integer(member.pairing_ref.revision)>0n&&hash(member.pairing_ref.digest),'action_recovery_grant');
 const steps=Array.isArray(start.steps)?start.steps.filter(item=>item.step_id===plan.step_id):[];
 const item=steps[0],originalBinding=source?.payload?.binding;
 need(steps.length===1&&item.decision==='execute_new'&&same(item.grant_ref,receipt.grant_ref)&&
  source?.step_id===plan.step_id&&source.execution_id===item.source_execution_id&&source.execution_id!==execution_id&&
  source.payload?.kind==='action'&&same(originalBinding?.grant_ref,planRequest.baseline_grant_ref)&&digest(source)===item.plan_digest&&
  same(plan,{...source,execution_id,payload:{...source.payload,binding:{...originalBinding,grant_ref:receipt.grant_ref}}}),
  'action_recovery_step');
 if(source_parameters===null){
  need(digest(source.payload)===item.parameters_digest,'action_recovery_parameters');
 }else{
  fields(source_parameters,'ref,body');
  const original=source_parameters.body;
  reference(source_parameters.ref,'action_parameters',scope,plan.step_id);
  need(original?.format==='leafseamer.action-parameters/1'&&original.execution_ref?.object_id===source.execution_id&&
   same(original.execution_ref.scope,scope)&&original.step_id===plan.step_id&&original.step_plan_digest===item.plan_digest&&
   digest(original)===source_parameters.ref.digest&&source_parameters.ref.digest===item.parameters_digest&&
   same(original.grant_ref,originalBinding.grant_ref)&&
   same(original.parameters,body.parameters)&&same(original.parameter_schema_ref,body.parameter_schema_ref),'action_recovery_parameters');
 }
}

export function actionAdmissionBinding(value,request,prepared,peerBindingId=null){
 const scheduled=value?.execution?.origin_kind==='schedule',recovery=request.execution_ref.revision==='2';
 fields(value,'execution,step_plan,step_ready,parameters,eligible_before_ns'+(recovery?',recovery':scheduled?',schedule':''));
 const {execution,step_plan:plan,step_ready:ready,parameters,eligible_before_ns}=value;
 const {execution_ref,step_id,parameters_ref,preparation}=request,{origin_scope,controller_scope}=preparation.lookup;
 const {request:planRequest,applied_receipt:receipt}=prepared,{grant}=receipt;
 need(execution&&Array.isArray(execution.steps)&&Array.isArray(execution.grant_basis),'action_execution');
 const {execution_id,run_id,arm_generation,steps,grant_basis}=execution;
 const originDigest=scheduled?execution.admission_ref?.digest:execution.origin_digest;
 need((recovery?execution.origin_kind==='recovery':scheduled?execution.format==='leafseamer.scheduled-execution/1':
  execution.format==='leafseamer.trigger-execution/1'&&execution.runtime_revision==='3'&&execution.origin_kind==='trigger')&&
  same(execution.scope,origin_scope)&&hash(originDigest)&&digest(execution)===execution_ref.digest&&execution_id===execution_ref.object_id&&
  same(execution.artifact_ref,planRequest.artifact_ref)&&run_id===grant.run_id&&arm_generation===grant.arm_generation&&
  (recovery?planRequest.mode==='recovery'&&planRequest.execution_id===execution_id:planRequest.mode==='arm'&&planRequest.execution_id===null),
  'action_execution');
 const listed=steps.find(step=>step.step_id===step_id),targetGrant=grant_basis.find(item=>same(item.grant_ref,receipt.grant_ref));
 need(listed&&targetGrant&&same(targetGrant.lookup,preparation.lookup)&&same(targetGrant.receipt_ref,preparation.receipt_ref),'action_grant');
 const payload=plan?.payload,binding=payload?.binding;
 need(payload?.kind==='action'&&binding?.target&&plan.execution_id===execution_id&&plan.step_id===step_id&&digest(plan)===listed.plan_digest&&
  same(binding.grant_ref,receipt.grant_ref)&&same(binding.target.controller_scope,controller_scope)&&
  grant.device_actions.some(action=>same(action,binding.target.device_action)),'action_plan');
 const schedule=scheduled?scheduleOrigin(value.schedule,execution,execution_ref,step_id,planRequest,plan):null;
 fields(ready,'ref,body');fields(parameters,'ref,body');
 uuid(ready.body?.ready_id);
 reference(ready.ref,'step_ready',origin_scope,ready.body.ready_id);
 need(digest(ready.body)===ready.ref.digest&&ready.body.format==='leafseamer.step-ready/1'&&same(ready.body.execution_ref,execution_ref)&&
  ready.body.step_id===step_id&&ready.body.step_plan_digest===listed.plan_digest,'action_ready');
 const body=parameters.body,eligible=integer(eligible_before_ns);
 need(body&&same(parameters.ref,parameters_ref)&&digest(body)===parameters_ref.digest&&body.format==='leafseamer.action-parameters/1'&&
  same(body.execution_ref,execution_ref)&&body.step_id===step_id&&body.step_plan_digest===listed.plan_digest&&
  same(body.step_ready_ref,ready.ref)&&body.origin_digest===originDigest&&same(body.grant_ref,receipt.grant_ref)&&
  same(body.parameter_schema_ref,binding.parameter_schema_ref)&&same(body.delay_window_refs,ready.body.delay_window_refs??[])&&
  body.parameters!==null&&typeof body.parameters==='object'&&!Array.isArray(body.parameters)&&digest(body.parameters)===body.parameters_digest&&
  eligible>0n&&eligible<=integer(body.eligible_before_ns)&&eligible<=integer(execution.approved_before_ns)&&
  eligible<=integer(targetGrant.eligible_before_ns),'action_parameters');
 assertEndorsementParameters(endorsementScope(grant.device_actions,grant.parameter_constraints),binding.target.device_action,body.parameters);
 if(recovery)recoveryOrigin(value.recovery,execution,planRequest,plan,body,receipt,peerBindingId);
 return {execution_ref,step_id,parameters_ref,origin_scope,controller_scope,run_id,arm_generation,
  definition_version:grant.definition_version,principal:grant.principal,grant_ref:receipt.grant_ref,
  target:binding.target.device_action,parameters:body.parameters,parameter_schema_ref:body.parameter_schema_ref,
  ...(binding.action_binding_ref&&{action_binding_ref:binding.action_binding_ref}),
  delay_window_refs:body.delay_window_refs,eligible_before_ns,...(schedule&&{schedule_binding:schedule})};
}
