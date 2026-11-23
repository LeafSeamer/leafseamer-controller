import {digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingInteger as integer,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {isPreparationDigest as hash} from './peer-run-arm-plan.mjs';
export {actionAdmissionRequest} from './peer-action-binding.mjs';
import {assertEndorsementParameters,endorsementScope} from './run-endorsement-scope.mjs';

function reference(ref,kind,scope,id){
 fields(ref,'kind,scope,object_id,revision,digest');
 need(ref.kind===kind&&same(ref.scope,scope)&&ref.object_id===id&&ref.revision==='1'&&hash(ref.digest),'action_reference');
}

export function actionAdmissionBinding(value,request,prepared){
 fields(value,'execution,step_plan,step_ready,parameters,eligible_before_ns');
 const {execution,step_plan:plan,step_ready:ready,parameters,eligible_before_ns}=value;
 const {execution_ref,step_id,parameters_ref,preparation}=request,{origin_scope,controller_scope}=preparation.lookup;
 const {request:planRequest,applied_receipt:receipt}=prepared,{grant}=receipt;
 need(execution&&Array.isArray(execution.steps)&&Array.isArray(execution.grant_basis),'action_execution');
 const {execution_id,run_id,arm_generation,steps,grant_basis}=execution;
 need(execution.format==='leafseamer.trigger-execution/1'&&execution.runtime_revision==='3'&&same(execution.scope,origin_scope)&&
  execution.origin_kind==='trigger'&&hash(execution.origin_digest)&&digest(execution)===execution_ref.digest&&execution_id===execution_ref.object_id&&
  same(execution.artifact_ref,planRequest.artifact_ref)&&run_id===grant.run_id&&arm_generation===grant.arm_generation&&
  planRequest.mode==='arm'&&planRequest.execution_id===null,
  'action_execution');
 const listed=steps.find(step=>step.step_id===step_id),targetGrant=grant_basis.find(item=>same(item.grant_ref,receipt.grant_ref));
 need(listed&&targetGrant&&same(targetGrant.lookup,preparation.lookup)&&same(targetGrant.receipt_ref,preparation.receipt_ref),'action_grant');
 const payload=plan?.payload,binding=payload?.binding;
 need(payload?.kind==='action'&&binding?.target&&plan.execution_id===execution_id&&plan.step_id===step_id&&digest(plan)===listed.plan_digest&&
  same(binding.grant_ref,receipt.grant_ref)&&same(binding.target.controller_scope,controller_scope)&&
  grant.device_actions.some(action=>same(action,binding.target.device_action)),'action_plan');
 fields(ready,'ref,body');fields(parameters,'ref,body');
 uuid(ready.body?.ready_id);
 reference(ready.ref,'step_ready',origin_scope,ready.body.ready_id);
 need(digest(ready.body)===ready.ref.digest&&ready.body.format==='leafseamer.step-ready/1'&&same(ready.body.execution_ref,execution_ref)&&
  ready.body.step_id===step_id&&ready.body.step_plan_digest===listed.plan_digest,'action_ready');
 const body=parameters.body,eligible=integer(eligible_before_ns);
 need(body&&same(parameters.ref,parameters_ref)&&digest(body)===parameters_ref.digest&&body.format==='leafseamer.action-parameters/1'&&
  same(body.execution_ref,execution_ref)&&body.step_id===step_id&&body.step_plan_digest===listed.plan_digest&&
  same(body.step_ready_ref,ready.ref)&&body.origin_digest===execution.origin_digest&&same(body.grant_ref,receipt.grant_ref)&&
  same(body.parameter_schema_ref,binding.parameter_schema_ref)&&same(body.delay_window_refs,ready.body.delay_window_refs??[])&&
  body.parameters!==null&&typeof body.parameters==='object'&&!Array.isArray(body.parameters)&&digest(body.parameters)===body.parameters_digest&&
  eligible>0n&&eligible<=integer(body.eligible_before_ns)&&eligible<=integer(execution.approved_before_ns)&&
  eligible<=integer(targetGrant.eligible_before_ns),'action_parameters');
 assertEndorsementParameters(endorsementScope(grant.device_actions,grant.parameter_constraints),binding.target.device_action,body.parameters);
 return {execution_ref,step_id,parameters_ref,origin_scope,controller_scope,run_id,arm_generation,
  definition_version:grant.definition_version,principal:grant.principal,grant_ref:receipt.grant_ref,
  target:binding.target.device_action,parameters:body.parameters,parameter_schema_ref:body.parameter_schema_ref,
  ...(binding.action_binding_ref&&{action_binding_ref:binding.action_binding_ref}),
  delay_window_refs:body.delay_window_refs,eligible_before_ns};
}
