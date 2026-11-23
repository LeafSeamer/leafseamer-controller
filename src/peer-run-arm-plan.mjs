import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingInteger as integer,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {proposalWindowEnd,runProposalBodyLimit} from './peer-run-approval-proposal.mjs';
import {runApprovalReference} from './peer-run-approval.mjs';
import {runArmOperationReference} from './peer-run-initiator.mjs';

export const isPreparationDigest=value=>typeof value==='string'&&/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(value);
const hash=isPreparationDigest;
const revision=value=>typeof value==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(value);
export function checkPreparationScope(scope){fields(scope,'authority_service_id,database_instance_id');Object.values(scope).forEach(uuid);}
function checkReference(ref,kind,scope){
 fields(ref,'kind,scope,object_id,revision,digest');uuid(ref.object_id);
 need(ref.kind===kind&&same(ref.scope,scope)&&ref.revision==='1'&&hash(ref.digest),'preparation_reference');
}
export function armPlanReference(ref){
 checkPreparationScope(ref?.scope);checkReference(ref,'arm_plan',ref.scope);return ref;
}
export function armPreparationRequest(request,scope){
 fields(request,'operation_id,preparation_id,controller_scope,origin_scope,run_id,definition_version,arm_generation,mode,execution_id,operation_ref,plan_ref,artifact_ref,approval_ref,authorization_digest,source_digest,controls,baseline_grant_ref,grant_intent');
 const {origin_scope,controller_scope,operation_id,preparation_id,operation_ref,plan_ref,artifact_ref,approval_ref,controls,grant_intent}=request;
 checkPreparationScope(origin_scope);checkPreparationScope(controller_scope);[operation_id,preparation_id,request.run_id].forEach(uuid);
 need(same(controller_scope,scope)&&request.mode==='arm'&&request.execution_id===null&&request.baseline_grant_ref===null&&
  revision(request.definition_version)&&revision(request.arm_generation)&&hash(request.authorization_digest)&&hash(request.source_digest),'preparation_request');
 checkReference(runArmOperationReference(operation_ref),'run_arm_operation',origin_scope);
 checkReference(runApprovalReference(approval_ref),'run_approval',origin_scope);
 checkReference(plan_ref,'arm_plan',origin_scope);checkReference(artifact_ref,'artifact',origin_scope);
 need(operation_id===operation_ref.object_id&&plan_ref.object_id===preparation_id,'preparation_reference');
 fields(grant_intent,'principal,device_actions,parameter_constraints,validity');
 fields(grant_intent.principal,'issuer_id,issuer_epoch,principal_id,principal_kind');
 const {principal:{issuer_id,issuer_epoch,principal_id,principal_kind},device_actions,parameter_constraints,validity}=grant_intent;
 [issuer_id,issuer_epoch,principal_id].forEach(uuid);
 fields(validity,'not_before,not_after,authorization_policy_revision');
 need(principal_kind==='service'&&revision(validity.authorization_policy_revision)&&Array.isArray(device_actions)&&
  device_actions.length>=1&&device_actions.length<=256&&Array.isArray(parameter_constraints)&&parameter_constraints.length<=64&&
  Array.isArray(controls)&&controls.length>=1&&controls.length<=256,'preparation_request');
 proposalWindowEnd({validity:{not_before:validity.not_before,not_after:validity.not_after}});
 for(const control of controls){
  fields(control,'device_id,expected_control');uuid(control.device_id);fields(control.expected_control,'epoch,version');
  uuid(control.expected_control.epoch);need(control.expected_control.version==='0'||revision(control.expected_control.version),'preparation_control');
 }
 need(Buffer.byteLength(canonical(request))<=runProposalBodyLimit,'preparation_capacity');
 return request;
}

export function armPlanOriginal(original,reference,controller){
 fields(original,'format,definition_id,preparation,controls');uuid(original.definition_id);
 need(original.format==='leafseamer.run-arm-plan/1'&&digest(original)===reference.digest,'preparation_plan');
 const preparation=original.preparation;need(!Object.hasOwn(preparation,'plan_ref'),'preparation_plan');
 const request=armPreparationRequest({...preparation,plan_ref:reference},controller);
 const ids=request.grant_intent.device_actions.map(action=>{
  fields(action,'device_id,action_id,capability_version');uuid(action.device_id);return action.device_id;
 });
 const devices=[...new Set(ids)].sort();
 need(same(devices,request.controls.map(control=>control.device_id))&&Array.isArray(original.controls)&&original.controls.length===devices.length,'preparation_controls');
 for(const [index,item] of original.controls.entries()){
  fields(item,'device_id,control_ref');fields(item.control_ref,'id,revision,digest');uuid(item.control_ref.id);
  need(item.device_id===devices[index]&&revision(item.control_ref.revision)&&hash(item.control_ref.digest),'preparation_control');
 }
 return request;
}

export function armPlanReadRequest(id,planDigest,challenge){
 uuid(id);uuid(challenge);need(hash(planDigest),'preparation_reference');
 return {preparation_id:id,plan_digest:planDigest,challenge_id:challenge};
}
export function armPlanReadReply(reply,request,record,seamer,controller){
 fields(reply,'format,challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.format==='leafseamer.run-arm-plan-response/1'&&reply.challenge_id===request.challenge_id&&
  reply.pair_attempt_id===record.transcript.pair_attempt_id&&reply.transcript_digest===record.transcript_digest,'preparation_response');
 const body=reply.body;fields(body,'plan_ref,original,eligible_before_ns');
 const reference=armPlanReference(body.plan_ref);
 need(reference.object_id===request.preparation_id&&reference.digest===request.plan_digest&&same(reference.scope,seamer),'preparation_reference');
 const plan=armPlanOriginal(body.original,reference,controller),deadline=integer(body.eligible_before_ns);
 const {not_before,not_after}=plan.grant_intent.validity;
 need(deadline>0n&&deadline<=integer(record.expires_ns)&&deadline<=proposalWindowEnd({validity:{not_before,not_after}}),'preparation_expired');
 return body;
}
