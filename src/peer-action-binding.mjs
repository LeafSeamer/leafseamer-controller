import {digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingInteger as integer,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {isPreparationDigest as hash} from './peer-run-arm-plan.mjs';
import {armPreparationEligibilityRequest} from './peer-run-preparation.mjs';

export const actionBindingPath='/internal/automation/action-bindings';
export const actionBindingVersion='leafseamer-action-binding/1';
export const actionBindingRequestLimit=4096;
export const actionBindingResponseLimit=1048576+4096;

function reference(ref,kind,scope,id){
 fields(ref,'kind,scope,object_id,revision,digest');
 need(ref.kind===kind&&same(ref.scope,scope)&&ref.object_id===id&&ref.revision==='1'&&hash(ref.digest),'action_reference');
}

export function actionAdmissionRequest(value,controller){
 fields(value,'preparation,execution_ref,step_id,parameters_ref');
 const {preparation,execution_ref,step_id,parameters_ref}=value;
 armPreparationEligibilityRequest(preparation,controller);
 const {origin_scope}=preparation.lookup;
 uuid(execution_ref?.object_id);
 need(typeof step_id==='string'&&/^[A-Za-z0-9_.:-]{1,128}$(?![\s\S])/.test(step_id),'action_step');
 reference(execution_ref,'execution',origin_scope,execution_ref.object_id);
 reference(parameters_ref,'action_parameters',origin_scope,step_id);
 return value;
}

export function actionBindingReply(reply,request,record,challenge){
 fields(reply,'version,challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.version===actionBindingVersion&&reply.challenge_id===challenge&&reply.pair_attempt_id===record.transcript.pair_attempt_id&&
  reply.transcript_digest===record.transcript_digest,'action_reply');
 const {body}=reply;
 fields(body,'execution,step_plan,step_ready,parameters,eligible_before_ns');
 const {execution_ref,step_id,parameters_ref}=request,{parameters,execution,step_plan}=body;
 const end=integer(body.eligible_before_ns);
 need(execution?.execution_id===execution_ref.object_id&&same(execution.scope,execution_ref.scope)&&digest(execution)===execution_ref.digest&&
  step_plan?.step_id===step_id&&step_plan.execution_id===execution_ref.object_id&&same(parameters?.ref,parameters_ref)&&
  digest(parameters.body)===parameters_ref.digest&&same(parameters.body.execution_ref,execution_ref)&&parameters.body.step_id===step_id&&
  end>0n&&end<=integer(record.expires_ns),'action_reply');
 return body;
}
