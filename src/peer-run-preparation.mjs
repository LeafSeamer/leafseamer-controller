import {digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingInteger as integer,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {checkPreparationScope,isPreparationDigest,armPreparationRequest} from './peer-run-arm-plan.mjs';
import {endorsementReference} from './peer-run-approval-endorsement.mjs';
import {runProposalBodyLimit} from './peer-run-approval-proposal.mjs';

export const preparationProtocol='automation-preparation/0.1.0-draft.2';
export const preparationRequestLimit=runProposalBodyLimit;
export const preparationResponseLimit=4*preparationRequestLimit+4096;
// 仅用于新发起的运行批准、准备资格和动作绑定观察。
export const runEligibilityObservationMs=5000;
export const runEligibilityObservationNs=BigInt(runEligibilityObservationMs)*1000000n;

export function armPreparationLookup(request,controller){
 fields(request,'controller_scope,origin_scope,preparation_id,request_digest');
 checkPreparationScope(request.origin_scope);uuid(request.preparation_id);
 need(same(request.controller_scope,controller)&&isPreparationDigest(request.request_digest),'preparation_request');return request;
}

export function armPreparationEligibilityRequest(request,controller,{allowScheduled=false}={}){
 const scheduled=allowScheduled&&Object.hasOwn(request??{},'schedule_device_ids');
 fields(request,scheduled?'lookup,receipt_ref,grant_ref,schedule_device_ids':'lookup,receipt_ref,grant_ref');
 if(scheduled){
  const ids=request.schedule_device_ids;
  need(Array.isArray(ids)&&ids.length>=1&&ids.length<=256,'preparation_schedule_devices');
  ids.forEach((id,index)=>{
   uuid(id);
   need(index===0||ids[index-1]<id,'preparation_schedule_devices');
  });
 }
 armPreparationLookup(request.lookup,controller);
 controllerReference(request.receipt_ref,'preparation_receipt',controller);
 controllerReference(request.grant_ref,'grant',controller);
 return request;
}

function controllerReference(ref,kind,scope){
 fields(ref,'kind,scope,object_id,revision,digest');uuid(ref.object_id);
 need(ref.kind===kind&&same(ref.scope,scope)&&ref.revision==='1'&&isPreparationDigest(ref.digest),'preparation_response');
}

export function armPreparationRecord(value,lookup){
 fields(value,'request,request_digest,revision,state,applied_receipt,protection_ref');
 const request=armPreparationRequest(value.request,lookup.controller_scope),receipt=value.applied_receipt;
 need(value.state==='applied'&&value.revision==='2'&&value.protection_ref===null&&
  value.request_digest===lookup.request_digest&&value.request_digest===digest(request)&&
  request.preparation_id===lookup.preparation_id&&same(request.origin_scope,lookup.origin_scope),'preparation_response');
 fields(receipt,'receipt_id,revision,controller_scope,preparation_id,request_digest,grant,grant_ref,commit_ref,receipt_digest');
 const {receipt_digest,...unsigned}=receipt;uuid(receipt.receipt_id);
 need(receipt.revision==='1'&&same(receipt.controller_scope,lookup.controller_scope)&&receipt.preparation_id===lookup.preparation_id&&
  receipt.request_digest===lookup.request_digest&&receipt_digest===digest(unsigned),'preparation_response');
 controllerReference(receipt.grant_ref,'grant',lookup.controller_scope);
 controllerReference(receipt.commit_ref,'controller_commit',lookup.controller_scope);
 const grant=receipt.grant,intent=request.grant_intent;
 fields(grant,'grant_id,revision,origin_scope,run_id,definition_version,arm_generation,principal,issuer_id,issuer_epoch,device_actions,parameter_constraints,validity,state,approval_ref,endorsement_ref');
 need(grant.grant_id===receipt.grant_ref.object_id&&grant.revision===receipt.grant_ref.revision&&digest(grant)===receipt.grant_ref.digest&&grant.state==='active'&&
  same(grant.origin_scope,request.origin_scope)&&grant.run_id===request.run_id&&grant.definition_version===request.definition_version&&
  grant.arm_generation===request.arm_generation&&grant.issuer_id===intent.principal.issuer_id&&grant.issuer_epoch===intent.principal.issuer_epoch&&
  same(grant.principal,intent.principal)&&same(grant.device_actions,intent.device_actions)&&same(grant.parameter_constraints,intent.parameter_constraints)&&
  same(grant.validity,intent.validity)&&same(grant.approval_ref,request.approval_ref)&&
  same(endorsementReference(grant.endorsement_ref).scope,lookup.controller_scope),'preparation_response');
 return value;
}

export function armPreparationReply(reply,request,pairing,challenge,lookup){
 preparationEnvelope(reply,pairing,challenge);
 if(!lookup)return armPreparationRecord(reply.body,{...request,request_digest:digest(request)});
 fields(reply.body,'state,record');
 if(reply.body.state==='found')armPreparationRecord(reply.body.record,request);
 else need(['not_found','indeterminate'].includes(reply.body.state)&&reply.body.record===null,'preparation_response');
 return reply.body;
}

function preparationEnvelope(reply,pairing,challenge){
 fields(reply,'challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.challenge_id===challenge&&reply.pair_attempt_id===pairing.transcript.pair_attempt_id&&
  reply.transcript_digest===pairing.transcript_digest,'preparation_response_binding');
}

export function armPreparationEligibilityReply(reply,request,pairing,challenge){
 preparationEnvelope(reply,pairing,challenge);
 const value=reply.body;fields(value,'request,state,eligible_before_ns');
 const deadline=integer(value.eligible_before_ns);
 need(same(value.request,request)&&value.state==='eligible'&&deadline>0n&&deadline<=integer(pairing.expires_ns),'preparation_eligibility_response');
 return value;
}
