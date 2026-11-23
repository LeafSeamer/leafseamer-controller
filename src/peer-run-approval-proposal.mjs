import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';

export const runProposalBodyLimit=1048576;
export const runProposalResponseLimit=runProposalBodyLimit+4096;
export const peerScope=party=>({authority_service_id:party.service_id,database_instance_id:party.database_instance_id});
const isDigest=value=>typeof value==='string'&&/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(value);
const unique=values=>new Set(values.map(value=>canonical(value))).size===values.length;
const actionKey=({device_id,action_id,capability_version})=>JSON.stringify([device_id,action_id,capability_version]);

export function proposalReference(ref){
 fields(ref,'kind,scope,object_id,revision,digest');fields(ref.scope,'authority_service_id,database_instance_id');
 uuid(ref.scope.authority_service_id);uuid(ref.scope.database_instance_id);uuid(ref.object_id);
 need(ref.kind==='run_approval_proposal'&&ref.revision==='1'&&isDigest(ref.digest),'proposal_reference');
 return ref;
}
export function proposalReadRequest(proposalId,bodyDigest,challenge){
 uuid(proposalId);uuid(challenge);need(isDigest(bodyDigest),'proposal_reference');
 return {proposal_id:proposalId,proposal_digest:bodyDigest,challenge_id:challenge};
}
export function proposalWindowEnd(proposal){
 fields(proposal.validity,'not_before,not_after');
 const timestamps=[proposal.validity.not_before,proposal.validity.not_after].map(value=>{
  const millis=typeof value==='string'?Date.parse(value):NaN;
  need(Number.isSafeInteger(millis)&&millis>=0&&new Date(millis).toISOString()===value,'proposal_window');
  return BigInt(millis)*1000000n;
 });
 need(timestamps[0]<timestamps[1],'proposal_window');return timestamps[1];
}
export function proposalTarget(proposal,scope){
 const targets=proposal.controller_targets;
 need(Array.isArray(targets)&&targets.length<=256&&unique(targets.map(target=>target.controller_scope)),'proposal_targets');
 const target=targets.find(item=>same(item.controller_scope,scope));need(target,'proposal_target');
 fields(target,'controller_scope,device_actions,parameter_constraints');
 need(Array.isArray(target.device_actions)&&target.device_actions.length>=1&&target.device_actions.length<=256&&unique(target.device_actions)&&
  Array.isArray(target.parameter_constraints)&&target.parameter_constraints.length<=64,'proposal_targets');
 for(const action of target.device_actions){
  fields(action,'device_id,action_id,capability_version');uuid(action.device_id);
  need(typeof action.action_id==='string'&&/^[A-Za-z0-9._-]{1,128}$(?![\s\S])/.test(action.action_id)&&
   typeof action.capability_version==='string'&&action.capability_version.length<=128&&
   /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$(?![\s\S])/.test(action.capability_version),'proposal_action');
 }
 const actions=new Set(target.device_actions.map(actionKey));
 for(const constraint of target.parameter_constraints){
  fields(constraint,'device_id,action_id,capability_version,parameter_pointer,rule');
  need(actions.has(actionKey(constraint))&&typeof constraint.parameter_pointer==='string'&&constraint.parameter_pointer.length<=1024&&
   /^(?:\/(?:[^~/]|~[01])*)*$(?![\s\S])/.test(constraint.parameter_pointer),'proposal_constraint');
 }
 return target;
}
export function proposalReadResult(body,request,seamer,controller){
 fields(body,'proposal,proposal_ref');
 const ref=proposalReference(body.proposal_ref),proposal=body.proposal;
 fields(proposal,'scope,proposal_id,revision,run_id,definition_id,definition_version,artifact_ref,program_digest,bindings_digest,dependency_footprint_ref,service_principal,source_service_approval_ref,controller_targets,validity,proposed_by,created_authentication_ref');
 need(same(ref.scope,seamer)&&same(proposal.scope,seamer)&&ref.object_id===request.proposal_id&&ref.digest===request.proposal_digest&&
  proposal.proposal_id===ref.object_id&&proposal.revision===ref.revision&&Buffer.byteLength(canonical(proposal))<=runProposalBodyLimit&&
  digest(proposal)===ref.digest,'proposal_integrity');
 proposalWindowEnd(proposal);proposalTarget(proposal,controller);return body;
}
export function proposalReadReply(reply,request,record,seamer,controller){
 fields(reply,'format,challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.format==='leafseamer.run-approval-proposal-response/1'&&reply.challenge_id===request.challenge_id&&
  reply.pair_attempt_id===record.transcript.pair_attempt_id&&reply.transcript_digest===record.transcript_digest,'proposal_response');
 return proposalReadResult(reply.body,request,seamer,controller);
}
