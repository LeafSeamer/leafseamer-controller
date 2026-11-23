import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {proposalReference,proposalTarget,proposalWindowEnd,runProposalBodyLimit} from './peer-run-approval-proposal.mjs';

const hash=value=>typeof value==='string'&&value.length===71&&/^sha256:[0-9a-f]{64}$/.test(value);
const principal=value=>{fields(value,'issuer_id,issuer_epoch,principal_id');Object.values(value).forEach(uuid);};
function basis(reference,kind,scope){
 fields(reference,'kind,scope,object_id,revision,digest');uuid(reference.object_id);
 need(reference.kind===kind&&same(reference.scope,scope)&&hash(reference.digest)&&typeof reference.revision==='string'&&
  /^[1-9][0-9]{0,19}$(?![\s\S])/.test(reference.revision),'endorsement_basis');
}
export function endorsementReference(value){
 fields(value,'kind,scope,object_id,revision,digest');fields(value.scope,'authority_service_id,database_instance_id');
 Object.values(value.scope).forEach(uuid);uuid(value.object_id);
 need(value.kind==='run_approval_endorsement'&&value.revision==='1'&&hash(value.digest),'endorsement_reference');
 return value;
}

export function endorsementReadRequest(id,bodyDigest,challenge){
 uuid(id);uuid(challenge);need(hash(bodyDigest),'endorsement_reference');
 return {endorsement_id:id,endorsement_digest:bodyDigest,challenge_id:challenge};
}

export function endorsementReadReply(reply,request,record,controller,seamer){
 fields(reply,'format,challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.format==='leafseamer.run-approval-endorsement-response/1'&&reply.challenge_id===request.challenge_id&&
  reply.pair_attempt_id===record.transcript.pair_attempt_id&&reply.transcript_digest===record.transcript_digest,'endorsement_response');
 const body=reply.body;
 const reversal=body?.revocation_operation_ref??null;
 fields(body,'endorsement,object_ref,state,status_revision,current_eligibility,eligible_before_ns'+(reversal?',revocation_operation_ref':''));
 const reference=endorsementReference(body.object_ref),value=body.endorsement;
 fields(value,'scope,endorsement_id,revision,proposal_ref,origin_scope,run_id,service_principal,controller_target_digest,device_actions,parameter_constraints,validity,endorsed_by,authorization_basis_refs,created_authentication_ref');
 uuid(value.run_id);principal(value.service_principal);principal(value.endorsed_by);
 const proposal=proposalReference(value.proposal_ref),end=proposalWindowEnd(value);
 const target=proposalTarget({controller_targets:[{controller_scope:value.scope,device_actions:value.device_actions,
  parameter_constraints:value.parameter_constraints}]},controller);
 need(same(reference.scope,controller)&&same(value.scope,controller)&&same(value.origin_scope,seamer)&&same(proposal.scope,seamer)&&
  reference.object_id===request.endorsement_id&&reference.digest===request.endorsement_digest&&value.endorsement_id===reference.object_id&&
  value.revision===reference.revision&&digest(value)===reference.digest&&digest(target)===value.controller_target_digest&&
  Buffer.byteLength(canonical(value))<=runProposalBodyLimit,'endorsement_integrity');
 need(Array.isArray(value.authorization_basis_refs)&&value.authorization_basis_refs.length===2,'endorsement_basis');
 basis(value.authorization_basis_refs[0],'run_endorsement_policy',controller);
 basis(value.authorization_basis_refs[1],'service_approval',controller);
 basis(value.created_authentication_ref,'authentication',controller);
 need(value.created_authentication_ref.object_id===value.endorsement_id&&value.created_authentication_ref.revision==='1','endorsement_basis');
 need((body.state==='active'&&body.status_revision==='1')||(['expired','revoking'].includes(body.state)&&body.status_revision==='2'&&
  body.current_eligibility==='blocked'),'endorsement_status');
 need(body.state==='expired'||(body.state==='active')===(reversal===null),'endorsement_status');
 if(reversal!==null){basis(reversal,'run_approval_operation',controller);need(reversal.revision==='1','endorsement_status');}
 if(body.current_eligibility==='eligible'){
  need(typeof body.eligible_before_ns==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(body.eligible_before_ns)&&
   BigInt(body.eligible_before_ns)<=end&&BigInt(body.eligible_before_ns)<=BigInt(record.expires_ns),'endorsement_expiry');
 }else need(['blocked','unavailable'].includes(body.current_eligibility)&&body.eligible_before_ns===null,'endorsement_status');
 return body;
}

export function endorsementControlReadReply(reply,request,record,controller,seamer){
 fields(reply,'format,challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.format==='leafseamer.run-approval-control-observation-response/1','endorsement_response');
 const body=reply.body;fields(body,'endorsement_read,devices');
 const endorsement=endorsementReadReply({...reply,format:'leafseamer.run-approval-endorsement-response/1',body:body.endorsement_read},
  request,record,controller,seamer);
 if(endorsement.current_eligibility!=='eligible'){
  need(body.devices===null,'control_observation_scope');return body;
 }
 const ids=[...new Set(endorsement.endorsement.device_actions.map(action=>action.device_id))].sort();
 need(Array.isArray(body.devices)&&same(body.devices.map(device=>device?.device_id),ids),'control_observation_scope');
 for(const device of body.devices){
  fields(device,'device_id,control');
  if(device.control===null)continue;
  const control=device.control;fields(control,'control_ref,control_epoch,effective_version,mode,gate_state,pending_operation_id');
  fields(control.control_ref,'id,revision,digest');uuid(control.control_ref.id);uuid(control.control_epoch);
  if(control.pending_operation_id!==null)uuid(control.pending_operation_id);
  need(hash(control.control_ref.digest)&&typeof control.control_ref.revision==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(control.control_ref.revision)&&
   typeof control.effective_version==='string'&&/^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(control.effective_version)&&
   ['manual','automatic'].includes(control.mode)&&['protected','ready','fencing'].includes(control.gate_state),'control_observation_record');
 }
 return body;
}
