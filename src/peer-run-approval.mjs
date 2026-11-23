import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {proposalReference,proposalWindowEnd,runProposalBodyLimit} from './peer-run-approval-proposal.mjs';
import {endorsementReference} from './peer-run-approval-endorsement.mjs';

const hash=value=>typeof value==='string'&&value.length===71&&/^sha256:[0-9a-f]{64}$/.test(value);
function reference(value,kind){
 fields(value,'kind,scope,object_id,revision,digest');fields(value.scope,'authority_service_id,database_instance_id');
 Object.values(value.scope).forEach(uuid);uuid(value.object_id);
 need(value.kind===kind&&hash(value.digest)&&typeof value.revision==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(value.revision),'approval_reference');return value;
}
export function runApprovalReference(value){
 reference(value,'run_approval');need(value.revision==='1','approval_reference');return value;
}
export function runApprovalReadRequest(id,version,bodyDigest,challenge){
 uuid(id);uuid(challenge);need(version==='1'&&hash(bodyDigest),'approval_reference');
 return {approval_id:id,approval_revision:version,approval_digest:bodyDigest,challenge_id:challenge};
}
function principal(value){fields(value,'issuer_id,issuer_epoch,principal_id');Object.values(value).forEach(uuid);}
export function runApprovalReadReply(reply,request,record,seamer,controller){
 fields(reply,'format,challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.format==='leafseamer.run-approval-response/1'&&reply.challenge_id===request.challenge_id&&
  reply.pair_attempt_id===record.transcript.pair_attempt_id&&reply.transcript_digest===record.transcript_digest,'approval_response');
 const body=reply.body;
 fields(body,'approval,object_ref,state,status_revision,revocation_operation_ref,local_eligibility,eligible_before_ns');
 const ref=runApprovalReference(body.object_ref),approval=body.approval;
 fields(approval,'scope,approval_id,revision,run_id,proposal_ref,artifact_ref,program_digest,bindings_digest,dependency_footprint_ref,service_principal,source_service_approval_ref,controller_endorsement_refs,validity,approved_by,approval_operation_id,created_authentication_ref');
 for(const id of [approval.run_id,approval.approval_operation_id])uuid(id);
 principal(approval.service_principal);principal(approval.approved_by);
 const proposal=proposalReference(approval.proposal_ref),end=proposalWindowEnd(approval);
 need(same(ref.scope,seamer)&&same(approval.scope,seamer)&&same(proposal.scope,seamer)&&approval.approval_id===ref.object_id&&
  approval.revision===ref.revision&&ref.object_id===request.approval_id&&ref.revision===request.approval_revision&&ref.digest===request.approval_digest&&
  digest(approval)===ref.digest&&Buffer.byteLength(canonical(approval))<=runProposalBodyLimit&&hash(approval.program_digest)&&hash(approval.bindings_digest),'approval_integrity');
 const artifact=reference(approval.artifact_ref,'artifact'),dependencies=reference(approval.dependency_footprint_ref,'program_dependencies');
 const auth=reference(approval.created_authentication_ref,'authentication');reference(approval.source_service_approval_ref,'service_approval');
 need([artifact,dependencies,auth].every(item=>same(item.scope,seamer))&&auth.object_id===approval.approval_id&&auth.revision==='1','approval_integrity');
 const refs=approval.controller_endorsement_refs;
 need(Array.isArray(refs)&&refs.length>=1&&refs.length<=256,'approval_targets');refs.forEach(endorsementReference);
 need(new Set(refs.map(item=>canonical(item.scope))).size===refs.length&&refs.some(item=>same(item.scope,controller)),'approval_targets');
 need((body.state==='active'&&body.status_revision==='1')||(body.local_eligibility==='blocked'&&
  (['expired','revoking','revoked'].includes(body.state)&&body.status_revision==='2'||body.state==='revoked'&&body.status_revision==='3')),'approval_state');
 const reversal=body.revocation_operation_ref;
 need(body.state==='expired'||(body.state==='active')===(reversal===null),'approval_state');
 if(reversal!==null){reference(reversal,'run_approval_operation');need(reversal.revision==='1'&&same(reversal.scope,seamer),'approval_state');}
 if(body.local_eligibility==='eligible'){
  need(typeof body.eligible_before_ns==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(body.eligible_before_ns)&&
   BigInt(body.eligible_before_ns)<=end&&BigInt(body.eligible_before_ns)<=BigInt(record.expires_ns),'approval_expiry');
 }else need(['blocked','unavailable'].includes(body.local_eligibility)&&body.eligible_before_ns===null,'approval_state');
 return body;
}
