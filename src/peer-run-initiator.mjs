import {same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingInteger as integer,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {runApprovalReference} from './peer-run-approval.mjs';

const hash=value=>typeof value==='string'&&/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(value);
const revision=value=>typeof value==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(value);
export function runArmOperationReference(value){
 fields(value,'kind,scope,object_id,revision,digest');fields(value.scope,'authority_service_id,database_instance_id');
 Object.values(value.scope).forEach(uuid);uuid(value.object_id);
 need(value.kind==='run_arm_operation'&&value.revision==='1'&&hash(value.digest),'run_initiator_reference');return value;
}
export function runInitiatorReadRequest(id,operationDigest,challenge){
 uuid(id);uuid(challenge);need(hash(operationDigest),'run_initiator_reference');
 return {operation_id:id,operation_digest:operationDigest,challenge_id:challenge};
}
export function runInitiatorReadReply(reply,request,record,seamer,controller){
 fields(reply,'format,challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.format==='leafseamer.run-initiator-response/1'&&reply.challenge_id===request.challenge_id&&
  reply.pair_attempt_id===record.transcript.pair_attempt_id&&reply.transcript_digest===record.transcript_digest,'run_initiator_response');
 const body=reply.body;fields(body,'operation_ref,run_id,definition_id,definition_version,arm_generation,approval_ref,artifact_ref,target_scope,preparation_id,initiator,initiator_authorization_ref,credential,eligible_before_ns');
 const operation=runArmOperationReference(body.operation_ref),approval=runApprovalReference(body.approval_ref),artifact=body.artifact_ref;
 fields(artifact,'kind,scope,object_id,revision,digest');uuid(artifact.object_id);
 for(const id of [body.run_id,body.definition_id,body.preparation_id])uuid(id);
 need(operation.object_id===request.operation_id&&operation.digest===request.operation_digest&&same(operation.scope,seamer)&&
  same(approval.scope,seamer)&&same(body.target_scope,controller)&&artifact.kind==='artifact'&&same(artifact.scope,seamer)&&
  artifact.revision==='1'&&hash(artifact.digest)&&revision(body.definition_version)&&revision(body.arm_generation),'run_initiator_scope');
 const {initiator,initiator_authorization_ref:authRef,credential}=body;
 fields(initiator,'issuer_id,issuer_epoch,principal_id,principal_kind');
 for(const id of [initiator.issuer_id,initiator.issuer_epoch,initiator.principal_id])uuid(id);
 fields(authRef,'id,revision,digest');
 need(initiator.principal_kind==='human'&&authRef.id===operation.object_id&&authRef.revision==='1'&&hash(authRef.digest),'run_initiator_authority');
 fields(credential,'issuer_service_id,token_id,session_id,session_revision,credential_id,policy_revision,scope_digest,recent_before_ns');
 for(const id of [credential.issuer_service_id,credential.token_id,credential.session_id,credential.credential_id])uuid(id);
 const until=integer(body.eligible_before_ns);
 need(credential.issuer_service_id===controller.authority_service_id&&revision(credential.session_revision)&&revision(credential.policy_revision)&&
  hash(credential.scope_digest)&&until>0n&&until<=integer(credential.recent_before_ns)&&until<=integer(record.expires_ns),'run_initiator_authority');
 return body;
}
