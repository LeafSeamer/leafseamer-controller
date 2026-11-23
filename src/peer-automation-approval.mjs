import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingInteger as integer,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';

function reference(ref){
 fields(ref,'id,revision,digest');uuid(ref.id);
 need(integer(ref.revision)>0n&&typeof ref.digest==='string'&&/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(ref.digest),'automation_approval_reference');
}
export function automationApprovalRequest(input){
 fields(input,'format,challenge_id,principal,approval_ref');
 need(input.format==='leafseamer.automation-approval-request/1','version');uuid(input.challenge_id);
 fields(input.principal,'issuer_id,issuer_epoch,principal_id');Object.values(input.principal).forEach(uuid);reference(input.approval_ref);
 return input;
}
export function automationApprovalReply(reply,request,record){
 fields(reply,'format,challenge_id,pair_attempt_id,transcript_digest,body');
 need(reply.format==='leafseamer.automation-approval-response/1'&&reply.challenge_id===request.challenge_id&&
  reply.pair_attempt_id===record.transcript.pair_attempt_id&&reply.transcript_digest===record.transcript_digest,'automation_approval_response');
 const body=reply.body;fields(body,'issuer_scope,subject_ref,approval_ref,approval');
 const controller=record.transcript.parties.find(p=>p.service_kind==='controller'),seamer=record.transcript.parties.find(p=>p.service_kind==='seamer');
 need(controller&&seamer&&controller.issuer_id===request.principal.issuer_id&&controller.issuer_epoch===request.principal.issuer_epoch&&
  same(body.issuer_scope,{authority_service_id:controller.service_id,database_instance_id:controller.database_instance_id}),'automation_approval_issuer');
 reference(body.subject_ref);reference(body.approval_ref);
 const approval=body.approval;fields(approval,'format,id,revision,digest,principal_id,issuer_id,issuer_epoch,audiences,permissions,device_ids,automation_origin,approval_operation_id,not_before_ns,expires_ns,approved_by,acquisition_ref');
 const {digest:hash,...original}=approval,origin=approval.automation_origin;
 fields(origin,'seamer_scope,pairing_ref,device_scope');reference(origin.pairing_ref);uuid(approval.approval_operation_id);
 need(approval.format==='local-service-approval/3'&&body.subject_ref.id===request.principal.principal_id&&approval.principal_id===body.subject_ref.id&&
  approval.issuer_id===request.principal.issuer_id&&approval.issuer_epoch===request.principal.issuer_epoch&&digest(original)===hash&&
  same(body.approval_ref,request.approval_ref)&&same(body.approval_ref,{id:approval.id,revision:approval.revision,digest:hash}), 'automation_approval_body');
 need(same(origin.seamer_scope,{authority_service_id:seamer.service_id,database_instance_id:seamer.database_instance_id})&&
  origin.pairing_ref.id===controller.binding_id&&digest(origin.device_scope)===seamer.object_scope_digest&&same(approval.audiences,[controller.service_id])&&
  Array.isArray(approval.permissions)&&approval.permissions.includes('automation.prepare')&&approval.permissions.every(p=>seamer.permissions.includes(p))&&
  Array.isArray(origin.device_scope?.device_ids)&&Array.isArray(approval.device_ids)&&approval.device_ids.every(id=>origin.device_scope.device_ids.includes(id))&&
  integer(approval.not_before_ns)<integer(approval.expires_ns),'automation_approval_scope');
 need(Buffer.byteLength(canonical(reply))<=16384,'capacity');
 return body;
}
