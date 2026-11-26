import {digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {endorsementReference} from './peer-run-approval-endorsement.mjs';
import {runApprovalReference} from './peer-run-approval.mjs';
import {proposalReference} from './peer-run-approval-proposal.mjs';
import {runArmOperationReference,runRecoveryOperationReference} from './peer-run-initiator.mjs';

const hash=value=>typeof value==='string'&&value.length===71&&/^sha256:[0-9a-f]{64}$/.test(value);
function generation(value){
 fields(value,'arm_generation,run_id');uuid(value.run_id);
 need(typeof value.arm_generation==='string'&&/^[1-9][0-9]{0,19}$/.test(value.arm_generation)&&!/\s/.test(value.arm_generation),'approval_protection_targets');
 return `${value.run_id}:${value.arm_generation}`;
}
function distinct(values,key){
 need(Array.isArray(values)&&values.length<=16,'approval_protection_targets');
 const keys=values.map(key);
 need(new Set(keys).size===keys.length,'approval_protection_targets');return keys;
}

export function approvalProtectionNotice(value){
 fields(value,'approval_ref,arm_generations,endorsement_ref,grants,kind,origin_scope,preparations,revocation_operation_ref,target_scope');
 const approval=runApprovalReference(value.approval_ref),endorsement=endorsementReference(value.endorsement_ref);
 const operation=value.revocation_operation_ref;
 fields(operation,'digest,kind,object_id,revision,scope');uuid(operation.object_id);
 need(operation.kind==='run_approval_operation'&&operation.revision==='1'&&typeof operation.digest==='string'&&operation.digest.length===71&&
  /^sha256:[0-9a-f]{64}$/.test(operation.digest)&&same(operation.scope,approval.scope)&&same(value.origin_scope,approval.scope)&&
  same(value.target_scope,endorsement.scope)&&value.kind==='run_approval_revocation','approval_protection_notice');
 const generations=distinct(value.arm_generations,generation);
 const preparations=distinct(value.preparations,entry=>{
  fields(entry,'arm_generation,operation_ref,preparation_id,request_digest,run_id');uuid(entry.preparation_id);
  const {run_id,arm_generation,operation_ref,request_digest}=entry;
  const operation=(operation_ref?.kind==='recovery_operation'?runRecoveryOperationReference:runArmOperationReference)(operation_ref);
  need(generations.includes(generation({run_id,arm_generation}))&&same(operation.scope,value.origin_scope)&&
   (request_digest===null||hash(request_digest)),'approval_protection_targets');return entry.preparation_id;
 });
 distinct(value.grants,entry=>{
  fields(entry,'grant_ref,preparation_id');uuid(entry.preparation_id);
  const ref=entry.grant_ref;fields(ref,'digest,kind,object_id,revision,scope');uuid(ref.object_id);
  need(preparations.includes(entry.preparation_id)&&value.preparations.find(item=>item.preparation_id===entry.preparation_id).request_digest!==null&&
   ref.kind==='grant'&&ref.revision==='1'&&hash(ref.digest)&&same(ref.scope,value.target_scope),'approval_protection_targets');return entry.preparation_id;
 });
 need(new Set(value.grants.map(entry=>entry.grant_ref.object_id)).size===value.grants.length,'approval_protection_targets');
 return value;
}

export function approvalProtectionReceipt(value,notice){
 fields(value,'approval_ref,endorsement_ref,format,identity_state,protection_state,receipt_id,request_digest,revocation_operation_ref,target_scope');uuid(value.receipt_id);
 need(value.format==='leafseamer.run-approval-rejection/1'&&same(value.target_scope,notice.target_scope)&&same(value.approval_ref,notice.approval_ref)&&
  same(value.endorsement_ref,notice.endorsement_ref)&&same(value.revocation_operation_ref,notice.revocation_operation_ref)&&
  value.request_digest===digest(notice)&&value.identity_state==='denied'&&value.protection_state==='pending','approval_protection_receipt');
 return value;
}

export const runApprovalProtectionVersion='run-approval-protection/1';
export const runApprovalProtectionObservationVersion='run-approval-protection-observation/1';
export function runApprovalProtectionObservation(value,notice,challenge){
 fields(value,'challenge_id,completion,format,request_digest,state');
 uuid(challenge);
 need(value.format==='leafseamer.run-approval-protection-observation/1'&&value.challenge_id===challenge&&
  value.request_digest===digest(notice),'approval_protection_observation');
 if(value.state==='verified'||value.state==='indeterminate'){
  need(runApprovalProtectionReply(value.completion,notice,{completion:true}).protection_state==='applied','approval_protection_observation');
 }else need(['not_found','pending'].includes(value.state)&&value.completion===null,'approval_protection_observation');
 return value;
}
export function runApprovalProtectionReply(value,notice,{completion=false}={}){
 if(!completion||value?.format!=='leafseamer.run-approval-protection/1')return approvalProtectionReceipt(value,notice);
 fields(value,'deny_through_generation,device_ids,format,proof_digest,protection_state,receipt_id,rejection,run_id');
 uuid(value.receipt_id);uuid(value.run_id);
 const rejection=approvalProtectionReceipt(value.rejection,notice);
 const floor=value.deny_through_generation;
 if(floor!==null)generation({arm_generation:floor,run_id:value.run_id});
 const validGeneration=floor===null?notice.arm_generations.length===0:
  notice.arm_generations.every(entry=>entry.run_id===value.run_id&&BigInt(entry.arm_generation)<=BigInt(floor));
 need(value.protection_state==='applied'&&value.receipt_id!==rejection.receipt_id&&hash(value.proof_digest)&&
  Array.isArray(value.device_ids)&&value.device_ids.length>=1&&value.device_ids.length<=256&&validGeneration,
 'approval_protection_completion');
 value.device_ids.forEach((id,index)=>{uuid(id);need(index===0||value.device_ids[index-1]<id,'approval_protection_completion');});
 return value;
}

export function endorsementRevocationNotice(value){
 fields(value,'deny_revision,endorsement_ref,kind,origin_scope,proposal_ref,revocation_operation_ref,target_scope');
 const endorsement=endorsementReference(value.endorsement_ref),proposal=proposalReference(value.proposal_ref),operation=value.revocation_operation_ref;
 fields(operation,'digest,kind,object_id,revision,scope');uuid(operation.object_id);
 need(value.kind==='run_approval_endorsement_revoked'&&value.deny_revision==='2'&&operation.kind==='run_approval_operation'&&
  operation.revision==='1'&&typeof operation.digest==='string'&&operation.digest.length===71&&/^sha256:[0-9a-f]{64}$/.test(operation.digest)&&
  same(endorsement.scope,value.origin_scope)&&same(operation.scope,value.origin_scope)&&same(proposal.scope,value.target_scope),'endorsement_revocation_notice');
 return value;
}

export function endorsementRevocationReceipt(value,notice){
 fields(value,'endorsement_ref,format,identity_state,proposal_ref,protection_operation_ref,receipt_id,request_digest,revocation_operation_ref,target_scope');
 uuid(value.receipt_id);const protection=value.protection_operation_ref;
 if(protection!==null){
  fields(protection,'digest,kind,object_id,revision,scope');uuid(protection.object_id);
  need(protection.kind==='run_approval_operation'&&protection.revision==='1'&&typeof protection.digest==='string'&&
   protection.digest.length===71&&/^sha256:[0-9a-f]{64}$/.test(protection.digest)&&same(protection.scope,value.target_scope),'endorsement_revocation_receipt');
 }
 need(value.format==='leafseamer.run-endorsement-rejection/1'&&value.identity_state==='denied'&&same(value.target_scope,notice.target_scope)&&
  same(value.proposal_ref,notice.proposal_ref)&&same(value.endorsement_ref,notice.endorsement_ref)&&
  same(value.revocation_operation_ref,notice.revocation_operation_ref)&&value.request_digest===digest(notice),'endorsement_revocation_receipt');return value;
}
