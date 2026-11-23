import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {runApprovalProtectionReply} from './peer-run-approval-protection.mjs';
import {readRunProtectionExits} from './run-protection-exits.mjs';
import {runGenerationDenied} from './run-generation-denial.mjs';
import {startOutboxDelivery} from './session-denial-delivery.mjs';

const need=(ok,code)=>{if(!ok)throw new IdentityError('run_protection_completion_'+code);};
const fenceEvidence='leafseamer.run-approval-protection-evidence/1';
const unpreparedEvidence='leafseamer.run-approval-protection-no-preparation/1';
const unpreparedTargets=ids=>ids.map(device_id=>({device_id,state:'never_prepared'}));
function document(text,checksum){
 const value=JSON.parse(text);need(canonical(value)===text&&digest(value)===checksum,'integrity');return value;
}
export function readRunProtectionCompletion(db,notice,rejection,checksum){
 need(db.inTransaction,'writer');
 const row=db.prepare('SELECT receipt_id,rejection_digest,proof_jcs,proof_digest,body_jcs,body_digest FROM run_approval_protection_completion WHERE rejection_id=?')
  .raw().get(rejection.receipt_id);
 if(!row)return null;
 const [id,sourceDigest,proofText,proofDigest,text,bodyDigest]=row,proof=document(proofText,proofDigest);
 const body=runApprovalProtectionReply(document(text,bodyDigest),notice,{completion:true});
 need(sourceDigest===checksum&&same(body.rejection,rejection)&&body.receipt_id===id&&body.proof_digest===proofDigest&&
  proof.rejection_digest===sourceDigest&&
  same(proof.plan.origin_scope,notice.origin_scope)&&proof.plan.run_id===body.run_id&&proof.plan.deny_through_generation===body.deny_through_generation&&
  same(proof.plan.device_ids,body.device_ids),'integrity');
 if(body.deny_through_generation===null){
  need(proof.format===unpreparedEvidence&&same(proof.targets,unpreparedTargets(body.device_ids)),'integrity');
 }else{
  need(proof.format===fenceEvidence&&same(proof.targets.map(target=>target.device_id),body.device_ids)&&
   proof.targets.every(target=>target.state==='acknowledged'&&target.exits.length>0&&target.exits.every(exit=>exit.state!=='pending')),'integrity');
 }
 return body;
}
export function commitRunProtectionCompletion(db,work,plan){
 need(db.inTransaction,'writer');
 const {notice,receipt:rejection,checksum,generations,local_targets}=work;
 const old=readRunProtectionCompletion(db,notice,rejection,checksum);
 if(old)return {state:'acknowledged',receipt:old};
 need(same(notice.origin_scope,plan.origin_scope),'source');
 let format,targets;
 if(plan.deny_through_generation===null){
  need(generations.size===0&&local_targets.length===0&&notice.arm_generations.length===0,'source');
  const {authority_service_id,database_instance_id}=notice.origin_scope;
  // Grants and preparation commits require a preparation row. The rejection and its insert trigger block future rows for this approval.
  const prepared=db.prepare(`SELECT 1 FROM run_preparation WHERE origin_service_id=? AND origin_database_instance_id=? AND approval_id=? LIMIT 1`)
   .pluck().get(authority_service_id,database_instance_id,notice.approval_ref.object_id);
  if(prepared)return {state:'pending',receipt:null};
  format=unpreparedEvidence;targets=unpreparedTargets(plan.device_ids);
 }else{
  need(generations.size===1&&generations.get(plan.run_id)===plan.deny_through_generation.padStart(20,'0')&&
   runGenerationDenied(db,plan.origin_scope,plan.run_id,plan.deny_through_generation),'source');
  format=fenceEvidence;targets=plan.device_ids.map(deviceId=>readRunProtectionExits(db,deviceId,plan));
  if(!targets.every(target=>target.state==='acknowledged'))return {state:'pending',receipt:null};
 }
 const proof={format,rejection_digest:checksum,plan,targets};
 const receipt=runApprovalProtectionReply({format:'leafseamer.run-approval-protection/1',protection_state:'applied',
  receipt_id:crypto.randomUUID(),rejection,run_id:plan.run_id,deny_through_generation:plan.deny_through_generation,
  device_ids:plan.device_ids,proof_digest:digest(proof)},notice,{completion:true});
 const text=canonical(proof);need(Buffer.byteLength(text)<=4194304,'capacity');
 need(db.prepare('INSERT INTO run_approval_protection_completion VALUES(?,?,?,?,?,?,?)')
  .run(rejection.receipt_id,receipt.receipt_id,checksum,text,receipt.proof_digest,canonical(receipt),digest(receipt)).changes===1,'storage');
 return {state:'delivered',receipt:readRunProtectionCompletion(db,notice,rejection,checksum)};
}

export function startRunProtectionDelivery({endorsements,workerLaunches,assertCurrent}){
 if(!endorsements?.scanRunProtection||!workerLaunches?.applyRunProtection)return null;
 return startOutboxDelivery({scan(request){assertCurrent();return endorsements.scanRunProtection(request);},
  async deliver(receiptId){
   assertCurrent();const plan=endorsements.runProtectionPlan(receiptId);
   if(plan.deny_through_generation===null)return endorsements.completeRunProtection(receiptId).state;
   const result=await workerLaunches.applyRunProtection(plan,assertCurrent);
   assertCurrent();
   return result.state==='acknowledged'&&endorsements.completeRunProtection?endorsements.completeRunProtection(receiptId).state:result.state;
  },pageSize:4});
}
