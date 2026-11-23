import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {approvalProtectionNotice,approvalProtectionReceipt} from './peer-run-approval-protection.mjs';
import {pairingUuid as uuid} from './peer-pairing-value.mjs';

const format='leafseamer.run-approval-protection-work/1';
const rejectionFormat='leafseamer.run-approval-rejection/1';
const need=(ok,code)=>{if(!ok)throw new IdentityError('run_generation_denial_'+code);};
const floor=value=>{
 need(typeof value==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(value),'generation');return value.padStart(20,'0');
};
const key=scope=>[scope.authority_service_id,scope.database_instance_id];

function readWork(row,controller){
 need(row,'original');
 const [service,database,approvalId,operationId,requestDigest,receiptId,text,checksum]=row;
 const body=JSON.parse(text);
 need(canonical(body)===text&&digest(body)===checksum,'original');
 let {notice,receipt,local_targets}=body;
 if(body.format===rejectionFormat){
  const {approval_ref,endorsement_ref,revocation_operation_ref,target_scope}=body;
  notice={kind:'run_approval_revocation',origin_scope:approval_ref.scope,target_scope,approval_ref,endorsement_ref,revocation_operation_ref,
   arm_generations:[],preparations:[],grants:[]};
  receipt=body;local_targets=[];
 }else need(body.format===format&&Array.isArray(local_targets),'original');
 approvalProtectionNotice(notice);approvalProtectionReceipt(receipt,notice);
 need(same(key(notice.origin_scope),[service,database])&&same(notice.target_scope,controller)&&notice.approval_ref.object_id===approvalId&&
  notice.revocation_operation_ref.object_id===operationId&&receipt.receipt_id===receiptId&&receipt.request_digest===requestDigest,'original');
 const generations=new Map();
 for(const {run_id,arm_generation} of [...notice.arm_generations,...local_targets]){
  uuid(run_id);const next=floor(arm_generation);
  if(next>(generations.get(run_id)??''))generations.set(run_id,next);
 }
 return {notice,receipt,checksum,generations,local_targets};
}

const protectionRows=`SELECT origin_service_id,origin_database_instance_id,approval_id,operation_id,request_digest,receipt_id,body_jcs,body_digest
 FROM run_approval_rejection`;
const generationRows=`${protectionRows} WHERE json_extract(body_jcs,'$.format')='${format}'`;
const latest=`SELECT deny_revision,floor FROM run_generation_denial WHERE origin_service_id=? AND origin_database_instance_id=? AND run_id=?
 ORDER BY deny_revision DESC LIMIT 1`;

function append(db,controller,row){
 const {notice,generations}=readWork(row,controller);
 const origin=key(notice.origin_scope),approval=notice.approval_ref.object_id;
 for(const [runId,next] of generations){
  const [revision=0,previous='']=db.prepare(latest).raw().get(...origin,runId)??[];
  if(next<=previous)continue;
  const result=db.prepare(`INSERT INTO run_generation_denial VALUES(
   (SELECT coalesce(max(snapshot_revision),0)+1 FROM run_generation_denial),?,?,?,?,?,?,?)`)
   .run(...origin,runId,revision+1,next,approval,row[7]);
  need(result.changes===1,'storage');
 }
}

export function adoptRunGenerationDenial(db,controller,origin,approvalId){
 need(db.inTransaction,'writer');
 const row=db.prepare(generationRows+' AND origin_service_id=? AND origin_database_instance_id=? AND approval_id=?').raw().get(...key(origin),approvalId);
 if(row)append(db,controller,row);
}

export function readRunProtectionWork(db,controller,receiptId){
 need(db.inTransaction,'writer');
 return readWork(db.prepare(protectionRows+' WHERE receipt_id=?').raw().get(receiptId),controller);
}

export function scanRunProtectionWork(db,after,limit,{completion=false}={}){
 need(db.inTransaction,'writer');
 const formats=completion?[format,rejectionFormat]:[format];
 const pending=completion?'AND NOT EXISTS(SELECT 1 FROM run_approval_protection_completion c WHERE c.rejection_id=r.receipt_id)':'';
 const rows=db.prepare(`SELECT receipt_id FROM run_approval_rejection r WHERE receipt_id>? COLLATE BINARY
  AND json_extract(body_jcs,'$.format') IN (${formats.map(()=>'?').join(',')}) ${pending}
  ORDER BY receipt_id COLLATE BINARY LIMIT ?`).pluck().all(after??'',...formats,limit+1);
 return {items:rows.slice(0,limit),next:rows.length>limit?rows[limit-1]:null};
}

export function restoreRunGenerationDenials(db,controller){
 need(db.inTransaction,'writer');
 for(const row of db.prepare(generationRows+' ORDER BY receipt_id COLLATE BINARY').raw().all())append(db,controller,row);
}

export function runGenerationDenied(db,origin,runId,generation){
 need(db.inTransaction,'writer');
 const row=db.prepare(latest).raw().get(...key(origin),runId);
 return !!row&&floor(generation)<=row[1];
}

export function captureRunDenySnapshot(db,controller,at){
 need(db.inTransaction,'writer');
 const head=db.prepare('SELECT coalesce(max(snapshot_revision),0) FROM run_generation_denial').pluck().get();
 const revision=at??head;
 need(Number.isSafeInteger(revision)&&revision>=0&&revision<=head,'snapshot_revision');
 const rows=db.prepare(`WITH current AS (
   SELECT origin_service_id,origin_database_instance_id,run_id,max(deny_revision) AS deny_revision
    FROM run_generation_denial WHERE snapshot_revision<=? GROUP BY origin_service_id,origin_database_instance_id,run_id)
  SELECT d.origin_service_id,d.origin_database_instance_id,d.run_id,d.deny_revision,d.floor
  FROM current JOIN run_generation_denial d USING(origin_service_id,origin_database_instance_id,run_id,deny_revision)
  ORDER BY d.origin_service_id COLLATE BINARY,d.origin_database_instance_id COLLATE BINARY,d.run_id COLLATE BINARY LIMIT 4097`).raw().all(revision);
 need(rows.length<=4096,'snapshot_capacity');
 const entries=rows.map(([authority_service_id,database_instance_id,run_id,revision,floor])=>({
  selector:{kind:'run_generation',origin_scope:{authority_service_id,database_instance_id},run_id,deny_through_generation:String(BigInt(floor))},deny_revision:String(revision)}));
 const body={controller_scope:controller,snapshot_revision:String(revision),entries};return {...body,snapshot_digest:digest(body)};
}
