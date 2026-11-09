import {memoExecutionRead} from './execution-read-view.mjs';
import {sqliteRows} from './sqlite-rows.mjs';
import crypto from 'node:crypto';
import fs from 'node:fs';
import canonicalize from 'canonicalize';
import {decodeArtifactDocument,artifactImportSelection} from './sdk/artifact-import.mjs';
import {narrowPermissions,reviewNeed as need} from './extension-review-permissions.mjs';
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const exact=(v,keys)=>v&&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
const id=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(v);
const rows=sqliteRows;
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
function readDocument(body,digest){const value=JSON.parse(body);need(canonicalize(value)===body&&'sha256:'+crypto.createHash('sha256').update(body).digest('hex')===digest,'integrity');return value;}
export function extensionReviewStore({db,service,available,reference,source,currentResolution,attachCurrent}){
 const read=(body,digest)=>memoExecutionRead(db,'extension-document',[body,digest],()=>readDocument(body,digest));
 let active=0;
 const policy={format:'leafseamer-extension-review-policy/1',authority_service_id:service.service_id,database_instance_id:service.database_instance_id,
  revision:'1',build_manifest_digest:'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(new URL('./build-manifest.json',import.meta.url))).digest('hex'),
  contract:artifactImportSelection,rule:'fixed-purpose-and-references-subset-collections-nonincreasing-quota-endpoint-closure'};
 const policyId='extension-review.'+hash(policy).slice(7),policyRef=reference('validation_policy',policyId,1,policy);
 const get=request=>rows(db,'SELECT * FROM extension_review_operation WHERE request_id=?',request)[0];
 const prior=input=>{const row=get(input.request_id);if(!row)return null;need(row.input_digest===hash(input)&&row.input_jcs===canonicalize(input),'conflict');return frozen(read(row.result_jcs,row.result_digest));};
 function selected(input){
  const resolution=currentResolution(input.installation_ref);need(resolution&&same(resolution.resolution_ref,input.role_resolution_ref),'resolution_stale');
  need(same(resolution.record.configuration_ref,input.configuration_ref),'configuration');return resolution;
 }
 function savePolicy(){
  const row=rows(db,'SELECT * FROM extension_review_policy WHERE policy_id=?',policyId)[0];
  if(row)need(same(read(row.body_jcs,row.body_digest),policy),'policy');
  else db.prepare('INSERT INTO extension_review_policy VALUES(?,?,?)').run(policyId,canonicalize(policy),hash(policy));
 }
 function currentReview(installationRef){
  need(db.inTransaction,'transaction');const resolution=currentResolution(installationRef);need(resolution,'resolution_stale');const row=rows(db,
   'SELECT r.* FROM extension_review_head h JOIN extension_permission_review r USING(review_id,revision) WHERE h.installation_id=?',resolution.record.installation_id)[0];
  if(!row)return null;const record=read(row.body_jcs,row.body_digest);need(same(record.role_resolution_ref,resolution.resolution_ref)&&same(record.configuration_ref,resolution.record.configuration_ref),'resolution_stale');
  need(row.policy_id===policyId&&same(record.policy_ref,policyRef),'policy');const stored=rows(db,'SELECT * FROM extension_review_policy WHERE policy_id=?',policyId)[0];
  need(stored&&same(read(stored.body_jcs,stored.body_digest),policy),'policy');need(same(record.requested_permissions,resolution.record.permissions),'integrity');
  narrowPermissions(record.requested_permissions,record.proposed_permissions);return frozen({review_ref:record.review_ref,record});
 }
 attachCurrent?.(currentReview);
 return Object.freeze({
  async review(input){
   available();need(exact(input,'request_id,installation_ref,configuration_ref,role_resolution_ref,expected_revision,proposed_permissions')&&id(input.request_id)&&
    typeof input.expected_revision==='string'&&/^(0|[1-9][0-9]{0,3})(?![\s\S])/.test(input.expected_revision)&&Array.isArray(input.proposed_permissions)&&input.proposed_permissions.length<=128,'input');
   const fixed=structuredClone(input);need(Buffer.byteLength(canonicalize(fixed))<=1048576,'capacity');const old=db.transaction(()=>prior(fixed)).immediate();if(old)return old;
   need(active<2,'capacity');++active;
   try{
    const resolution=db.transaction(()=>selected(fixed)).immediate();
    // 使用同一产品Permission定义校验提案，不改变原解析原件或其摘要。
    const proposalBody={...resolution.record,permissions:fixed.proposed_permissions};delete proposalBody.resolution_digest;
    const proposal=await decodeArtifactDocument(Buffer.from(canonicalize({...proposalBody,resolution_digest:hash(proposalBody)})),'RoleResolution');available();
    const proposed=narrowPermissions(resolution.record.permissions,proposal.permissions);
    const installation=db.transaction(()=>{selected(fixed);const row=rows(db,'SELECT content_jcs,content_digest FROM extension_candidate WHERE installation_id=?',resolution.record.installation_id)[0];return read(row.content_jcs,row.content_digest);}).immediate();
    const host=source();need(host&&host.identity.authority_service_id===installation.intake_ref.authority_service_id&&host.identity.database_instance_id===installation.intake_ref.database_instance_id&&
     host.identity.host_installation_id===installation.receipt.host_installation_id,'source');
    const current=await host.describe({intake_id:installation.intake_ref.object_id,target_authority_service_id:service.service_id});available();
    need(current?.status==='available'&&same(current.content?.intake_ref,installation.intake_ref)&&hash(current.content.receipt)===installation.intake_ref.digest,'source_unavailable');
    return db.transaction(()=>{
     const raced=prior(fixed);if(raced)return raced;const latest=selected(fixed);need(same(latest,resolution),'resolution_stale');narrowPermissions(latest.record.permissions,proposed);
     const head=rows(db,'SELECT * FROM extension_review_head WHERE installation_id=?',installation.installation_id)[0],previous=head?.revision??0;
     need(String(previous)===fixed.expected_revision,'stale');need(previous<4096&&db.prepare('SELECT count(*) FROM extension_review_operation').pluck().get()<4096,'capacity');
     const revision=previous+1,reviewId=crypto.randomUUID(),operation=crypto.randomUUID();
     const body={installation_ref:fixed.installation_ref,manifest_digest:resolution.record.manifest_digest,artifact_set_digest:resolution.record.artifact_set_digest,
      configuration_ref:fixed.configuration_ref,requested_permissions:resolution.record.permissions,proposed_permissions:proposed,policy_ref:policyRef,role_resolution_ref:fixed.role_resolution_ref};
     const reviewRef=reference('review',reviewId,revision,body),record={...body,review_ref:reviewRef,content_digest:hash(body)},result={review_ref:reviewRef,record},jcs=canonicalize(record);
     need(db.prepare('SELECT coalesce(sum(length(CAST(body_jcs AS BLOB))),0) FROM extension_permission_review').pluck().get()+Buffer.byteLength(jcs)<=67108864,'capacity');savePolicy();
     db.prepare('INSERT INTO extension_permission_review VALUES(?,?,?,?,?,?,?,?,?)').run(reviewId,revision,installation.installation_id,resolution.record.resolution_id,
      Number(resolution.resolution_ref.revision),policyId,operation,jcs,hash(record));
     if(head)db.prepare('UPDATE extension_review_head SET review_id=?,revision=? WHERE installation_id=?').run(reviewId,revision,installation.installation_id);
     else db.prepare('INSERT INTO extension_review_head VALUES(?,?,?)').run(installation.installation_id,reviewId,revision);
     db.prepare('INSERT INTO extension_review_operation VALUES(?,?,?,?,?,?,?,?,?)').run(fixed.request_id,operation,reviewId,revision,canonicalize(fixed),hash(fixed),canonicalize(result),hash(result),
      canonicalize({kind:'extension_permission_review',operation_id:operation,result_digest:hash(result)}));return frozen(result);
    }).immediate();
   }finally{--active;}
  },
  query(requestId){available();need(id(requestId),'input');return db.transaction(()=>{const row=get(requestId);return row?frozen(read(row.result_jcs,row.result_digest)):null;}).immediate();},
  current(installationRef){available();return db.transaction(()=>currentReview(installationRef)).immediate();}
 });
}
