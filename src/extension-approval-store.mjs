import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {narrowPermissions} from './extension-review-permissions.mjs';
import {readStaticCapabilities} from './extension-capabilities.mjs';
import {extensionApprovalState} from './extension-approval-state.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('extension_approval_'+code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const exact=(v,keys)=>v&&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
const id=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(v);
const rows=(db,sql,...args)=>{const q=db.prepare(sql),names=q.columns().map(c=>c.name);return q.raw().all(...args).map(row=>Object.fromEntries(names.map((n,i)=>[n,row[i]])));};
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
function read(body,digest){const value=JSON.parse(body);need(canonicalize(value)===body&&hash(value)===digest,'integrity');return value;}
// 仅由真实sessionStore装配authorize，业务调用不能传actor或自报人员身份。
export function extensionApprovalStore({db,service,available,reference,source,currentReview,currentResolution,authorize}){
 let active=0;const staticCapabilities=Number(service.schema_revision)>=18;
 const actor=proof=>({principal_id:proof.principal_id,session_id:proof.session_id,credential_id:proof.credential_id,issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch});
 const get=(credential,request)=>rows(db,'SELECT * FROM extension_approval_operation WHERE credential_id=? AND request_id=?',credential,request)[0];
 function prior(input){const row=get(input.actor.credential_id,input.request_id);if(!row)return null;need(row.input_digest===hash(input)&&same(read(row.input_jcs,row.input_digest),input),'conflict');return frozen(read(row.result_jcs,row.result_digest));}
 function selected(input){
  const review=currentReview(input.installation_ref);need(review&&same(review.review_ref,input.permission_review_ref)&&same(review.record.configuration_ref,input.configuration_ref),'review_stale');
  need(input.approved_permission_ids.every((value,i)=>id(value)&&(i===0||value>input.approved_permission_ids[i-1])),'permission_ids');
  const byId=new Map(review.record.proposed_permissions.map(p=>[p.request_id,p])),permissions=input.approved_permission_ids.map(key=>byId.get(key));
  need(permissions.every(Boolean),'permission_ids');narrowPermissions(review.record.requested_permissions,permissions);return {review,permissions};
 }
 const state=extensionApprovalState({db,service,reference,currentReview,currentResolution}),approval=state.lookup,capabilities=state.capabilities;
 function reserve(){need(db.prepare('SELECT count(*) FROM extension_approval_operation').pluck().get()<4096,'capacity');}
 function operation(input){const body={operation_id:crypto.randomUUID(),kind:input.kind,authority_service_id:service.service_id,database_instance_id:service.database_instance_id,input};
  return {body,ref:reference('installation_operation',body.operation_id,1,body)};}
 function save(input,operation,approvalId,result,proof){
  const text=canonicalize(result);need(Buffer.byteLength(text)<=4194304&&db.prepare('SELECT coalesce(sum(length(CAST(result_jcs AS BLOB))),0) FROM extension_approval_operation').pluck().get()+Buffer.byteLength(text)<=67108864,'capacity');
  db.prepare('INSERT INTO extension_approval_operation VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(input.actor.credential_id,input.request_id,operation.body.operation_id,input.kind,approvalId,
   input.actor.principal_id,input.actor.session_id,canonicalize(input),hash(input),canonicalize(operation.body),hash(operation.body),text,hash(result),
   canonicalize({kind:'extension_'+input.kind,operation_id:operation.body.operation_id,result_digest:hash(result),actor:input.actor,authorization_digest:proof.authorization_digest,acquisition_ref:proof.acquisition_ref}));return frozen(result);
 }
 async function currentSource(installation){
  const host=source();need(host&&host.identity.authority_service_id===installation.intake_ref.authority_service_id&&host.identity.database_instance_id===installation.intake_ref.database_instance_id&&
   host.identity.host_installation_id===installation.receipt.host_installation_id,'source');
  const result=await host.describe({intake_id:installation.intake_ref.object_id,target_authority_service_id:service.service_id});available();
  need(result?.status==='available'&&same(result.content?.intake_ref,installation.intake_ref)&&hash(result.content.receipt)===installation.intake_ref.digest,'source_unavailable');
 }
 return Object.freeze({
  async approve(token,input){
   available();need(exact(input,'request_id,installation_ref,permission_review_ref,configuration_ref,approved_permission_ids')&&id(input.request_id)&&Array.isArray(input.approved_permission_ids)&&input.approved_permission_ids.length<=128,'input');
   const credential=structuredClone(token),request=structuredClone(input);need(Buffer.byteLength(canonicalize(request))<=1048576,'capacity');
   const initial=db.transaction(()=>{const proof=authorize(credential,'extension.manage',true),fixed={...request,kind:'approve',actor:actor(proof)},old=prior(fixed);if(old)return {old};
    const chosen=selected(fixed);if(!staticCapabilities)capabilities(chosen.permissions);need(!db.prepare('SELECT 1 FROM extension_approval WHERE installation_id=?').pluck().get(fixed.installation_ref.object_id),'frozen');
    const row=rows(db,'SELECT content_jcs,content_digest FROM extension_candidate WHERE installation_id=?',fixed.installation_ref.object_id)[0];return {fixed,chosen,installation:read(row.content_jcs,row.content_digest)};
   }).immediate();if(initial.old)return initial.old;need(active<2,'capacity');++active;
   try{
    const evidence=staticCapabilities?await readStaticCapabilities(initial.installation,source()):null;available();
    await currentSource(initial.installation);return db.transaction(()=>{
    const proof=authorize(credential,'extension.manage',true);need(same(actor(proof),initial.fixed.actor),'actor');const old=prior(initial.fixed);if(old)return old;
    reserve();need(!db.prepare('SELECT 1 FROM extension_approval WHERE installation_id=?').pluck().get(initial.installation.installation_id),'frozen');
    const chosen=selected(initial.fixed);need(same(chosen,initial.chosen),'review_stale');
    capabilities(chosen.permissions,initial.installation,staticCapabilities?currentResolution(initial.fixed.installation_ref).record:null,evidence);
    const op=operation(initial.fixed),approvalId=crypto.randomUUID(),review=chosen.review.record;
    const body={installation_ref:initial.fixed.installation_ref,review_ref:chosen.review.review_ref,approved_permission_ids:initial.fixed.approved_permission_ids,
     configuration_ref:initial.fixed.configuration_ref,manifest_digest:review.manifest_digest,artifact_set_digest:review.artifact_set_digest,
     platform_profile_ref:initial.installation.receipt.platform_profile_ref,approval_operation_ref:op.ref,revoked_by:null,
     role_resolution_ref:review.role_resolution_ref,permissions_digest:hash(chosen.permissions)};
    const ref=reference('approval',approvalId,1,body),record={...body,approval_ref:ref},result={approval_ref:ref,record,permissions:chosen.permissions};
    db.prepare('INSERT INTO extension_approval VALUES(?,?,?,?,?,?,?,?,?)').run(approvalId,initial.installation.installation_id,review.review_ref.object_id,Number(review.review_ref.revision),op.body.operation_id,
     canonicalize(record),hash(record),canonicalize(chosen.permissions),hash(chosen.permissions));
    if(staticCapabilities){const text=canonicalize(evidence);need(Buffer.byteLength(text)<=2097152&&db.prepare('SELECT coalesce(sum(length(CAST(body_jcs AS BLOB))),0) FROM extension_approval_capabilities').pluck().get()+Buffer.byteLength(text)<=67108864,'capacity');
     db.prepare('INSERT INTO extension_approval_capabilities VALUES(?,?,?)').run(approvalId,text,hash(evidence));}
    const resultValue=save(initial.fixed,op,approvalId,result,proof);authorize(credential,'extension.manage',true);return resultValue;
   }).immediate();}finally{--active;}
  },
  revoke(token,input){
   available();need(exact(input,'request_id,approval_ref,reason')&&id(input.request_id)&&typeof input.reason==='string'&&input.reason.length>0&&Buffer.byteLength(input.reason)<=1024,'input');
   const request=structuredClone(input);return db.transaction(()=>{
    const proof=authorize(token,'extension.manage',true),fixed={...request,kind:'revoke',actor:actor(proof)},old=prior(fixed);if(old)return old;reserve();const found=approval(request.approval_ref),op=operation(fixed);
    let row=rows(db,'SELECT * FROM extension_approval_deny WHERE approval_id=?',found.row.approval_id)[0],result;
    if(row){const record=read(row.body_jcs,row.body_digest);result={deny_ref:reference('deny_record',row.deny_id,1,record),record};}
    else{const denyId=crypto.randomUUID(),record={deny_id:denyId,approval_ref:request.approval_ref,installation_ref:found.record.installation_ref,reason:request.reason,operation_ref:op.ref};
     db.prepare('INSERT INTO extension_approval_deny VALUES(?,?,?,?,?)').run(denyId,found.row.approval_id,op.body.operation_id,canonicalize(record),hash(record));result={deny_ref:reference('deny_record',denyId,1,record),record};}
    const resultValue=save(fixed,op,found.row.approval_id,result,proof);authorize(token,'extension.manage',true);return resultValue;
   }).immediate();
  },
  query(token,requestId){available();need(id(requestId),'input');return db.transaction(()=>{const proof=authorize(token,'extension.read',false),row=get(proof.credential_id,requestId);return row?frozen(read(row.result_jcs,row.result_digest)):null;}).immediate();},
  current(token,approvalRef){available();return db.transaction(()=>{authorize(token,'extension.read',false);return state.current(approvalRef);}).immediate();}
 });
}
