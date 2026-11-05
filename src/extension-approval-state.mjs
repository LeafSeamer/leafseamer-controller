import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {requireStaticPermissions} from './extension-capabilities.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('extension_approval_'+code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const exact=(v,keys)=>v&&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
const id=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(v);
const rows=(db,sql,...args)=>{const q=db.prepare(sql),names=q.columns().map(c=>c.name);return q.raw().all(...args).map(row=>Object.fromEntries(names.map((n,i)=>[n,row[i]])));};
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
function read(body,digest){const value=JSON.parse(body);need(canonicalize(value)===body&&hash(value)===digest,'integrity');return value;}
// 内部同writer读取，不是外部授权入口；人员接口在调用前仍须验证真实令牌。
export function extensionApprovalState({db,service,reference,currentReview,currentResolution}){
 const staticCapabilities=Number(service.schema_revision)>=18;
 function device(ref){
  const row=rows(db,'SELECT descriptor_body,descriptor_digest FROM device_record WHERE device_id=?',ref.object_id)[0];need(row,'capability_unavailable');
  const descriptor=read(row.descriptor_body.toString('utf8'),row.descriptor_digest);need(same(reference('device',descriptor.device_id,1,descriptor),ref),'capability_stale');return descriptor;
 }
 function capabilities(permissions,installation,resolution,evidence){
  if(staticCapabilities)return requireStaticPermissions({installation,resolution,evidence,permissions,device});
  for(const permission of permissions){
   need(permission.kind==='device_scope','capability_provider_unavailable');
   for(const ref of permission.scope.devices){
    const descriptor=device(ref);
    need(permission.scope.action_ids.every(key=>descriptor.actions.some(action=>action.action_id===key))&&
     permission.scope.trigger_ids.every(key=>descriptor.triggers.some(trigger=>trigger.trigger_id===key)),'capability_unavailable');
   }
  }
 }
 function approval(ref){
  need(exact(ref,'kind,authority_service_id,database_instance_id,object_id,revision,digest')&&ref.kind==='approval'&&ref.authority_service_id===service.service_id&&
   ref.database_instance_id===service.database_instance_id&&id(ref.object_id)&&ref.revision==='1','binding');
  const row=rows(db,'SELECT * FROM extension_approval WHERE approval_id=?',ref.object_id)[0];need(row,'binding');const record=read(row.body_jcs,row.body_digest);
  need(same(record.approval_ref,ref),'binding');const permissions=read(row.permissions_jcs,row.permissions_digest);need(record.permissions_digest===hash(permissions),'integrity');return {row,record,permissions};
 }
 return Object.freeze({lookup:approval,capabilities,current(approvalRef){
  need(db.inTransaction,'writer_required');const found=approval(approvalRef),deny=rows(db,'SELECT * FROM extension_approval_deny WHERE approval_id=?',found.row.approval_id)[0];
  if(deny){const record=read(deny.body_jcs,deny.body_digest);return frozen({status:'revoked',approval_ref:approvalRef,deny_ref:reference('deny_record',deny.deny_id,1,record)});}
   const review=currentReview(found.record.installation_ref);need(review&&same(review.review_ref,found.record.review_ref),'review_stale');
   if(staticCapabilities){
    const row=rows(db,'SELECT content_jcs,content_digest FROM extension_candidate WHERE installation_id=?',found.row.installation_id)[0],installation=read(row.content_jcs,row.content_digest);
    const document=rows(db,'SELECT * FROM extension_approval_capabilities WHERE approval_id=?',found.row.approval_id)[0];
    if(document)capabilities(found.permissions,installation,currentResolution(found.record.installation_ref).record,read(document.body_jcs,document.body_digest));
    else need(found.permissions.length===0,'capability_unavailable');
   }else capabilities(found.permissions);
   return frozen({status:'approved',approval_ref:approvalRef,record:found.record,permissions:found.permissions});
 }});
}
