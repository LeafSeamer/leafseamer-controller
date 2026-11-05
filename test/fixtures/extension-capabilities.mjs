import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import {prepared} from './extension-role.mjs';
const template=JSON.parse(await fs.readFile(new URL('./static-capability.json',import.meta.url),'utf8'));
export async function setup(t,{mutate=()=>{},response=answer=>answer,revision=18,recheck=()=>{},prepareHost=()=>{},prepareBindings=()=>{}}={}){
 const f=await prepared(t,{revision,recheck,prepareHost(host){
  const document=structuredClone(template);mutate(document);const bytes=Buffer.from(JSON.stringify(document));
  const file={file_id:'capability',path:'capability.json',size_bytes:String(bytes.length),digest:'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex'),role:'schema',executable:false};
  host.content.inventory.files.push(file);host.content.inventory.files.sort((a,b)=>a.file_id<b.file_id?-1:1);host.content.manifest.capability_template_file_ids=['capability'];prepareHost(host);
  host.describeCapabilityTemplates=async()=>response({status:'available',content:{format:'leafseamer-capability-template-files/1',intake_ref:host.content.intake_ref,
   manifest_digest:host.content.receipt.manifest_digest,artifact_set_digest:host.content.receipt.artifact_set_digest,files:[{file,bytes}]}});
 }});await prepareBindings(f);const resolved=await f.api.roles.resolve(f.request),proposed=structuredClone(resolved.record.permissions);proposed[0].scope.action_ids=['get'];
 const reviewed=await f.api.reviews.review({request_id:'review',installation_ref:f.installed.installation_ref,configuration_ref:f.config.configuration_ref,
  role_resolution_ref:resolved.resolution_ref,expected_revision:'0',proposed_permissions:proposed});
 return {...f,reviewed,proposed,request:{request_id:'approve',installation_ref:f.installed.installation_ref,permission_review_ref:reviewed.review_ref,
  configuration_ref:f.config.configuration_ref,approved_permission_ids:['device.request']}};
}
