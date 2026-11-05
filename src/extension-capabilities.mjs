import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {decodeCapabilityTemplate,capabilityTemplateSelection} from './sdk/capability-template.mjs';
import {validateSchemaDocuments} from './configuration-validator.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('extension_capability_'+code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const rawHash=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
export async function readStaticCapabilities(installation,host){
 const ids=installation.manifest.capability_template_file_ids,expected=installation.inventory.files.filter(file=>ids.includes(file.file_id));
 need(expected.length===ids.length&&expected.every(file=>file.role==='schema')&&expected.reduce((n,file)=>n+BigInt(file.size_bytes),0n)<=1048576n,'capacity');
 let files=[];
 if(ids.length){
  need(host?.capabilities,'source');const response=await host.capabilities({intake_id:installation.intake_ref.object_id,target_authority_service_id:installation.receipt.target_authority_service_id});
  need(response?.status==='available','source_unavailable');const content=response.content;
  need(content?.format==='leafseamer-capability-template-files/1'&&same(content.intake_ref,installation.intake_ref)&&content.manifest_digest===installation.receipt.manifest_digest&&
   content.artifact_set_digest===installation.receipt.artifact_set_digest&&Array.isArray(content.files)&&content.files.length===expected.length,'binding');
  files=content.files.map((document,index)=>{need(same(document.file,expected[index])&&(Buffer.isBuffer(document.bytes)||document.bytes instanceof Uint8Array),'binding');
   const bytes=Buffer.from(document.bytes);need(bytes.length<=1048576&&String(bytes.length)===expected[index].size_bytes&&rawHash(bytes)===expected[index].digest,'binding');return {file:structuredClone(document.file),bytes};});
 }
 const documents=[],templateIds=new Set(),roles=new Set(),schemas=new Map();
 const schema=value=>{need(hash(value.document)===value.digest,'schema_digest');const old=schemas.get(value.schema_id);need(!old||same(old,value),'schema_identity');schemas.set(value.schema_id,value);need(schemas.size<=256,'capacity');};
 for(const file of files){
  const template=await decodeCapabilityTemplate(file.bytes),key=template.device_role+'/'+template.device_kind;
  need(!templateIds.has(template.template_id)&&!roles.has(key),'template_identity');templateIds.add(template.template_id);roles.add(key);
  need(installation.manifest.roles.some(role=>role.role_id===template.device_role&&role.kind==='device'),'role');schema(template.state_schema);
  for(const action of template.actions)for(const key of ['parameters_schema','result_schema','preconditions_schema'])schema(action[key]);
  for(const trigger of template.triggers)schema(trigger.payload_schema);documents.push({file:file.file,template});
 }
 if(schemas.size)await validateSchemaDocuments(Buffer.from(canonicalize([...schemas.values()].map(value=>value.document))));
 return {format:'leafseamer-static-capability-evidence/1',selection:capabilityTemplateSelection,intake_ref:installation.intake_ref,
  manifest_digest:installation.receipt.manifest_digest,artifact_set_digest:installation.receipt.artifact_set_digest,documents};
}
export function requireStaticPermissions({installation,resolution,evidence,permissions,device}){
 need(evidence?.format==='leafseamer-static-capability-evidence/1'&&same(evidence.selection,capabilityTemplateSelection)&&same(evidence.intake_ref,installation.intake_ref)&&
  evidence.manifest_digest===installation.receipt.manifest_digest&&evidence.artifact_set_digest===installation.receipt.artifact_set_digest,'binding');
 for(const permission of permissions){
  need(permission.kind==='device_scope','provider_unavailable');const declaration=installation.manifest.permission_templates.find(template=>template.request_id===permission.request_id&&template.kind==='device_scope');
  need(declaration,'permission');const binding=resolution.bindings.find(binding=>binding.role_id===declaration.scope.device_role&&binding.kind==='device');need(binding,'role');
  for(const ref of permission.scope.devices){
   need(binding.values.some(value=>same(value,ref)),'role');const current=device(ref),template=evidence.documents.find(document=>document.template.device_role===binding.role_id&&document.template.device_kind===current.device_kind)?.template;
   need(template,'template_unavailable');
   for(const key of permission.scope.action_ids){const action=template.actions.find(action=>action.action_id===key);need(action,'action_unavailable');
    need(action.platforms.some(platform=>platform.os===(process.platform==='win32'?'windows':'linux')&&platform.arch===process.arch&&platform.status!=='unsupported'),'platform');}
   need(permission.scope.trigger_ids.every(key=>template.triggers.some(trigger=>trigger.trigger_id===key)),'trigger_unavailable');
  }
 }
}
