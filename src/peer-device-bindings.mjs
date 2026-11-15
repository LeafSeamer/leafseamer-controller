import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingNeed as need,pairingFields as fields,pairingUuid as uuid} from './peer-pairing-value.mjs';
export const deviceBindingsPurpose='automation.bindings.read';
export const deviceBindingsLimit=262144;
const hash=value=>need(typeof value==='string'&&/^sha256:[0-9a-f]{64}$/.test(value),'bindings_digest');
const reference=value=>{fields(value,'id,revision,digest');need(typeof value.id==='string'&&value.id.length>0&&value.id.length<=256&&value.revision==='1','bindings_reference');hash(value.digest);};
export function deviceBindingsScope(value){
 fields(value,'format,authority_service_id,database_instance_id,device_ids');
 need(value.format==='leafseamer.device-binding-scope/1','bindings_version');uuid(value.authority_service_id);uuid(value.database_instance_id);
 need(Array.isArray(value.device_ids)&&value.device_ids.length>0&&value.device_ids.length<=64,'bindings_scope');
 value.device_ids.forEach(uuid);need(same(value.device_ids,[...new Set(value.device_ids)].sort()),'bindings_scope');return value;
}
export function deviceBindingsRequest(value){
 fields(value,'format,challenge_id,scope,device_id,expected_registration_ref');need(value.format==='leafseamer.device-bindings-request/1','bindings_version');
 uuid(value.challenge_id);uuid(value.device_id);deviceBindingsScope(value.scope);need(value.scope.device_ids.includes(value.device_id),'bindings_scope');
 const ref=value.expected_registration_ref;
 if(ref!==null){fields(ref,'kind,scope,object_id,revision,digest');need(ref.kind==='source_registration'&&same(ref.scope,{authority_service_id:value.scope.authority_service_id,database_instance_id:value.scope.database_instance_id}),'bindings_reference');reference({id:ref.object_id,revision:ref.revision,digest:ref.digest});}
 return value;
}
export function authorizeDeviceBindings(record,request,controllerId,seamerId){
 deviceBindingsRequest(request);const controller=record.transcript.parties.find(p=>p.service_id===controllerId),seamer=record.transcript.parties.find(p=>p.service_id===seamerId);
 need(record.state==='activated'&&controller?.service_kind==='controller'&&seamer?.service_kind==='seamer'&&seamer.permissions.includes(deviceBindingsPurpose),'purpose');
 need(request.scope.authority_service_id===controller.service_id&&request.scope.database_instance_id===controller.database_instance_id&&seamer.object_scope_digest===digest(request.scope),'bindings_scope');
 return controller;
}
export function deviceBindingsBundle(value,request){
 fields(value,'registration_ref,registration,bindings,schemas,input_schemas,result_schema,alias_table');
 const registration=value.registration,ref=value.registration_ref,scope={authority_service_id:request.scope.authority_service_id,database_instance_id:request.scope.database_instance_id};
 fields(ref,'kind,scope,object_id,revision,digest');reference({id:ref.object_id,revision:ref.revision,digest:ref.digest});
 need(ref.kind==='source_registration'&&same(ref.scope,scope)&&registration?.format==='leafseamer-device-automation-registration/1'&&same(registration.scope,scope)&&
  registration.device_id===request.device_id&&registration.registration_id===ref.object_id&&digest(registration)===ref.digest,'bindings_registration');
 if(request.expected_registration_ref!==null)need(same(request.expected_registration_ref,ref),'bindings_registration');
 need(Array.isArray(value.bindings)&&value.bindings.length>0&&value.bindings.length<=64,'bindings_capacity');
 const ids=new Set();
 for(const binding of value.bindings){fields(binding,'kind,binding_id,content_ref,value');reference(binding.content_ref);
  need(['input','action'].includes(binding.kind)&&binding.binding_id===binding.value?.binding_id&&binding.content_ref.id===binding.binding_id&&
   digest(binding.value)===binding.content_ref.digest&&!ids.has(binding.binding_id)&&binding.value.authority_id===scope.authority_service_id&&
   same(binding.value.registration_ref,{id:ref.object_id,revision:ref.revision,digest:ref.digest}),'bindings_content');ids.add(binding.binding_id);
  if(binding.kind==='action')need(binding.value.controller_id===scope.authority_service_id&&binding.value.device_id===request.device_id,'bindings_content');
 }
 need(Array.isArray(value.schemas)&&Array.isArray(value.input_schemas)&&value.schemas.length<=64&&value.input_schemas.length<=64,'bindings_capacity');
 for(const schema of [...value.schemas,...value.input_schemas,value.result_schema]){reference(schema.schema_ref);need(digest(schema.document)===schema.schema_ref.digest,'bindings_schema');}
 fields(value.alias_table,'ref,entries');reference(value.alias_table.ref);need(Array.isArray(value.alias_table.entries)&&digest(value.alias_table.entries)===value.alias_table.ref.digest,'bindings_aliases');
 need(Buffer.byteLength(canonical(value))<=deviceBindingsLimit,'bindings_capacity');return value;
}
export function deviceBindingsReply(value,request,record,controllerId,seamerId){
 fields(value,'format,challenge_id,controller_id,seamer_id,transcript_digest,bundle_digest,bundle');
 need(value.format==='leafseamer.device-bindings-response/1'&&value.challenge_id===request.challenge_id&&value.controller_id===controllerId&&value.seamer_id===seamerId&&
  value.transcript_digest===record.transcript_digest&&value.bundle_digest===digest(value.bundle),'bindings_response');
 authorizeDeviceBindings(record,request,controllerId,seamerId);deviceBindingsBundle(value.bundle,request);return value;
}
export function decodeDeviceBindings(bytes,limit=deviceBindingsLimit){
 need(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=limit,'bindings_capacity');const value=JSON.parse(bytes.toString('utf8'));
 need(Buffer.from(canonical(value)).equals(bytes),'bindings_canonical');return value;
}
