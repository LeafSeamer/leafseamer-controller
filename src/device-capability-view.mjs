import {canonical,digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {readDeviceFootprint} from './device-footprint-qualification.mjs';
import {isObsModuleEntry,obsModuleDefinition,projectObsSceneCatalog,validateObsSceneSample} from './obs-module-profile.mjs';
import {readConfirmedObsSceneCatalog} from './obs-scene-confirmation.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('device_capabilities_'+code);};
const same=(a,b)=>canonical(a)===canonical(b);
const read=(text,expected)=>{const value=JSON.parse(text);need(canonical(value)===text&&digest(value)===expected,'integrity');return value;};

// 当前核心装配提供runtime/selected/dependencies，调用者只选择device_id。
// 静态模板是内容来源；缺少完整作用范围证明时明确complete=false，不授自动化或发送资格。
export function readCurrentDeviceCatalog(db,{service,device,runtime,selected,dependencies,channel}){
 need(db.inTransaction,'writer');
 const descriptorRow=db.prepare('SELECT descriptor_body,descriptor_digest FROM device_record WHERE device_id=?').raw().get(device);
 need(descriptorRow,'not_found');const descriptor=read(descriptorRow[0].toString(),descriptorRow[1]);need(descriptor.device_id===device,'integrity');
 const last=db.prepare(`SELECT frame_jcs,message_type,frame_digest FROM device_module_frame WHERE channel_id=? AND direction='w2c'
  AND message_type IN ('CONNECTED','DISCONNECTED') AND json_extract(frame_jcs,'$.body.device_id')=? ORDER BY length(sequence) DESC,sequence DESC LIMIT 1`).raw().get(channel,device);
 need(last&&last[1]==='CONNECTED','unavailable');const connected=read(last[0],last[2]);
 const row=db.prepare('SELECT body_jcs,body_digest FROM device_catalog_approval WHERE channel_id=? AND device_id=? AND device_session_id=?').raw().get(channel,device,connected.body.device_session_id);
 need(row,'unavailable');const approved=read(...row),q=approved.qualification,content=selected.content,intent=runtime.binding.launch_intent;
 need(approved.device_id===device&&approved.channel_id===channel&&approved.connected_message_id===connected.request_id&&
  same(approved.runtime_binding_ref,runtime.ref)&&same(connected.binding.runtime_binding_ref,runtime.ref)&&
  runtime.binding.service_id===service.service_id&&runtime.binding.database_instance_id===service.database_instance_id,'binding');
 need(q.manifest_digest===content.receipt.manifest_digest&&q.artifact_set_digest===content.receipt.artifact_set_digest&&
  same(q.approval_ref,intent.extension_binding.approval_ref)&&same(q.installation_ref,intent.extension_binding.installation_ref)&&same(q.platform_profile_ref,intent.extension_binding.platform_profile_ref),'binding');
 const links=dependencies.links.filter(link=>link.device_ref.object_id===device);
 need(links.length===1&&same(links[0].device_ref,q.device_ref)&&same(links[0].resource_ref,q.resource_ref)&&links[0].template_digest===q.template_digest,'binding');
 if(descriptor.device_kind==='obs')need(isObsModuleEntry(content,selected.entry)&&links[0].obs_binding&&q.obs_binding&&
  same(links[0].obs_binding,q.obs_binding)&&
  q.qualification===obsModuleDefinition.qualification&&q.module_digest===obsModuleDefinition.module&&
  q.protocol_io_policy_digest===obsModuleDefinition.policy,'binding');
 const evidenceRow=db.prepare('SELECT body_jcs,body_digest FROM extension_approval_capabilities WHERE approval_id=?').raw().get(q.approval_ref.object_id);
 need(evidenceRow&&evidenceRow[1]===dependencies.capability_evidence_digest,'binding');const evidence=read(...evidenceRow);
 need(same(evidence.intake_ref,content.intake_ref)&&evidence.manifest_digest===q.manifest_digest&&evidence.artifact_set_digest===q.artifact_set_digest,'binding');
 const templates=evidence.documents.filter(document=>digest(document.template)===q.template_digest);need(templates.length===1,'binding');const template=templates[0].template;
 need(template.device_kind===descriptor.device_kind&&same(template.state_schema,approved.catalog.state_schema)&&
  same(template.actions.map(action=>action.action_id).sort(),[...approved.catalog.action_ids].sort())&&
  same(template.triggers.map(trigger=>trigger.trigger_id).sort(),[...approved.catalog.trigger_ids].sort()),'binding');
 for(const schema of [template.state_schema,...template.actions.flatMap(action=>[action.parameters_schema,action.result_schema,action.preconditions_schema]),...template.triggers.map(trigger=>trigger.payload_schema)])
  need(digest(schema.document)===schema.digest,'integrity');
 const qualified=readDeviceFootprint(approved,runtime);
 if(qualified){const entry=selected.entry,inventory=content.inventory?.files;
  need(entry&&inventory?.find(file=>file.file_id===entry.file_id)?.digest===q.module_digest&&
   inventory.find(file=>file.file_id===entry.io_policy_file_id)?.digest===q.protocol_io_policy_digest,'binding');}
 return {approved,qualified,template,descriptor,content,intent};
}
export function readDeviceCapabilities(db,input){
 const {approved,qualified,template,descriptor,content,intent}=readCurrentDeviceCatalog(db,input),q=approved.qualification,runtime=input.runtime;
 const actions=template.actions.map(action=>({...structuredClone(action),footprint:qualified?.action_footprints.find(value=>value.action_id===action.action_id)??{manifest_digest:q.manifest_digest,semantics_revision:'1',complete:false,
  reads:[],writes:[],failure_writes:[],resources:[],safe_failure_classes:[],action_id:action.action_id}}));
 return {provider_id:intent.member_id,provider_boot_id:runtime.binding.admission_receipt.member_boot_id,catalog_revision:approved.catalog.catalog_revision,
  module_id:content.manifest.extension_id,module_version:content.manifest.extension_version,
  devices:[{...descriptor,connection_state:'ready',actions,triggers:structuredClone(template.triggers),state_schema:structuredClone(template.state_schema)}]};
}

export function readDeviceSceneCatalog(db,input,includeConfirmation=true){
 const {approved}=readCurrentDeviceCatalog(db,input),q=approved.qualification;
 need(q.qualification===obsModuleDefinition.qualification,'unavailable');
 const row=db.prepare('SELECT body_jcs,body_digest FROM device_baseline_sample WHERE approval_id=? ORDER BY length(sample_sequence) DESC,sample_sequence DESC LIMIT 1')
  .raw().get(approved.approval_id);
 need(row,'unavailable');
 const sample=read(...row);
 need(sample.device_id===approved.device_id&&sample.device_session_id===approved.device_session_id&&
  sample.catalog_approval_ref.object_id===approved.approval_id&&sample.catalog_approval_ref.digest===digest(approved)&&
  validateObsSceneSample(sample.value,q.obs_binding.scene_uuids),'binding');
 const catalog=projectObsSceneCatalog(approved,sample);
 return includeConfirmation?readConfirmedObsSceneCatalog(db,catalog):catalog;
}
