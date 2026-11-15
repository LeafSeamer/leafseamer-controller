import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingNeed as need,pairingFields as fields,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {deviceBindingsScope} from './peer-device-bindings.mjs';
export const deviceEventsLimit=262144;
const counter=value=>{need(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(value),'events_sequence');return BigInt(value);};
const hash=value=>need(typeof value==='string'&&/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(value),'events_digest');
export const deviceEventSourceRef=value=>({kind:'source_registration',scope:{authority_service_id:value.source_key.authority_service_id,database_instance_id:value.source_key.database_instance_id},object_id:value.registration_id,revision:value.revision,digest:digest(value)});
export function deviceEventsRequest(value){
 fields(value,'format,challenge_id,scope,device_id,expected_source_ref,after_sequence,limit');need(value.format==='leafseamer.device-events-request/1','events_version');
 uuid(value.challenge_id);uuid(value.device_id);deviceBindingsScope(value.scope);need(value.scope.device_ids.includes(value.device_id),'events_scope');counter(value.after_sequence);
 need(Number.isInteger(value.limit)&&value.limit>=1&&value.limit<=32,'events_capacity');
 if(value.expected_source_ref!==null){const ref=value.expected_source_ref;fields(ref,'kind,scope,object_id,revision,digest');uuid(ref.object_id);hash(ref.digest);
  need(ref.kind==='source_registration'&&ref.revision==='1'&&same(ref.scope,{authority_service_id:value.scope.authority_service_id,database_instance_id:value.scope.database_instance_id}),'events_reference');}
 need(value.after_sequence==='0'||value.expected_source_ref!==null,'events_reference');return value;
}
export function authorizeDeviceEvents(record,request,controllerId,seamerId){
 deviceEventsRequest(request);const controller=record.transcript.parties.find(p=>p.service_id===controllerId),seamer=record.transcript.parties.find(p=>p.service_id===seamerId);
 need(record.state==='activated'&&controller?.service_kind==='controller'&&seamer?.service_kind==='seamer'&&seamer.permissions.includes('events.internal.read'),'purpose');
 need(request.scope.authority_service_id===controller.service_id&&request.scope.database_instance_id===controller.database_instance_id&&seamer.object_scope_digest===digest(request.scope),'events_scope');return controller;
}
export function deviceEventsBundle(value,request){
 fields(value,'registration,highest_committed_sequence,fault,events');const r=value.registration;
 fields(r,'format,registration_id,revision,source_key,binding_ref,qualification,canonical_delivery,payload_schema_ref,payload_schema');
 need(r.format==='leafseamer-device-event-source/1'&&r.revision==='1'&&r.canonical_delivery==='ordered_subscription','events_registration');uuid(r.registration_id);
 const key=r.source_key,binding=r.binding_ref;fields(key,'authority_service_id,database_instance_id,registration_id,source_stream_id,source_epoch');
 need(key.authority_service_id===request.scope.authority_service_id&&key.database_instance_id===request.scope.database_instance_id&&key.registration_id===r.registration_id&&
  binding.registration_id===r.registration_id&&binding.owner_service_id===key.authority_service_id&&binding.database_instance_id===key.database_instance_id&&
  binding.target?.kind==='device'&&binding.target.device_id===request.device_id&&r.qualification?.device_id===request.device_id&&
  r.qualification.capture?.capture_id===key.source_epoch,'events_registration');
 need(same(r.payload_schema_ref.scope,{authority_service_id:key.authority_service_id,database_instance_id:key.database_instance_id})&&r.payload_schema_ref.kind==='schema'&&r.payload_schema_ref.digest===digest(r.payload_schema),'events_schema');
 if(request.expected_source_ref!==null)need(same(deviceEventSourceRef(r),request.expected_source_ref),'events_reference');
 let sequence=counter(request.after_sequence);const highest=counter(value.highest_committed_sequence);need(sequence<=highest,'events_sequence');
 need(Array.isArray(value.events)&&value.events.length<=request.limit,'events_capacity');const ids=new Set();
 for(const item of value.events){fields(item,'origin,origin_digest');const origin=item.origin;
  need(origin&&digest(origin)===item.origin_digest&&same(origin.source_key,key)&&same(origin.binding_ref,binding)&&same(origin.payload?.schema_ref,r.payload_schema_ref)&&
   counter(origin.source_sequence)===++sequence&&!ids.has(origin.event_id),'events_origin');ids.add(origin.event_id);}
 need(sequence<=highest&&value.events.length===Number(highest-counter(request.after_sequence)>BigInt(request.limit)?BigInt(request.limit):highest-counter(request.after_sequence)),'events_sequence');
 if(value.fault!==null)need(value.fault?.registration_id===r.registration_id&&['capture_failed','capture_stopped','channel_closed'].includes(value.fault.reason),'events_fault');
 need(Buffer.byteLength(canonical(value))<=deviceEventsLimit,'events_capacity');return value;
}
export function deviceEventsReply(value,request,record,controllerId,seamerId){
 fields(value,'format,challenge_id,controller_id,seamer_id,transcript_digest,bundle_digest,bundle');
 need(value.format==='leafseamer.device-events-response/1'&&value.challenge_id===request.challenge_id&&value.controller_id===controllerId&&value.seamer_id===seamerId&&
  value.transcript_digest===record.transcript_digest&&value.bundle_digest===digest(value.bundle),'events_response');
 authorizeDeviceEvents(record,request,controllerId,seamerId);deviceEventsBundle(value.bundle,request);return value;
}
export function decodeDeviceEvents(bytes,limit=deviceEventsLimit){
 need(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=limit,'events_capacity');const value=JSON.parse(bytes.toString('utf8'));need(Buffer.from(canonical(value)).equals(bytes),'events_canonical');return value;
}
