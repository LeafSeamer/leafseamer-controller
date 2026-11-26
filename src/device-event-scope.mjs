import crypto from 'node:crypto';
import fs from 'node:fs';
import Database from 'better-sqlite3';
import {readSourceProjectionCut} from './device-source-projection.mjs';
import {canonical,digest} from './auth-clock-value.mjs';
import {deviceEventSourceRef} from './peer-device-events.mjs';
import {contractSelection} from './sdk/selection.mjs';
import {IdentityError} from './identity-error.mjs';
const need=(ok,reason)=>{if(!ok)throw new IdentityError('event_scope_'+reason);};
const same=(a,b)=>canonical(a)===canonical(b);
const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(value);
const graphBytes=fs.readFileSync(new URL('./sdk/contract/models.schema.json',import.meta.url)),graph=JSON.parse(graphBytes),graphDigest=crypto.createHash('sha256').update(graphBytes).digest('hex');
need(graph.$defs.snapshot__SourceSnapshotView&&graph.$defs.channel__ScopeSpec,'installed_graph');
export const eventScopeReference=body=>({authority_service_id:body.authority_service_id,database_instance_id:body.database_instance_id,entity_kind:body.kind,
 entity_id:body.entity_id,entity_epoch:body.entity_epoch,revision:body.revision,content_digest:digest(body).slice(7)});
const unpack=(text,hash)=>{const body=JSON.parse(text);need(canonical(body)===text&&digest(body)===hash,'integrity');return body;};
const written=result=>need(result.changes===1,'storage');
// 从当前来源登记固定集合；用途由可信本机入口决定，调用方不能提供Profile或Selector。
export function deviceEventScopeStore({db,service,bootId,currentSource}){
 const transaction=work=>db.transaction(work).immediate();
 const available=()=>need(db.open&&db.inTransaction&&Number(service.schema_revision)>=65,'writer');
 function source(device,expected=null){
  const value=currentSource(device,expected,'0',1);need(!value.fault,'source_fault');const registration=value.registration;
  need(registration.source_key.authority_service_id===service.service_id&&registration.source_key.database_instance_id===service.database_instance_id&&
   registration.binding_ref.target.kind==='device'&&registration.binding_ref.target.device_id===device&&registration.canonical_delivery==='ordered_subscription','source_binding');
  const row=db.prepare('SELECT body_jcs,body_digest FROM device_event_source WHERE registration_id=?').raw().get(registration.registration_id);
  need(row&&same(unpack(...row),registration),'source_original');
  const sequences=db.prepare('SELECT count(*),coalesce(max(length(source_sequence)),0) FROM device_source_event WHERE registration_id=?').raw().get(registration.registration_id);
  // 当前来源账本从1严格连续提交；容量有界，数量必须等于完整前沿而非最高seen。
  need(String(sequences[0])===value.highest_committed_sequence,'source_frontier');
  return {device_id:device,source_registration_ref:deviceEventSourceRef(registration),source_key:registration.source_key,binding_ref:registration.binding_ref,registration_sequence:value.highest_committed_sequence};
 }
 function original(reference){
  need(reference&&reference.entity_kind==='subscription_scope','reference');const row=db.prepare('SELECT body_jcs,body_digest FROM device_subscription_scope WHERE scope_id=?').raw().get(reference.entity_id);
  need(row,'missing');const value=unpack(...row);need(same(eventScopeReference(value),reference),'reference');return value;
 }
 function current(reference){
  available();const value=original(reference);need(value.service_boot_id===bootId&&!db.prepare('SELECT 1 FROM device_subscription_scope_revocation WHERE scope_id=?').pluck().get(value.entity_id),'inactive');
  need(same(value.selection,contractSelection)&&value.profile.graph_digest===graphDigest,'selection');
  const frontiers=value.sources.map(expected=>{const actual=source(expected.device_id,expected.source_registration_ref);
   need(same(actual.source_key,expected.source_key)&&same(actual.binding_ref,expected.binding_ref)&&BigInt(actual.registration_sequence)>=BigInt(expected.registration_sequence),'source_changed');return actual;});
  return {registration:value,scope_ref:eventScopeReference(value),current_frontiers:frontiers};
 }
 return Object.freeze({
  register(request,purpose='canonical_trigger'){
   need(['canonical_trigger','status_projection'].includes(purpose)&&request&&Object.keys(request).sort().join(',')==='device_ids,request_id'&&uuid(request.request_id)&&Array.isArray(request.device_ids)&&request.device_ids.length>=1&&request.device_ids.length<=32&&request.device_ids.every(uuid)&&new Set(request.device_ids).size===request.device_ids.length,'input');
   request={request_id:request.request_id,device_ids:[...request.device_ids].sort()};
   const requestDigest=digest(purpose==='canonical_trigger'?request:{...request,purpose});
   return transaction(()=>{available();const old=db.prepare('SELECT request_digest,body_jcs,body_digest FROM device_subscription_scope WHERE request_id=?').raw().get(request.request_id);
    if(old){need(old[0]===requestDigest,'conflict');const registration=unpack(old[1],old[2]);need(registration.purpose===purpose,'conflict');return {registration,scope_ref:eventScopeReference(registration)};}
    need(db.prepare('SELECT count(*) FROM device_subscription_scope').pluck().get()<1024,'capacity');
    const sources=request.device_ids.map(device=>source(device)),scopeId=crypto.randomUUID(),epoch=crypto.randomUUID(),common={format_version:'scope-registry/0.1.0-draft.1',authority_service_id:service.service_id,database_instance_id:service.database_instance_id,entity_epoch:epoch,revision:'1'};
    const ownerKind=purpose==='status_projection'?'human':'service';
    if(ownerKind==='human'){
     need(Number(service.schema_revision)>=67,'snapshot_reader');
     const projected=db.prepare('SELECT 1 FROM device_source_projection_head WHERE registration_id=?').pluck();
     need(sources.every(member=>projected.get(member.source_key.registration_id)),'projection_missing');
    }
    const profile={...common,kind:'projection_profile',entity_id:scopeId+'_profile',authority_role:'controller',selection:contractSelection,owner_kinds:[ownerKind],purposes:[purpose],graph_digest:graphDigest,maximum_records:32,
     collections:[{entity_kind:'sources',permission:'status.read',view_schema_ref:{schema_id:graph.$id,definition:'snapshot__SourceSnapshotView',schema_digest:graphDigest},relation_policies:['authorized_reference'],history_policies:['current']}]};
    const selector={...common,kind:'selector',entity_id:scopeId+'_sources',profile_ref:eventScopeReference(profile),target_collection:'sources',mode:'entity_set',entity_ids:sources.map(s=>s.source_key.registration_id).sort(),relation_policy:'authorized_reference',history_policy:'current',window:null};
    const scope={scope_id:scopeId,scope_revision:'1',projection_profile_ref:eventScopeReference(profile),collections:[{entity_kind:'sources',selector_ref:eventScopeReference(selector),relation_policy:'authorized_reference',history_policy:'current'}]};
    const value={format:'leafseamer-device-event-scope/1',kind:'subscription_scope',entity_id:scopeId,entity_epoch:epoch,revision:'1',authority_service_id:service.service_id,database_instance_id:service.database_instance_id,
     service_boot_id:bootId,selection:contractSelection,purpose,profile,selector,scope,scope_digest:digest(scope).slice(7),sources};
    const hash=digest(value);written(db.prepare('INSERT INTO device_subscription_scope VALUES(?,?,?,?,?,?,?)').run(scopeId,request.request_id,requestDigest,bootId,canonical(value),hash,scopeId));
    for(const member of sources)written(db.prepare('INSERT INTO device_subscription_scope_member VALUES(?,?,?,?)').run(scopeId,member.device_id,member.source_key.registration_id,canonical(member)));
    written(db.prepare('INSERT INTO device_subscription_scope_seal VALUES(?,?)').run(scopeId,hash));current(eventScopeReference(value));return {registration:value,scope_ref:eventScopeReference(value)};
   });
  },
  current:reference=>transaction(()=>current(reference)),currentInTransaction:current,
  snapshotCut(reference){
   need(!db.inTransaction&&Number(service.schema_revision)>=67,'snapshot_reader');
   const selected=transaction(()=>current(reference));
   const reader=new Database(db.name,{readonly:true,fileMustExist:true,timeout:1000});let cut;
   try{reader.pragma('query_only=ON');reader.pragma('read_uncommitted=OFF');cut=readSourceProjectionCut(reader,selected.registration);}finally{reader.close();}
   transaction(()=>{const latest=current(reference);need(same(latest.registration,selected.registration),'snapshot_changed');});
   return {...cut,registration:selected.registration,scope_ref:selected.scope_ref};
  },
  revoke(reference){return transaction(()=>{available();const value=original(reference);const old=db.prepare('SELECT 1 FROM device_subscription_scope_revocation WHERE scope_id=?').pluck().get(value.entity_id);
   if(!old)written(db.prepare('INSERT INTO device_subscription_scope_revocation VALUES(?,?)').run(value.entity_id,canonical(reference)));return {scope_ref:reference,state:'revoked'};});}
 });
}
