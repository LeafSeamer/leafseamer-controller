import {memoExecutionRead} from './execution-read-view.mjs';
import {sqliteRows} from './sqlite-rows.mjs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {decodeArtifactDocument} from './sdk/artifact-import.mjs';
import {resolveRolePermissions,roleNeed as need} from './extension-role-resolution.mjs';
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const exact=(v,keys)=>v&&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
const id=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(v);
const rows=sqliteRows;
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
function readDocument(body,digest){const value=JSON.parse(body);need(canonicalize(value)===body&&'sha256:'+crypto.createHash('sha256').update(body).digest('hex')===digest,'integrity');return value;}
export function extensionRoleStore({db,service,available,reference,source,attachCurrent}){
 const read=(body,digest)=>memoExecutionRead(db,'extension-document',[body,digest],()=>readDocument(body,digest));
 let active=0;const scope={authority:'controller',authority_service_id:service.service_id,database_instance_id:service.database_instance_id};
 const get=request=>rows(db,'SELECT * FROM extension_role_operation WHERE request_id=?',request)[0];
 const prior=input=>{const row=get(input.request_id);if(!row)return null;need(row.input_digest===hash(input)&&row.input_jcs===canonicalize(input),'conflict');return frozen(read(row.result_jcs,row.result_digest));};
 function candidate(ref){
  need(exact(ref,'kind,authority_service_id,database_instance_id,object_id,revision,digest')&&ref.kind==='installation'&&ref.authority_service_id===service.service_id&&
   ref.database_instance_id===service.database_instance_id&&id(ref.object_id)&&ref.revision==='1','installation');
  const row=rows(db,'SELECT * FROM extension_candidate WHERE installation_id=?',ref.object_id)[0];
  need(row?.state==='verified'&&row.content_digest===ref.digest,'installation');return read(row.content_jcs,row.content_digest);
 }
 function device(deviceId){
  need(id(deviceId),'object');const row=rows(db,'SELECT descriptor_body,descriptor_digest FROM device_record WHERE device_id=?',deviceId)[0];need(row,'object_unavailable');
  const body=row.descriptor_body.toString('utf8'),record=read(body,row.descriptor_digest);need(record.device_id===deviceId,'integrity');
  return {ref:reference('device',deviceId,1,record),record};
 }
 function currentObject(ref){
  // 其他类型须接入各自实际存储，不能由客户端提供一个可自行计算摘要的记录冒充。
  need(ref.kind==='device','object_provider_unavailable');const found=device(ref.object_id);need(same(found.ref,ref),'object_stale');return found.record;
 }
 function configuration(installation,ref){
  const row=rows(db,'SELECT c.* FROM extension_configuration_head h JOIN extension_configuration c USING(configuration_id,revision) WHERE h.installation_id=?',installation.installation_id)[0];
  need(row,'configuration');const body=read(row.body_jcs,row.body_digest);need(same(reference('configuration',row.configuration_id,row.revision,body),ref),'configuration_stale');
  return {id:row.configuration_id,revision:row.revision,body};
 }
 function project(installation,configRef,bindings){return resolveRolePermissions({manifest:installation.manifest,inventory:installation.inventory,
  configuration_ref:configRef,bindings,scope,current:currentObject});}
 function currentResolution(installationRef){
  need(db.inTransaction,'transaction');const installation=candidate(installationRef),row=rows(db,
   'SELECT r.* FROM extension_role_head h JOIN extension_role_resolution r USING(resolution_id,revision) WHERE h.installation_id=?',installation.installation_id)[0];
  if(!row)return null;const record=read(row.body_jcs,row.body_digest);configuration(installation,record.configuration_ref);
  need(same(project(installation,record.configuration_ref,record.bindings),record.permissions),'changed');
  return frozen({resolution_ref:{kind:'role_resolution',authority_service_id:service.service_id,database_instance_id:service.database_instance_id,object_id:record.resolution_id,
   revision:String(row.revision),digest:record.resolution_digest},record});
 }
 attachCurrent?.(currentResolution);
 return Object.freeze({
  deviceReference(deviceId){available();return db.transaction(()=>frozen(device(deviceId).ref)).immediate();},
  async resolve(input){
   available();need(exact(input,'request_id,installation_ref,configuration_ref,expected_revision,bindings')&&id(input.request_id)&&typeof input.expected_revision==='string'&&
    /^(0|[1-9][0-9]{0,3})(?![\s\S])/.test(input.expected_revision)&&Array.isArray(input.bindings)&&input.bindings.length<=128,'input');
   const fixed=structuredClone(input);need(Buffer.byteLength(canonicalize(fixed))<=1048576,'capacity');const old=db.transaction(()=>prior(fixed)).immediate();if(old)return old;
   need(active<2,'capacity');++active;
   try{
    const selected=db.transaction(()=>{const installation=candidate(fixed.installation_ref);configuration(installation,fixed.configuration_ref);
     return {installation,permissions:project(installation,fixed.configuration_ref,fixed.bindings)};}).immediate();
    const body={resolution_id:crypto.randomUUID(),authority_service_id:service.service_id,database_instance_id:service.database_instance_id,
     installation_id:selected.installation.installation_id,manifest_digest:selected.installation.receipt.manifest_digest,artifact_set_digest:selected.installation.receipt.artifact_set_digest,
     configuration_ref:fixed.configuration_ref,bindings:fixed.bindings,permissions:selected.permissions};
    const record=await decodeArtifactDocument(Buffer.from(canonicalize({...body,resolution_digest:hash(body)})),'RoleResolution');available();
    const host=source();need(host&&host.identity.authority_service_id===selected.installation.intake_ref.authority_service_id&&
     host.identity.database_instance_id===selected.installation.intake_ref.database_instance_id&&host.identity.host_installation_id===selected.installation.receipt.host_installation_id,'source');
    const current=await host.describe({intake_id:selected.installation.intake_ref.object_id,target_authority_service_id:service.service_id});available();
    need(current?.status==='available'&&same(current.content?.intake_ref,selected.installation.intake_ref)&&hash(current.content.receipt)===selected.installation.intake_ref.digest,'source_unavailable');
    return db.transaction(()=>{
     const raced=prior(fixed);if(raced)return raced;const installation=candidate(fixed.installation_ref),config=configuration(installation,fixed.configuration_ref);
     need(same(project(installation,fixed.configuration_ref,fixed.bindings),record.permissions),'changed');
     const head=rows(db,'SELECT * FROM extension_role_head WHERE installation_id=?',installation.installation_id)[0],previous=head?.revision??0;
     need(String(previous)===fixed.expected_revision,'stale');need(previous<4096&&db.prepare('SELECT count(*) FROM extension_role_operation').pluck().get()<4096,'capacity');
     const revision=previous+1,operation=crypto.randomUUID(),jcs=canonicalize(record);need(db.prepare('SELECT coalesce(sum(length(CAST(body_jcs AS BLOB))),0) FROM extension_role_resolution').pluck().get()+Buffer.byteLength(jcs)<=67108864,'capacity');
     const result={resolution_ref:{...reference('role_resolution',record.resolution_id,revision,body),digest:record.resolution_digest},record};
     db.prepare('INSERT INTO extension_role_resolution VALUES(?,?,?,?,?,?,?,?)').run(record.resolution_id,revision,installation.installation_id,config.id,config.revision,operation,jcs,hash(record));
     if(head)db.prepare('UPDATE extension_role_head SET resolution_id=?,revision=? WHERE installation_id=?').run(record.resolution_id,revision,installation.installation_id);
     else db.prepare('INSERT INTO extension_role_head VALUES(?,?,?)').run(installation.installation_id,record.resolution_id,revision);
     db.prepare('INSERT INTO extension_role_operation VALUES(?,?,?,?,?,?,?,?,?)').run(fixed.request_id,operation,record.resolution_id,revision,canonicalize(fixed),hash(fixed),canonicalize(result),hash(result),
      canonicalize({kind:'extension_role_resolution',operation_id:operation,result_digest:hash(result)}));return frozen(result);
    }).immediate();
   }finally{--active;}
  },
  query(requestId){available();need(id(requestId),'input');return db.transaction(()=>{const row=get(requestId);return row?frozen(read(row.result_jcs,row.result_digest)):null;}).immediate();},
  current(installationRef){available();return db.transaction(()=>currentResolution(installationRef)).immediate();}
 });
}
