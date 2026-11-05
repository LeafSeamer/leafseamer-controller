import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {validateConfiguration,ConfigurationValidationError} from './configuration-validator.mjs';
const need=(ok,code)=>{if(!ok)throw new ConfigurationValidationError(code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const rawHash=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const exact=(value,keys)=>value&&Object.keys(value).sort().join(',')===keys.split(',').sort().join(',');
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
const rows=(db,sql,...args)=>{const q=db.prepare(sql),names=q.columns().map(c=>c.name);return q.raw().all(...args).map(row=>Object.fromEntries(names.map((n,i)=>[n,row[i]])));};
function read(body,digest){const value=JSON.parse(body);need(canonicalize(value)===body&&hash(value)===digest,'extension_configuration_integrity');return value;}
export function extensionConfigurationStore({db,service,available,reference,source}){
  let active=0;
  const get=request=>rows(db,'SELECT * FROM extension_configuration_operation WHERE request_id=?',request)[0];
  const prior=input=>{const row=get(input.request_id);if(!row)return null;need(row.input_digest===hash(input)&&row.input_jcs===canonicalize(input),'extension_configuration_conflict');return frozen(read(row.result_jcs,row.result_digest));};
  function candidate(ref){
    need(exact(ref,'kind,authority_service_id,database_instance_id,object_id,revision,digest')&&ref.kind==='installation'&&ref.authority_service_id===service.service_id&&
      ref.database_instance_id===service.database_instance_id&&id(ref.object_id)&&ref.revision==='1','extension_configuration_binding');
    const row=rows(db,'SELECT * FROM extension_candidate WHERE installation_id=?',ref.object_id)[0];
    need(row?.state==='verified'&&row.content_digest===ref.digest,'extension_configuration_binding');return read(row.content_jcs,row.content_digest);
  }
  return Object.freeze({
    async configure(input){
      available();need(exact(input,'request_id,installation_ref,expected_revision,bytes')&&id(input.request_id)&&typeof input.expected_revision==='string'&&
        /^(0|[1-9][0-9]{0,3})(?![\s\S])/.test(input.expected_revision)&&Buffer.isBuffer(input.bytes)&&input.bytes.length<=1048576,'extension_configuration_input');
      const bytes=Buffer.from(input.bytes),fixed=structuredClone({request_id:input.request_id,installation_ref:input.installation_ref,expected_revision:input.expected_revision,input_digest:rawHash(bytes)});
      const old=db.transaction(()=>prior(fixed)).immediate();if(old)return old;
      need(active<2,'extension_configuration_capacity');++active;
      try{
        const selected=db.transaction(()=>candidate(fixed.installation_ref)).immediate(),host=source();
        need(host?.schema&&selected.intake_ref.authority_service_id===host.identity.authority_service_id&&selected.intake_ref.database_instance_id===host.identity.database_instance_id&&
          selected.receipt.host_installation_id===host.identity.host_installation_id,'extension_source_binding');
        const query={intake_id:selected.intake_ref.object_id,target_authority_service_id:service.service_id};
        const response=await host.schema(query);available();need(response?.status==='available','extension_configuration_source_unavailable');
        const document=response.content,file=selected.inventory.files.find(f=>f.file_id===selected.manifest.configuration_schema_file_id&&f.role==='schema');
        need(exact(document,'format,intake_ref,manifest_digest,artifact_set_digest,file,bytes')&&document.format==='leafseamer-configuration-schema/1'&&file&&same(document.intake_ref,selected.intake_ref)&&
          document.manifest_digest===selected.receipt.manifest_digest&&document.artifact_set_digest===selected.receipt.artifact_set_digest&&same(document.file,file)&&
          (Buffer.isBuffer(document.bytes)||document.bytes instanceof Uint8Array),'extension_configuration_binding');
        const schema=Buffer.from(document.bytes);need(schema.length<=1048576&&String(schema.length)===file.size_bytes&&rawHash(schema)===file.digest,'extension_configuration_binding');
        const configuration=await validateConfiguration(schema,bytes);available();
        const current=await host.describe(query);available();need(current?.status==='available'&&same(current.content?.intake_ref,selected.intake_ref)&&
          hash(current.content.receipt)===selected.intake_ref.digest,'extension_configuration_source_unavailable');
        return db.transaction(()=>{
          const raced=prior(fixed);if(raced)return raced;candidate(fixed.installation_ref);
          const head=rows(db,'SELECT * FROM extension_configuration_head WHERE installation_id=?',selected.installation_id)[0],previous=head?.revision??0;
          need(String(previous)===fixed.expected_revision,'extension_configuration_stale');need(previous<4096&&db.prepare('SELECT count(*) FROM extension_configuration_operation').pluck().get()<4096,'extension_configuration_capacity');
          const configId=head?.configuration_id??crypto.randomUUID(),revision=previous+1,operation=crypto.randomUUID();
          const body={configuration_id:configId,revision:String(revision),installation_ref:fixed.installation_ref,intake_ref:selected.intake_ref,
            manifest_digest:selected.receipt.manifest_digest,artifact_set_digest:selected.receipt.artifact_set_digest,schema_file:file,configuration};
          const jcs=canonicalize(body);need(db.prepare('SELECT coalesce(sum(length(CAST(body_jcs AS BLOB))),0) FROM extension_configuration').pluck().get()+Buffer.byteLength(jcs)<=67108864,'extension_configuration_capacity');
          const result={configuration_ref:reference('configuration',configId,revision,body),record:body};
          db.prepare('INSERT INTO extension_configuration VALUES(?,?,?,?,?,?)').run(configId,revision,selected.installation_id,operation,jcs,hash(body));
          if(head)db.prepare('UPDATE extension_configuration_head SET revision=? WHERE installation_id=?').run(revision,selected.installation_id);
          else db.prepare('INSERT INTO extension_configuration_head VALUES(?,?,?)').run(selected.installation_id,configId,revision);
          db.prepare('INSERT INTO extension_configuration_operation VALUES(?,?,?,?,?,?,?,?,?)').run(fixed.request_id,operation,configId,revision,canonicalize(fixed),hash(fixed),canonicalize(result),hash(result),
            canonicalize({kind:'extension_configuration',operation_id:operation,result_digest:hash(result)}));
          return frozen(result);
        }).immediate();
      }finally{--active;}
    },
    query(requestId){available();need(id(requestId),'extension_configuration_input');return db.transaction(()=>{const row=get(requestId);return row?frozen(read(row.result_jcs,row.result_digest)):null;}).immediate();},
    current(installationRef){available();return db.transaction(()=>{const selected=candidate(installationRef),row=rows(db,
      'SELECT c.* FROM extension_configuration_head h JOIN extension_configuration c USING(configuration_id,revision) WHERE h.installation_id=?',selected.installation_id)[0];
      if(!row)return null;const record=read(row.body_jcs,row.body_digest);return frozen({configuration_ref:reference('configuration',row.configuration_id,row.revision,record),record});
    }).immediate();}
  });
}
