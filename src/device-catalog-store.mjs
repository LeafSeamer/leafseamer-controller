import fs from 'node:fs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {moduleNeed as need} from './sdk/device-module.mjs';
import {simulatorCatalog} from './simulator-module.mjs';
import {openNativeClock} from './native-clock.mjs';

const digest=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const hash=value=>digest(canonicalize(value));
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
const moduleDigest=digest(fs.readFileSync(new URL('./simulator-module.mjs',import.meta.url)));
const policyDigest=digest(fs.readFileSync(new URL('./simulator-policy.json',import.meta.url)));
const identity={kind:'virtual',model:'leafseamer.simulator',revision:'1'};
function read(body,digest){const value=JSON.parse(body);need(canonicalize(value)===body&&hash(value)===digest,'module_catalog_integrity');return value;}

// 固定内存模拟器的只读资格提供者。其他模块或型号不能凭自报身份取得此资格。
// current/select由核心闭包装配；调用方不提交批准、静态模板、资源或制品摘要。
export function deviceCatalogStore({db,current,select}){
 const clock=openNativeClock();
 const ref=(runtime,kind,id,body)=>({kind,authority_service_id:runtime.ref.authority_service_id,
  database_instance_id:runtime.ref.database_instance_id,object_id:id,revision:'1',digest:hash(body)});
 function profile(runtime,device){
  const {selected,dependencies}=select(runtime.binding.launch_intent),{content,entry}=selected;
  const module=content.inventory.files.find(f=>f.file_id===entry.file_id),policy=content.inventory.files.find(f=>f.file_id===entry.io_policy_file_id);
  need(module?.digest===moduleDigest&&policy?.digest===policyDigest,'module_catalog_qualification');
  const links=dependencies.links.filter(link=>link.device_ref.object_id===device);need(links.length===1,'module_catalog_scope');
  const evidenceRow=db.prepare('SELECT body_jcs,body_digest FROM extension_approval_capabilities WHERE approval_id=?').raw().get(runtime.binding.launch_intent.extension_binding.approval_ref.object_id);
  need(evidenceRow&&evidenceRow[1]===dependencies.capability_evidence_digest,'module_catalog_template');
  const evidence=read(...evidenceRow),templates=evidence.documents.filter(value=>hash(value.template)===links[0].template_digest);
  need(templates.length===1&&same(templates[0].template.state_schema,simulatorCatalog().state_schema),'module_catalog_template');
  return {installation_ref:runtime.binding.launch_intent.extension_binding.installation_ref,
   approval_ref:runtime.binding.launch_intent.extension_binding.approval_ref,platform_profile_ref:runtime.binding.launch_intent.extension_binding.platform_profile_ref,
   device_ref:links[0].device_ref,resource_ref:links[0].resource_ref,template_digest:links[0].template_digest,
   manifest_digest:content.receipt.manifest_digest,artifact_set_digest:content.receipt.artifact_set_digest,
   module_digest:moduleDigest,protocol_io_policy_digest:policyDigest,qualification:'fixed_memory_read_only/1'};
 }
 function active(frame,runtime){
  need(frame.binding.runtime_binding_ref.digest===runtime.ref.digest&&frame.binding.runtime_binding_ref.object_id===runtime.ref.object_id,'module_catalog_runtime');
  const now=clock.tick();need(now>=BigInt(frame.issued_tick_ns)&&now<BigInt(frame.deadline_tick_ns),'module_expired');
 }
 function catalog(channel,device,session){
  const row=db.prepare('SELECT approval_id,body_jcs,body_digest FROM device_catalog_approval WHERE channel_id=? AND device_id=? AND device_session_id=?').raw().get(channel,device,session);
  need(row,'module_catalog_required');return {id:row[0],body:read(row[1],row[2])};
 }
 function checkSession(channel,device,session){
  // 持久会话终态也参与检查，历史批准不能在断开或新连接后复活。
  const last=db.prepare("SELECT frame_jcs,message_type FROM device_module_frame WHERE channel_id=? AND direction='w2c' AND message_type IN ('CONNECTED','DISCONNECTED') AND json_extract(frame_jcs,'$.body.device_id')=? ORDER BY length(sequence) DESC,sequence DESC LIMIT 1").raw().get(channel,device);
  need(last&&last[1]==='CONNECTED'&&JSON.parse(last[0]).body.device_session_id===session,'module_session');
 }
 return Object.freeze({
  receive(frame){
   if(!['CONNECTED','CAPTURED'].includes(frame.type))return;
   const runtime=current();active(frame,runtime);
   db.transaction(()=>{
    need(db.prepare("SELECT frame_digest FROM device_module_frame WHERE message_id=? AND direction='w2c'").pluck().get(frame.request_id)===hash(frame),'module_catalog_frame');
    const body=frame.body,channel=frame.binding.ipc_session_id,qualification=profile(runtime,body.device_id);
    checkSession(channel,body.device_id,body.device_session_id);
    if(frame.type==='CONNECTED'){
     need(same(body.identity,identity)&&same(body.catalog,simulatorCatalog()),'module_catalog_proposal');
     need(db.prepare('SELECT count(*) FROM device_catalog_approval').pluck().get()<4096,'module_catalog_capacity');
     const id=crypto.randomUUID(),record={format:'leafseamer-readonly-catalog-approval/1',approval_id:id,
      runtime_binding_ref:runtime.ref,channel_id:channel,device_id:body.device_id,device_session_id:body.device_session_id,
      connected_message_id:frame.request_id,identity:body.identity,catalog:body.catalog,qualification,
      evidence_policy:{kind:'correlated_baseline/1',completion:'read_only_snapshot',automation_eligible:false,write_eligible:false}};
     need(db.prepare('INSERT INTO device_catalog_approval VALUES(?,?,?,?,?,?,?,?)').run(id,channel,body.device_id,body.device_session_id,frame.request_id,canonicalize(record),hash(record),
      canonicalize({kind:'readonly_catalog_approved',approval_id:id,record_digest:hash(record)})).changes===1,'module_catalog_storage');
    }else{
     const approved=catalog(channel,body.device_id,body.device_session_id);need(same(approved.body.qualification,qualification),'module_catalog_stale');
     const value=body.value;
     need(value&&Object.keys(value).sort().join(',')==='sample_sequence,value'&&value.value===0&&typeof value.sample_sequence==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(value.sample_sequence),'module_sample_schema');
     const previous=db.prepare('SELECT sample_sequence FROM device_baseline_sample WHERE approval_id=? ORDER BY length(sample_sequence) DESC,sample_sequence DESC LIMIT 1').pluck().get(approved.id);
     need(BigInt(value.sample_sequence)===BigInt(previous??'0')+1n,'module_sample_sequence');
     need(db.prepare('SELECT count(*) FROM device_baseline_sample').pluck().get()<16384,'module_catalog_capacity');
     const id=crypto.randomUUID(),record={format:'leafseamer-baseline-sample/1',sample_id:id,catalog_approval_ref:ref(runtime,'catalog_approval',approved.id,approved.body),
      captured_message_id:frame.request_id,captured_tick_ns:body.captured_tick_ns,value,device_id:body.device_id,device_session_id:body.device_session_id,
      clock_domain_descriptor:runtime.binding.clock_domain_descriptor};
     need(db.prepare('INSERT INTO device_baseline_sample VALUES(?,?,?,?,?,?,?)').run(id,approved.id,frame.request_id,value.sample_sequence,canonicalize(record),hash(record),
      canonicalize({kind:'baseline_sample_accepted',sample_id:id,record_digest:hash(record)})).changes===1,'module_catalog_storage');
    }
    active(frame,runtime);
   }).immediate();
  },
  current(channel,device,session){
   const runtime=current();return db.transaction(()=>{
    checkSession(channel,device,session);const approved=catalog(channel,device,session);
    need(same(approved.body.runtime_binding_ref,runtime.ref)&&same(approved.body.qualification,profile(runtime,device)),'module_catalog_stale');
    const row=db.prepare('SELECT body_jcs,body_digest FROM device_baseline_sample WHERE approval_id=? ORDER BY length(sample_sequence) DESC,sample_sequence DESC LIMIT 1').raw().get(approved.id);
    return frozen({catalog_approval_ref:ref(runtime,'catalog_approval',approved.id,approved.body),approval:approved.body,sample:row?read(...row):null});
   }).immediate();
  }
 });
}
