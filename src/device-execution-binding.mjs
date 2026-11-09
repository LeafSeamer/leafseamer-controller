import crypto from 'node:crypto';
import fs from 'node:fs';
import canonicalize from 'canonicalize';
import {moduleNeed as need} from './sdk/device-module.mjs';
import {memoExecutionRead} from './execution-read-view.mjs';
const digest=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const hash=value=>digest(canonicalize(value));
const ref=(id,value)=>({id,revision:'1',digest:hash(value)});
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
const moduleDigest=digest(fs.readFileSync(new URL('./simulator-control-module.mjs',import.meta.url)));
const policyDigest=digest(fs.readFileSync(new URL('./simulator-control-policy.json',import.meta.url)));
const template=JSON.parse(fs.readFileSync(new URL('./simulator-control-capability.json',import.meta.url)));
const templateDigest=hash(template);
const same=(a,b)=>canonicalize(a)===canonicalize(b);
function read(db,text,expected){return memoExecutionRead(db,'execution-binding-document',[text,expected],()=>{
 const value=JSON.parse(text);need(canonicalize(value)===text&&digest(text)===expected,'execution_binding_integrity');return value;
});}

// 只读当前writer中的真实装配；旧连接原件和握手本身不产生发送资格。
export function currentDeviceExecutionBinding(db,runtime,device,sessionId){
 need(db.inTransaction,'execution_binding_writer');
 const rows=db.prepare(`SELECT b.body_jcs,b.body_digest,c.body_jcs,c.body_digest FROM device_execution_binding b
  JOIN device_catalog_approval c ON c.approval_id=b.catalog_approval_id WHERE b.ipc_session_id=? AND b.device_id=?`).raw().all(sessionId,device);
 const matches=[];
 for(const row of rows){
  const value=read(db,row[0],row[1]),catalog=read(db,row[2],row[3]);
  const latest=db.prepare(`SELECT frame_jcs,message_type FROM device_module_frame WHERE channel_id=? AND direction='w2c'
   AND message_type IN ('CONNECTED','DISCONNECTED') AND json_extract(frame_jcs,'$.body.device_id')=?
   ORDER BY length(sequence) DESC,sequence DESC LIMIT 1`).raw().get(catalog.channel_id,device);
  if(!latest||latest[1]!=='CONNECTED'||JSON.parse(latest[0]).body.device_session_id!==value.binding.device_session_id)continue;
  need(same(value.runtime_binding_ref,runtime.ref)&&same(catalog.runtime_binding_ref,runtime.ref)&&
   value.binding.device_id===device&&value.binding.ipc_session_id===sessionId&&value.catalog_approval_ref.digest===row[3]&&
   value.catalog_approval_ref.id===catalog.approval_id&&catalog.device_session_id===value.binding.device_session_id,'execution_binding_stale');
  const q=catalog.qualification;
  need(q.qualification==='fixed_memory_control_catalog/1'&&q.module_digest===moduleDigest&&q.protocol_io_policy_digest===policyDigest&&q.template_digest===templateDigest,'execution_binding_qualification');
  const sample=db.prepare('SELECT body_jcs,body_digest FROM device_baseline_sample WHERE approval_id=? ORDER BY length(sample_sequence) DESC,sample_sequence DESC LIMIT 1').raw().get(catalog.approval_id);
  need(sample,'execution_binding_sample');const baseline=read(db,...sample);
  need(baseline.device_id===device&&baseline.device_session_id===value.binding.device_session_id&&baseline.catalog_approval_ref.digest===row[3],'execution_binding_sample');
  matches.push({ref:{id:value.binding_id,revision:'1',digest:row[1]},value,catalog,baseline});
 }
 need(matches.length===1,'execution_binding_current');return frozen(matches[0]);
}

// 固定内存模块的核心内部装配来源。记录实际连接及不可变编码/传输配置，保持关闭；
// 它不替代运行握手、完整屏障、主体授权、T2或设备发送许可。
export function bindDeviceExecution(db,runtime,catalog){
 need(Number(db.pragma('user_version',{simple:true}))>=29&&!db.inTransaction,'execution_binding_migration');
 const approved=catalog.approval,q=approved.qualification,sample=catalog.sample;
 need(q.qualification==='fixed_memory_control_catalog/1'&&q.module_digest===moduleDigest&&q.protocol_io_policy_digest===policyDigest&&sample,'execution_binding_qualification');
 need(same(approved.runtime_binding_ref,runtime.ref)&&sample.device_session_id===approved.device_session_id,'execution_binding_runtime');
 return db.transaction(()=>{
  const sessionRow=db.prepare(`SELECT s.binding_jcs,s.binding_digest FROM execution_session s LEFT JOIN execution_session_end e USING(ipc_session_id)
   WHERE s.runtime_id=? AND e.ipc_session_id IS NULL`).raw().get(runtime.ref.object_id);
  need(sessionRow,'execution_binding_session');const session=read(db,...sessionRow);
  const evidenceRow=db.prepare('SELECT body_jcs,body_digest FROM extension_approval_capabilities WHERE approval_id=?').raw().get(q.approval_ref.object_id);
  need(evidenceRow,'execution_binding_capability');const evidence=read(db,...evidenceRow);
  need(evidence.documents.filter(v=>same(v.template,template)&&hash(v.template)===q.template_digest).length===1,'execution_binding_capability');
  const old=db.prepare('SELECT body_jcs,body_digest FROM device_execution_binding WHERE catalog_approval_id=?').raw().get(approved.approval_id);
  if(old){const value=read(db,...old);need(value.session_ref.id===session.ipc_session_id&&value.session_ref.digest===sessionRow[1]&&same(value.runtime_binding_ref,runtime.ref),'execution_binding_stale');
   return frozen({ref:ref(value.binding_id,value),value});}
  const id=crypto.randomUUID(),exit='exit_'+hash({ipc_session_id:session.ipc_session_id,device_id:approved.device_id,device_session_id:approved.device_session_id}).slice(7);
  const binding={scope:{authority_service_id:session.service_id,database_instance_id:session.database_instance_id},controller_boot_id:session.controller_boot_id,worker_boot_id:session.worker_boot_id,
   ipc_session_id:session.ipc_session_id,writer_exit_id:exit,device_id:approved.device_id,device_session_id:approved.device_session_id,clock_domain_id:session.clock_domain_id,descriptor_digest:session.descriptor_digest};
  const action=template.actions[0],profile={format:'leafseamer-memory-transport/1',profile_id:id+'-transport',module_digest:moduleDigest,policy_digest:policyDigest,
   transport:'memory',max_packet_bytes:8,max_in_flight:1,automatic_resends:false,external_resources:[]};
  const plan={format:'leafseamer-memory-primitive-plan/1',plan_id:id+'-plan',primitive_id:'simulator_value_set',action_id:action.action_id,capability_version:action.capability_version,
   parameters_schema_digest:action.parameters_schema.digest,packet:{length:8,prefix_hex:'4c534d31',value_offset:4,value_encoding:'int32_be'},retry:'never'};
  const value={format:'leafseamer-device-execution-binding/1',binding_id:id,state:'bound_closed',write_eligible:false,binding,runtime_binding_ref:runtime.ref,
   session_ref:ref(session.ipc_session_id,session),catalog_approval_ref:ref(approved.approval_id,approved),initial_sample_ref:ref(sample.sample_id,sample),
   capability_ref:{id:q.approval_ref.object_id,revision:'1',digest:evidenceRow[1]},transport_profile:profile,transport_profile_ref:ref(profile.profile_id,profile),
   primitive_plan:plan,primitive_plan_ref:ref(plan.plan_id,plan),exit:{socket_instance_id:'memory_'+exit.slice(5),protocol_session:null},
   action:{action_id:action.action_id,capability_version:action.capability_version,parameters_schema_digest:action.parameters_schema.digest,result_schema_digest:action.result_schema.digest}};
  const transaction=crypto.randomUUID();
  need(db.prepare('INSERT INTO device_execution_binding VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,session.ipc_session_id,approved.approval_id,sample.sample_id,exit,approved.device_id,approved.device_session_id,canonicalize(value),hash(value),transaction).changes===1,'execution_binding_storage');
  need(db.prepare('INSERT INTO device_execution_binding_commit VALUES(?,?,?)').run(id,transaction,canonicalize({kind:'device_execution_bound_closed',binding_id:id,binding_digest:hash(value)})).changes===1,'execution_binding_storage');
  return frozen({ref:ref(id,value),value});
 }).immediate();
}
