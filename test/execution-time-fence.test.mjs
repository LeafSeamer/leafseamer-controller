import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import test from 'node:test';
import Database from 'better-sqlite3';
import {canonical,digest} from '../dist/auth-clock-value.mjs';
import {decodeExecutionPayload} from '../dist/device-execution-channel.mjs';
import {deviceExecutionGate} from '../dist/device-execution-gate.mjs';
import {executionTick} from '../dist/device-execution-handshake.mjs';
import {selectTimeFence,commitTimeFence,currentTimeFence,acceptTimeFence} from '../dist/execution-time-fence.mjs';
import {deviceExecutionCapabilities as capabilities,deviceExecutionVersion} from '../dist/sdk/device-execution.mjs';

const bytesHash=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
const ref=(id,hash=digest(id))=>({id,revision:'1',digest:hash});
const manual=[...capabilities.base,...capabilities.manual,...capabilities.without_reference];
const features=[...capabilities.base,...capabilities.manual,...capabilities.reference];
const raw=value=>Buffer.from(JSON.stringify(value));

function fixture(t){
 const db=new Database(':memory:');t.after(()=>db.close());
 // 只装入与本轮无关的既存来源。时间屏障表、外键及领域触发器使用发行迁移原件。
 db.exec(`PRAGMA user_version=112;
 CREATE TABLE time_provider_reference_invalidation(operation_id TEXT,service_boot_id TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE time_provider_reference_protection(operation_id TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE time_provider_reference_exit_cut(operation_id TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE time_provider_reference_exit_target(operation_id TEXT,exit_id TEXT,binding_id TEXT,ipc_session_id TEXT,body_jcs TEXT,body_digest TEXT,
  UNIQUE(operation_id,exit_id,body_digest));
 CREATE TABLE time_provider_reference_exit_retired(operation_id TEXT,exit_id TEXT);
 CREATE TABLE device_execution_binding(binding_id TEXT,body_jcs TEXT,body_digest TEXT,catalog_approval_id TEXT,ipc_session_id TEXT,device_id TEXT);
 CREATE TABLE device_catalog_approval(approval_id TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE device_module_frame(channel_id TEXT,direction TEXT,message_type TEXT,frame_jcs TEXT,sequence TEXT);
 CREATE TABLE device_baseline_sample(approval_id TEXT,sample_sequence TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE command_final_admission(binding_id TEXT,transaction_id TEXT,permit_id TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE command_transmission_issue(transaction_id TEXT,permit_id TEXT,issued_revision TEXT);
 CREATE TABLE execution_frame_record(record_id TEXT PRIMARY KEY,ipc_session_id TEXT,direction TEXT,sequence TEXT,message_id TEXT,message_type TEXT,device_id TEXT,
  reply_record_id TEXT, wire BLOB,frame_jcs TEXT,wire_digest TEXT,frame_digest TEXT,record_jcs TEXT,record_digest TEXT,
  observed_tick TEXT,transaction_id TEXT,domain_kind TEXT,UNIQUE(record_id,transaction_id),
  FOREIGN KEY(record_id,transaction_id) REFERENCES execution_effect_commit(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED);
 CREATE TABLE execution_effect_commit(record_id TEXT,transaction_id TEXT,disposition TEXT,committed_tick TEXT,audit_jcs TEXT,audit_digest TEXT,
  effect_jcs TEXT,effect_digest TEXT,UNIQUE(record_id,transaction_id));
 CREATE TABLE execution_write_attempt(attempt_id TEXT PRIMARY KEY,record_id TEXT REFERENCES execution_frame_record(record_id),started_tick TEXT);`);
 const migration=fs.readFileSync(new URL('../dist/execution-time-fence.sql',import.meta.url),'utf8');
 db.exec(migration.slice(migration.indexOf('CREATE TABLE execution_time_fence_frame'),migration.indexOf('CREATE TRIGGER execution_frame_parent')));
 const scope={authority_service_id:'service',database_instance_id:'database'},operation='operation',exit='exit',service_boot_id='boot';
 const domain={clock_domain_id:'clock_'+'1'.repeat(64),descriptor_digest:'sha256:'+'2'.repeat(64)};
 const binding={ipc_version:deviceExecutionVersion,ipc_session_id:'ipc',controller_boot_id:'controller',worker_boot_id:'worker',service_boot_id,...domain};
 const worker={...domain,scope,ipc_session_id:binding.ipc_session_id,controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,
  device_id:'device',device_session_id:'device.session',writer_exit_id:exit};
 const runtime={ref:{object_id:'runtime',revision:'1',digest:digest('runtime')}};
 const catalog={approval_id:'catalog',channel_id:'channel',runtime_binding_ref:runtime.ref,device_session_id:worker.device_session_id,qualification:{
  qualification:'fixed_memory_control_catalog/1',module_digest:bytesHash(fs.readFileSync(new URL('../dist/simulator-control-module.mjs',import.meta.url))),
  protocol_io_policy_digest:bytesHash(fs.readFileSync(new URL('../dist/simulator-control-policy.json',import.meta.url))),
  template_digest:digest(JSON.parse(fs.readFileSync(new URL('../dist/simulator-control-capability.json',import.meta.url))))}};
 const catalogRef=ref('catalog',digest(catalog));
 const bound={binding_id:'binding',binding:worker,runtime_binding_ref:runtime.ref,catalog_approval_ref:catalogRef};
 db.prepare('INSERT INTO device_catalog_approval VALUES(?,?,?)').run('catalog',canonical(catalog),catalogRef.digest);
 db.prepare('INSERT INTO device_execution_binding VALUES(?,?,?,?,?,?)').run('binding',canonical(bound),digest(bound),'catalog','ipc','device');
 db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?)').run('channel','w2c','CONNECTED',canonical({body:{device_id:'device',device_session_id:worker.device_session_id}}),'1');
 const sample={device_id:'device',device_session_id:worker.device_session_id,catalog_approval_ref:catalogRef};
 db.prepare('INSERT INTO device_baseline_sample VALUES(?,?,?,?)').run('catalog','1',canonical(sample),digest(sample));
 db.prepare("INSERT INTO execution_frame_record(record_id,ipc_session_id,direction,sequence) VALUES('hello','ipc','c2w',?)").run(executionTick(1n));

 const old_binding={domain:{...domain,...scope,provider_id:'provider',provider_boot_id:'provider.boot',runtime_binding_ref:ref('time.runtime'),
  clock_generation:'1'},time_generation:'1',source_ref:ref('source'),profile_ref:ref('profile'),approval_ref:ref('approval'),policy_ref:ref('policy')};
 const body={operation_id:operation,service_boot_id,domain_ref:domain,minimum_time_generation:'2',old_binding};
 const cause_ref=ref(operation,digest(body));
 const target={exit_id:exit,device_id:worker.device_id,ipc_session_id:'ipc',device_binding_ref:ref('binding',digest(bound)),
  runtime_ref:ref(runtime.ref.object_id,runtime.ref.digest)};
 const targetRef=ref(exit,digest(target)),cut={invalidation_ref:cause_ref,domain_ref:domain,targets:[targetRef]};
 const protection_operation_ref=ref(operation+'.exit-cut',digest(cut));
 const wire={invalidation_id:operation+'.time',revision:'1',old_binding,next_time_generation:'2',cause_ref,deny_new_utc_permits:true,protection_operation_ref};
 const work={invalidation_ref:cause_ref,domain_ref:domain,issued_cut_revision:'0',minimum_time_generation:'2',exit_cut_ref:protection_operation_ref,
  wire_invalidation_ref:ref(wire.invalidation_id,digest(wire))};
 db.prepare('INSERT INTO time_provider_reference_invalidation VALUES(?,?,?,?)').run(operation,service_boot_id,canonical(body),cause_ref.digest);
 db.prepare('INSERT INTO time_provider_reference_exit_cut VALUES(?,?,?)').run(operation,canonical(cut),protection_operation_ref.digest);
 db.prepare('INSERT INTO time_provider_reference_protection VALUES(?,?,?)').run(operation,canonical(work),digest(work));
 db.prepare('INSERT INTO time_provider_reference_exit_target VALUES(?,?,?,?,?,?)').run(operation,exit,'binding','ipc',canonical(target),targetRef.digest);
 return {db,binding,worker,runtime,input:{operation,exit},within:fn=>db.transaction(fn).immediate()};
}

test('持久 TIME_FENCE 需要已协商能力、原出口与关联写入，采用后只读原回执',async t=>{
 const {db,binding,worker,runtime,input,within}=fixture(t),select=features=>selectTimeFence(db,{binding,runtime,input,features});
 assert.throws(()=>within(()=>select(manual)),/execution_feature_missing/);
 assert.throws(()=>within(()=>selectTimeFence(db,{binding,runtime,input:{...input,exit:'other'},features})),/execution_time_fence_target/);
 const candidate=within(()=>select(features));
 await decodeExecutionPayload(raw(candidate.frame),'c2w');
 const saved=within(()=>commitTimeFence(db,{binding,runtime,candidate,tick:()=>8n}));
 assert.equal(saved.ack,null);
 assert.equal(saved.request.frame.seq,'2');
 const id=saved.request.recordRef.id;
 assert.equal(within(()=>currentTimeFence(db,{binding,runtime,id})).request.recordRef.id,id);
 const owner=deviceExecutionGate({binding:worker,tick:()=>10n,signal:new AbortController().signal,failed:()=>{},
  limits:{max_entries:8,max_metadata_bytes:65536}});
 const response=await owner.receive(raw(candidate.frame));
 const {service_boot_id,...envelope}=binding;
 const ack={...envelope,...response,message_id:'response',seq:'2',journal_mode:'durable'};
 async function receive(frame){
  const decoded=await decodeExecutionPayload(raw(frame),'w2c');
  return within(()=>acceptTimeFence(db,{binding,decoded,features,tick:()=>12n,receivedTick:11n}));
 }
 await assert.rejects(receive(ack),/execution_time_fence_reply/);
 db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run('write',id,executionTick(9n));
 await assert.rejects(receive({...ack,body:{...ack.body,minimum_time_generation:'3'}}),/execution_time_fence_reply/);
 assert.equal(db.prepare("SELECT count(*) FROM execution_time_fence_frame WHERE phase='ack'").pluck().get(),0);
 const adopted=await receive(ack),repeated=await receive(ack);
 assert.equal(adopted.ack.recordRef.id,repeated.ack.recordRef.id);
 assert.equal(within(()=>select(features)).saved.ack.recordRef.id,adopted.ack.recordRef.id);
 assert.throws(()=>within(()=>currentTimeFence(db,{binding,runtime,id})),/execution_time_fence_changed/);
 assert.equal(db.prepare('SELECT count(*) FROM execution_effect_commit').pluck().get(),2);
 assert.deepEqual(db.pragma('foreign_key_check'),[]);
});
