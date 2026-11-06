import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import canonicalize from 'canonicalize';
import {captureInitialDenials,readInitialDenials} from '../dist/device-initial-denials.mjs';
import {deviceExecutionCapabilities} from '../dist/sdk/device-execution.mjs';
const digest=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const rawDigest=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');

// 来源读取器的合成SQLite反例；完整帧Schema、监督身份与持久原件由原生联调用例另行验证。
function fixture(t){
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec(`CREATE TABLE service_state(service_id TEXT,database_instance_id TEXT,schema_revision TEXT);
 CREATE TABLE ca_command_initial(command_id TEXT);
 CREATE TABLE execution_session(ipc_session_id TEXT,binding_jcs TEXT,binding_digest TEXT);
 CREATE TABLE execution_frame_record(record_id TEXT,transaction_id TEXT,direction TEXT,record_jcs TEXT,record_digest TEXT,
 frame_jcs TEXT,frame_digest TEXT,wire BLOB,wire_digest TEXT,message_type TEXT,ipc_session_id TEXT,sequence TEXT);
 CREATE TABLE execution_effect_commit(record_id TEXT,transaction_id TEXT,disposition TEXT);`);
 const service={service_id:'controller',database_instance_id:'database',schema_revision:'44'};
 db.prepare('INSERT INTO service_state VALUES(?,?,?)').run(service.service_id,service.database_instance_id,service.schema_revision);
 const binding={authority:'controller',service_id:service.service_id,database_instance_id:service.database_instance_id,ipc_session_id:'session'};
 db.prepare('INSERT INTO execution_session VALUES(?,?,?)').run(binding.ipc_session_id,canonicalize(binding),digest(binding));
 function add(id,type='HELLO_ACK',body={selected_features:deviceExecutionCapabilities.base}){
  const value={ipc_session_id:'session',type,message_id:id,seq:id==='a'?'1':'2',body},payload=Buffer.from(JSON.stringify(value)),wire=Buffer.alloc(payload.length+4);
  wire.writeUInt32BE(payload.length);payload.copy(wire,4);
  const record={record_id:id,session_ref:{id:'session',revision:'1',digest:digest(binding)},direction:'c2w',message_type:type,
   sequence:value.seq,message_id:id,frame_digest:digest(value),wire_digest:rawDigest(wire),wire_length:wire.length};
  const sealed={...record,record_digest:digest(record)};
  db.prepare('INSERT INTO execution_frame_record VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(id,id,'c2w',canonicalize(sealed),sealed.record_digest,
   canonicalize(value),digest(value),wire,rawDigest(wire),type,'session',value.seq.padStart(20,'0'));
  db.prepare("INSERT INTO execution_effect_commit VALUES(?,?,'applied')").run(id,id);
 }
 add('a');
 return {db,service,add,run:fn=>db.transaction(fn).immediate(),capture:()=>db.transaction(()=>captureInitialDenials(db,service,'device')).immediate()};
}
test('首次快照必须处于writer，零水位绑定真实scope和设备；后续版本不能沿用首次捕获',t=>{
 const f=fixture(t);assert.throws(()=>captureInitialDenials(f.db,f.service,'device'),/initial_denials_writer/);
 const source=f.capture();assert.equal(source.run_deny_snapshot.snapshot_revision,'0');assert.equal(source.command_deny_snapshot.device_id,'device');
 assert.equal(source.outgoing_frame_refs.length,1);
 f.add('b');assert.notDeepEqual(f.capture(),source);
 assert.deepEqual(f.run(()=>readInitialDenials(f.db,f.service,'device',source)),source);
 f.db.exec("UPDATE service_state SET schema_revision='56'");f.service.schema_revision='56';
 assert.throws(f.capture,/initial_denials_schema/);
 assert.deepEqual(f.run(()=>readInitialDenials(f.db,f.service,'device',source)),source);
});
test('任意设备的已受理命令或不再属于首次关闭的执行历史阻止空快照',t=>{
 const f=fixture(t);f.db.exec("INSERT INTO ca_command_initial VALUES('other_device_command')");
 assert.throws(f.capture,/initial_denials_command_history/);f.db.exec('DELETE FROM ca_command_initial');
 f.add('b','FENCE',{issued_cut_revision:'1',target_gate_revision:'1',attempt_binding:{attempt_ordinal:'1',previous_barrier_id:null},
  open_intents:[],open_transmission_intents:[],cancel_transmissions:[]});assert.throws(f.capture,/initial_denials_fence_history/);
});
test('拒绝能力、缺少提交、损坏原wire、错scope与重算空快照摘要均不能成为来源',t=>{
 const f=fixture(t),source=f.capture();
 const changed=structuredClone(source);changed.command_deny_snapshot.device_id='other';
 const {snapshot_digest,...body}=changed.command_deny_snapshot;changed.command_deny_snapshot.snapshot_digest=digest(body);
 assert.throws(()=>f.run(()=>readInitialDenials(f.db,f.service,'device',changed)),/initial_denials_snapshot/);
 assert.throws(()=>f.run(()=>readInitialDenials(f.db,f.service,'other',source)),/initial_denials_source/);
 f.db.exec("UPDATE execution_effect_commit SET disposition='rejected'");assert.throws(f.capture,/initial_denials_binding/);
 f.db.exec("DELETE FROM execution_effect_commit");assert.throws(f.capture,/initial_denials_frame_missing/);
 const g=fixture(t);g.add('b','HELLO_ACK',{selected_features:[...deviceExecutionCapabilities.base,...deviceExecutionCapabilities.automation]});
 assert.throws(g.capture,/initial_denials_features/);
 const h=fixture(t);h.db.exec("UPDATE execution_frame_record SET wire=x'000000017b'");assert.throws(h.capture,/initial_denials_integrity/);
});
