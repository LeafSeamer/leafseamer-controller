import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import canonicalize from 'canonicalize';
import {currentDeviceExecutionBinding} from '../dist/device-execution-binding.mjs';
import {withExecutionReadView} from '../dist/execution-read-view.mjs';
const bytesDigest=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
const hash=value=>bytesDigest(canonicalize(value));

// 合成存储读取器反例；运行来源、设备写入和持久完整性由原生联调另行验证。
function fixture(t){
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec(`CREATE TABLE device_execution_binding(body_jcs TEXT,body_digest TEXT,catalog_approval_id TEXT,ipc_session_id TEXT,device_id TEXT);
 CREATE TABLE device_catalog_approval(approval_id TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE device_module_frame(channel_id TEXT,direction TEXT,message_type TEXT,frame_jcs TEXT,sequence TEXT);
 CREATE TABLE device_baseline_sample(approval_id TEXT,sample_sequence TEXT,body_jcs TEXT,body_digest TEXT);`);
 const runtime={ref:{object_id:'runtime',revision:'1',digest:hash('runtime')}};
 const catalog={approval_id:'catalog',channel_id:'channel',runtime_binding_ref:runtime.ref,device_session_id:'device.session',qualification:{
  qualification:'fixed_memory_control_catalog/1',module_digest:bytesDigest(fs.readFileSync(new URL('../dist/simulator-control-module.mjs',import.meta.url))),
  protocol_io_policy_digest:bytesDigest(fs.readFileSync(new URL('../dist/simulator-control-policy.json',import.meta.url))),
  template_digest:hash(JSON.parse(fs.readFileSync(new URL('../dist/simulator-control-capability.json',import.meta.url))))}};
 const value={binding_id:'binding',binding:{device_id:'device',ipc_session_id:'ipc',device_session_id:'device.session'},runtime_binding_ref:runtime.ref,
  catalog_approval_ref:{id:'catalog',revision:'1',digest:hash(catalog)}};
 db.prepare('INSERT INTO device_catalog_approval VALUES(?,?,?)').run('catalog',canonicalize(catalog),hash(catalog));
 db.prepare('INSERT INTO device_execution_binding VALUES(?,?,?,?,?)').run(canonicalize(value),hash(value),'catalog','ipc','device');
 db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?)').run('channel','w2c','CONNECTED',canonicalize({body:{device_id:'device',device_session_id:'device.session'}}),'1');
 function sample(sequence){const value={sample_id:'sample.'+sequence,device_id:'device',device_session_id:'device.session',catalog_approval_ref:{id:'catalog',revision:'1',digest:hash(catalog)}};
  db.prepare('INSERT INTO device_baseline_sample VALUES(?,?,?,?)').run('catalog',sequence,canonicalize(value),hash(value));}
 sample('1');return {db,sample,current:()=>currentDeviceExecutionBinding(db,runtime,'device','ipc')};
}
test('复用装配原件后仍读取最新基线和连接状态',t=>{
 const f=fixture(t);f.db.transaction(()=>withExecutionReadView(f.db,()=>{
  assert.equal(f.current().baseline.sample_id,'sample.1');f.sample('2');
  assert.equal(f.current().baseline.sample_id,'sample.2');
  f.db.exec("UPDATE device_module_frame SET message_type='DISCONNECTED'");
  assert.throws(f.current,/execution_binding_current/);
 })).immediate();
});
test('重复读取不能掩盖原件字节损坏',t=>{
 const f=fixture(t);f.db.transaction(()=>withExecutionReadView(f.db,()=>{
  f.current();f.db.exec("UPDATE device_execution_binding SET body_jcs='{}'");
  assert.throws(f.current,/execution_binding_integrity/);
 })).immediate();
});
