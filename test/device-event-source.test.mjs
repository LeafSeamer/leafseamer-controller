import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import Database from 'better-sqlite3';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));assert.ok(path.isAbsolute(root));
const load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const {canonical,digest}=await load('auth-clock-value.mjs'),{deviceEventSourceStore}=await load('device-event-source.mjs');
const {qualifyDeviceFootprint}=await load('device-footprint-qualification.mjs'),{qualifyDeviceEventFrame}=await load('device-event-qualification.mjs');
const {readSourceProjectionCut}=await load('device-source-projection.mjs');
const {createDeviceModule,simulatorControlCatalog}=await load('simulator-control-module.mjs');
const review=JSON.parse(fs.readFileSync(path.join(root,'dist/simulator-event-review.json')));
async function fixture(t,projection=false){
 const directory=projection?fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-source-projection-')):null;
 const readers=[],db=new Database(directory?path.join(directory,'source.sqlite'):':memory:');t.after(()=>{for(const reader of readers)reader.close();db.close();if(directory){assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));fs.rmSync(directory,{recursive:true,force:true});}});db.pragma('foreign_keys=ON');
 // 使用实际领域SQL与writer；上游运行和目录在本测试中为可信投影，完整链由原生集成覆盖。
 db.exec('CREATE TABLE device_module_channel(channel_id TEXT PRIMARY KEY); CREATE TABLE device_catalog_approval(approval_id TEXT PRIMARY KEY,channel_id TEXT,device_id TEXT,device_session_id TEXT); CREATE TABLE device_module_frame(message_id TEXT PRIMARY KEY,channel_id TEXT,message_type TEXT,direction TEXT,frame_jcs TEXT,frame_digest TEXT);');
 db.exec(fs.readFileSync(path.join(root,'dist/device-event-source.sql'),'utf8').split('CREATE TABLE device_event_source (')[1].replace(/^/,'CREATE TABLE device_event_source ('));
 if(projection){db.exec('CREATE TABLE device_source_notification ('+fs.readFileSync(path.join(root,'dist/device-source-projection.sql'),'utf8').split('CREATE TABLE device_source_notification (')[1]);db.pragma('user_version=67');db.pragma('journal_mode=WAL',{simple:true});}
 db.exec("INSERT INTO device_module_channel VALUES('channel'); INSERT INTO device_catalog_approval VALUES('approval','channel','device','session')");
 const runtime={current_boot:true,withdrawal:null,ref:{kind:'runtime_binding',authority_service_id:'service',database_instance_id:'database',object_id:'runtime',revision:'1',digest:digest('runtime')},
  binding:{service_id:'service',database_instance_id:'database',launch_intent:{member_id:'member'},admission_receipt:{member_boot_id:'boot'},clock_domain_descriptor:{test:'synthetic-domain'}}};
 const qualification={qualification:'fixed_memory_control_catalog/1',module_digest:review.module_digest,protocol_io_policy_digest:review.protocol_io_policy_digest,template_digest:review.template_digest,manifest_digest:digest('manifest'),resource_ref:{object_id:'resource',digest:digest('resource')}};
 const approved={format:'leafseamer-catalog-approval/3',approval_id:'approval',runtime_binding_ref:runtime.ref,qualification,channel_id:'channel',device_id:'device',device_session_id:'session',catalog:simulatorControlCatalog()};
 approved.footprint_qualification=qualifyDeviceFootprint({...approved,runtime});
 let tick=100n,sequence=1;const signal=new AbortController().signal,input={device_id:'device',device_session_id:'session',capture_id:'capture',signal},module=createDeviceModule({configuration:{},device_ids:['device'],signal,tick:()=>tick++});await module.connectReadOnly(input);
 const envelope=(type,body)=>({version:'device-module/4',type,sequence:String(++sequence),request_id:'response-'+sequence,reply_to:'request-'+sequence,binding:{runtime_binding_ref:runtime.ref,ipc_session_id:'channel',member_boot_id:'boot'},issued_tick_ns:'1',deadline_tick_ns:'1000',body:{device_id:'device',device_session_id:'session',capture_id:'capture',...body}});
 const save=(frame,direction='w2c')=>db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?,?)').run(frame.request_id,'channel',frame.type,direction,canonical(frame),digest(frame));
 const started=envelope('EVENT_STARTED',{capture:module.events.start(input)});save(started);
 const catalog={current:()=>({approval:approved}),currentEventCapture:()=>qualifyDeviceEventFrame({approved,runtime,frame:started})};
 const store=deviceEventSourceStore({db,current:()=>runtime,catalog});
 const write=async value=>module.execution.writePrimitive({...input,bytes:await module.execution.encodePrimitive({...input,primitive_id:'simulator_value_set',parameters:{value}})});
 const batch=(after='0')=>{const frame=envelope('EVENT_BATCH',{result:module.events.read({...input,after_sequence:after,max_events:32})});save(frame);return frame;};
 const count=table=>db.prepare('SELECT count(*) FROM '+table).pluck().get();
 return {db,store,started,write,batch,envelope,save,count,runtime,openReader(){const reader=new Database(db.name,{readonly:true,fileMustExist:true});readers.push(reader);return reader;}};
}
test('来源事件和outbox原子保存，重复批次复用原件，无时间证明如实为空',async t=>{
 const f=await fixture(t),registration=f.store.start(f.started);assert.deepEqual(f.store.start(f.started),registration);
 await f.write(7);await f.write(23);const batch=f.batch(),receipt=f.store.accept(batch);assert.equal(receipt.record_ids.length,2);assert.deepEqual(f.store.accept(batch),receipt);
 assert.deepEqual(f.store.accept(f.batch()).record_ids,receipt.record_ids);assert.equal(f.count('device_source_event'),2);assert.equal(f.count('device_source_event_outbox'),2);
 const records=f.store.read(f.started);assert.equal(records.highest_committed_sequence,'2');assert.equal(records.fault,null);assert.deepEqual(records.events.map(e=>e.origin.payload.value.value),[7,23]);assert.ok(records.events.every(e=>e.origin.source_time_ref===null&&digest(e.origin)===e.origin_digest));assert.equal(f.store.read(f.started,'1').events.length,1);assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
});
test('outbox故障回滚事件和批次，未提交ACK拒绝，重试提交后才允许ACK',async t=>{
 const f=await fixture(t);f.store.start(f.started);await f.write(7);const batch=f.batch();
 const ack=f.envelope('EVENT_ACK',{batch_digest:batch.body.result.batch_digest,through_sequence:'1'});
 assert.throws(()=>f.save(ack,'c2w'),/source_ack_uncommitted/);
 f.db.exec("CREATE TRIGGER inject_outbox_failure BEFORE INSERT ON device_source_event_outbox BEGIN SELECT RAISE(ABORT,'injected_failure'); END");
 assert.throws(()=>f.store.accept(batch),/injected_failure/);for(const table of ['device_source_event','device_source_event_outbox','device_source_batch'])assert.equal(f.count(table),0);
 assert.throws(()=>f.save(ack,'c2w'),/source_ack_uncommitted/);f.db.exec('DROP TRIGGER inject_outbox_failure');f.store.accept(batch);f.save(ack,'c2w');assert.equal(f.count('device_source_event'),1);
});
test('忽略写入不能返回已提交批次，所有来源写集一并回滚',async t=>{
 for(const table of ['device_source_event','device_source_event_outbox','device_source_batch']){
  const f=await fixture(t);f.store.start(f.started);await f.write(7);const batch=f.batch();
  f.db.exec('CREATE TRIGGER omit_write BEFORE INSERT ON '+table+' BEGIN SELECT RAISE(IGNORE); END');assert.throws(()=>f.store.accept(batch),{code:'source_storage'});
  for(const name of ['device_source_event','device_source_event_outbox','device_source_batch'])assert.equal(f.count(name),0);
 }
});
test('重算摘要后的身份冲突拒绝，停止与运行失效不能恢复来源',async t=>{
 const f=await fixture(t);f.store.start(f.started);await f.write(7);const first=f.batch();f.store.accept(first);
 const conflict=structuredClone(first);conflict.request_id='conflict';conflict.body.result.batch.events[0].event_id='different';conflict.body.result.batch_digest=digest(conflict.body.result.batch);f.save(conflict);assert.throws(()=>f.store.accept(conflict),{code:'source_conflict'});
 const stopped=f.envelope('EVENT_STOPPED',{closed:{acknowledged_sequence:'0',last_sequence:'1'}});f.save(stopped);f.store.stop(stopped);assert.equal(f.store.read(f.started).fault.reason,'capture_stopped');assert.throws(()=>f.store.accept(f.batch()),{code:'source_closed'});f.store.close();assert.equal(f.store.read(f.started).fault.reason,'capture_stopped');f.runtime.current_boot=false;assert.throws(()=>f.store.read(f.started),{code:'source_runtime'});
});
test('跳过来源序号拒绝，缺少outbox或缺少事件不能提交',async t=>{
 const f=await fixture(t),registration=f.store.start(f.started);await f.write(7);await f.write(23);const batch=f.batch(),gap=structuredClone(batch);
 gap.request_id='gap';gap.body.result.batch.after_sequence='1';gap.body.result.batch.events.shift();gap.body.result.batch_digest=digest(gap.body.result.batch);f.save(gap);assert.throws(()=>f.store.accept(gap),{code:'source_gap'});
 assert.throws(()=>f.db.prepare('INSERT INTO device_source_batch VALUES(?,?,?,?,?)').run(batch.request_id,registration.registration_id,batch.body.result.batch_digest,'2','{}'),/source_batch_parent/);
 const event=batch.body.result.batch.events[0],origin={source_key:registration.source_key,binding_ref:registration.binding_ref,event_id:event.event_id,source_sequence:event.sequence,payload:{schema_ref:registration.payload_schema_ref,value:event.payload},source_time_ref:null};
 assert.throws(()=>f.db.transaction(()=>f.db.prepare('INSERT INTO device_source_event VALUES(?,?,?,?,?,?,?,?,?)').run('orphan',registration.registration_id,event.event_id,event.sequence,canonical(origin),digest(origin),batch.request_id,canonical(event),'tx')).immediate(),/FOREIGN KEY/);
 assert.equal(f.count('device_source_event'),0);assert.equal(f.count('device_source_event_outbox'),0);f.store.accept(batch);assert.equal(f.count('device_source_event'),2);
});
test('67版实际来源写入同事务投影与有序通知，重投不推进水位，独立读保持一致切点',async t=>{
 const f=await fixture(t,true),source=f.store.start(f.started),scope={sources:[{source_key:source.source_key,binding_ref:source.binding_ref}]};
 const reader=f.openReader();
 const initial=readSourceProjectionCut(reader,scope);assert.equal(initial.journal_sequence,'1');assert.equal(initial.records[0].view.contiguous_sequence,'0');assert.equal(initial.records[0].view.state,'baseline_required');
 reader.exec('BEGIN');assert.equal(reader.prepare('SELECT max(sequence) FROM device_source_notification').pluck().get(),1);
 await f.write(7);await f.write(23);const batch=f.batch();f.store.accept(batch);
 assert.equal(reader.prepare('SELECT max(sequence) FROM device_source_notification').pluck().get(),1);assert.equal(reader.prepare('SELECT revision FROM device_source_projection_head').pluck().get(),1);reader.exec('COMMIT');
 const cut=readSourceProjectionCut(reader,scope);assert.equal(cut.journal_sequence,'4');assert.equal(cut.records[0].entity_revision,'2');assert.equal(cut.records[0].view.contiguous_sequence,'2');assert.equal(cut.source_watermarks[0].baseline_sequence,'2');
 assert.deepEqual(f.db.prepare('SELECT entry_kind FROM device_source_notification ORDER BY sequence').pluck().all(),['entity.upsert','source.event','source.event','entity.upsert']);
 f.store.accept(batch);f.store.accept(f.batch());assert.deepEqual(readSourceProjectionCut(reader,scope),cut);assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
 const script=`import sys,json
from jsonschema import Draft202012Validator,FormatChecker
graph=json.load(open(sys.argv[1],encoding='utf8')); data=json.load(sys.stdin)
for model,key in [('snapshot__Record','records'),('snapshot__Watermark','source_watermarks')]:
 for value in data[key]: Draft202012Validator({'$ref':'#/$defs/'+model,'$defs':graph['$defs']},format_checker=FormatChecker()).validate(value)
`;
 const checked=spawnSync(process.env.LEAFSEAMER_SCHEMA_PYTHON??'python',['-I','-B','-c',script,path.join(root,'dist/sdk/contract/models.schema.json')],{input:JSON.stringify(cut),encoding:'utf8',windowsHide:true});assert.equal(checked.status,0,checked.stderr||checked.error?.message);
});
test('67版投影或通知任一缺写回滚来源、事件和批次，不能提交没有投影的来源状态',async t=>{
 for(const table of ['device_source_notification','device_source_projection','device_source_projection_head']){
  const f=await fixture(t,true);f.db.exec('CREATE TRIGGER omit_source_projection BEFORE INSERT ON '+table+' BEGIN SELECT RAISE(IGNORE); END');
  assert.throws(()=>f.store.start(f.started),{code:'source_projection_storage'});assert.equal(f.count('device_event_source'),0);assert.equal(f.count('device_source_notification'),0);f.db.exec('DROP TRIGGER omit_source_projection');
  f.store.start(f.started);await f.write(7);const batch=f.batch();f.db.exec('CREATE TRIGGER omit_source_projection BEFORE '+(table==='device_source_projection_head'?'UPDATE':'INSERT')+' ON '+table+' BEGIN SELECT RAISE(IGNORE); END');
  assert.throws(()=>f.store.accept(batch),{code:'source_projection_storage'});assert.equal(f.count('device_source_event'),0);assert.equal(f.count('device_source_event_outbox'),0);assert.equal(f.count('device_source_batch'),0);assert.equal(f.count('device_source_notification'),1);
  f.db.exec('DROP TRIGGER omit_source_projection');f.store.accept(batch);assert.equal(f.count('device_source_event'),1);
 }
});
test('67版停止丢弃区间与失联未知缺口如实投影，故障和投影同事务且不可清除',async t=>{
 const f=await fixture(t,true);f.store.start(f.started);await f.write(7);f.store.accept(f.batch());await f.write(23);
 const stopped=f.envelope('EVENT_STOPPED',{closed:{acknowledged_sequence:'1',last_sequence:'2',discarded_events:1,failure:null}});f.save(stopped);
 f.db.exec('CREATE TRIGGER omit_source_projection BEFORE INSERT ON device_source_projection BEGIN SELECT RAISE(IGNORE); END');assert.throws(()=>f.store.stop(stopped),{code:'source_projection_storage'});assert.equal(f.count('device_source_fault'),0);f.db.exec('DROP TRIGGER omit_source_projection');
 f.store.stop(stopped);const current=()=>JSON.parse(f.db.prepare('SELECT record_jcs FROM device_source_projection r JOIN device_source_projection_head h USING(registration_id,revision)').pluck().get()).view;
 const closed=current();assert.equal(closed.state,'closed');assert.equal(closed.contiguous_sequence,'1');assert.equal(closed.highest_seen_sequence,'2');assert.deepEqual(closed.gaps.map(g=>[g.loss_extent,g.first_missing,g.last_missing]),[['known','2','2']]);f.store.close();assert.deepEqual(current(),closed);
 const other=await fixture(t,true);other.store.start(other.started);other.store.close();const unknown=JSON.parse(other.db.prepare('SELECT record_jcs FROM device_source_projection r JOIN device_source_projection_head h USING(registration_id,revision)').pluck().get()).view.gaps[0];assert.equal(unknown.loss_extent,'unknown');assert.equal(unknown.first_missing,null);assert.equal(unknown.last_missing,null);
});
