import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {registered} from './fixtures/device-bindings.mjs';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));assert.ok(path.isAbsolute(root));
const load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const {digest}=await load('auth-clock-value.mjs'),{qualifyDeviceFootprint}=await load('device-footprint-qualification.mjs');
const {qualifyDeviceEventFrame}=await load('device-event-qualification.mjs'),{createDeviceModule,simulatorControlCatalog}=await load('simulator-control-module.mjs');
const review=JSON.parse(fs.readFileSync(path.join(root,'dist/simulator-event-review.json')));
const {deviceCatalogStore}=await load('device-catalog-store.mjs'),{registerDeviceAutomation}=await load('device-automation-binding.mjs');
const {canonical}=await load('auth-clock-value.mjs'),{openNativeClock}=await load('native-clock.mjs');
async function fixture(){
 const runtime={ref:{kind:'runtime_binding',authority_service_id:'service',database_instance_id:'database',object_id:'runtime',revision:'1',digest:digest('runtime')},
  binding:{service_id:'service',database_instance_id:'database',admission_receipt:{member_boot_id:'boot'},clock_domain_descriptor:{test:'synthetic-domain'}}};
 const qualification={qualification:'fixed_memory_control_catalog/1',module_digest:review.module_digest,protocol_io_policy_digest:review.protocol_io_policy_digest,
  template_digest:review.template_digest,manifest_digest:digest('manifest'),resource_ref:{object_id:'resource',digest:digest('resource')}};
 const approved={format:'leafseamer-catalog-approval/3',approval_id:'approval',runtime_binding_ref:runtime.ref,qualification,channel_id:'channel',device_id:'device',device_session_id:'session',catalog:simulatorControlCatalog()};
 approved.footprint_qualification=qualifyDeviceFootprint({...approved,runtime});
 let tick=100n;const abort=new AbortController(),input={device_id:'device',device_session_id:'session',capture_id:'capture',signal:abort.signal},module=createDeviceModule({configuration:{},device_ids:['device'],signal:abort.signal,tick:()=>tick++});
 await module.connectReadOnly(input);const write=async value=>module.execution.writePrimitive({...input,bytes:await module.execution.encodePrimitive({...input,primitive_id:'simulator_value_set',parameters:{value}})});
 await write(5);const capture=module.events.start(input);await write(-2147483648);await write(2147483647);
 const envelope=(type,sequence,body)=>({version:'device-module/4',type,sequence,request_id:'response-'+sequence,reply_to:'request-'+sequence,
  binding:{runtime_binding_ref:runtime.ref,ipc_session_id:'channel',member_boot_id:'boot'},issued_tick_ns:'1',deadline_tick_ns:'1000',body:{device_id:'device',device_session_id:'session',capture_id:'capture',...body}});
 const started=envelope('EVENT_STARTED','2',{capture}),frame=envelope('EVENT_BATCH','3',{result:module.events.read({...input,after_sequence:'0',max_events:32})});
 return {approved,runtime,started,frame};
}
test('实际模拟器事件绑定固定制品、会话与原写入基线，保留原采集区间',async()=>{
 const f=await fixture(),start=qualifyDeviceEventFrame({...f,frame:f.started}),batch=qualifyDeviceEventFrame(f);
 assert.deepEqual(batch,start);assert.equal(batch.capture.baseline.write_sequence,'1');assert.equal(batch.review.delivery_semantics,'discrete');
 assert.deepEqual(f.frame.body.result.batch.events.map(e=>e.payload),[{value:-2147483648,write_sequence:'2'},{value:2147483647,write_sequence:'3'}]);
 assert.deepEqual(batch.clock_domain_descriptor,f.runtime.binding.clock_domain_descriptor);
 assert.equal(batch.review.module_digest,'sha256:'+ (await import('node:crypto')).createHash('sha256').update(fs.readFileSync(path.join(root,'dist/simulator-control-module.mjs'))).digest('hex'));
});
test('重算摘要不能使错类型、正文或写入序号成为已核验事件',async()=>{
 const original=await fixture();
 for(const change of [
  f=>{f.frame.body.result.batch.events[0].payload.value=2147483648;},
  f=>{f.frame.body.result.batch.events[0].payload.value=1.5;},
  f=>{f.frame.body.result.batch.events[0].payload.value='7';},
  f=>{f.frame.body.result.batch.events[0].payload.extra=true;},
  f=>{f.frame.body.result.batch.events[0].payload.write_sequence='1';},
  f=>{f.frame.body.result.batch.capture.baseline.write_sequence='99999999999999999999';f.started.body.capture.baseline.write_sequence='99999999999999999999';},
  f=>{f.frame.body.result.batch.capture.baseline.extra=0;f.started.body.capture.baseline.extra=0;},
  f=>{for(const e of f.frame.body.result.batch.events)e.event_type='other';f.frame.body.result.batch.capture.event_type='other';f.started.body.capture.event_type='other';}
 ]){
  const f=structuredClone(original);change(f);f.frame.body.result.batch_digest=digest(f.frame.body.result.batch);
  assert.throws(()=>qualifyDeviceEventFrame(f),error=>/^module_event_source_/.test(error.code));
 }
});
test('错运行、错会话、缺原启动和改变的制品资格不得复用事件来源',async()=>{
 const original=await fixture();
 for(const change of [f=>{f.frame.binding.member_boot_id='other';},f=>{f.approved.device_id='other';},f=>{f.started=null;},
  f=>{f.started.sequence='4';},f=>{f.approved.qualification.module_digest=digest('other');},f=>{f.approved.footprint_qualification=null;}]){
  const f=structuredClone(original);change(f);assert.throws(()=>qualifyDeviceEventFrame(f));
 }
});
test('核心读取使用持久启动原件，失败或停止不得恢复资格，错误payload在接收路径拒绝',async t=>{
 // 此处以SQLite投影夹具验证接收路径；完整迁移和监督装配由原生联调覆盖。
 const f=registered(t),sample=await fixture(),db=f.db;
 Object.assign(f.input.runtime.ref,sample.runtime.ref);f.input.runtime.binding.clock_domain_descriptor=sample.runtime.binding.clock_domain_descriptor;
 f.approved.footprint_qualification=qualifyDeviceFootprint({...f.approved,runtime:f.input.runtime});
 f.approved.automation_registration=registerDeviceAutomation(f.approved,f.input.runtime);f.save();
 f.input.selected.content.manifest.api_versions=['leafseamer-device-primitives/1','leafseamer-device-event-capture/1'];
 db.exec("ALTER TABLE device_catalog_approval ADD COLUMN approval_id TEXT; UPDATE device_catalog_approval SET approval_id='catalog'; ALTER TABLE device_module_frame ADD COLUMN message_id TEXT; CREATE TABLE device_baseline_sample(approval_id TEXT,sample_sequence TEXT,body_jcs TEXT,body_digest TEXT)");
 const store=deviceCatalogStore({db,current:()=>f.input.runtime,select:()=>({selected:f.input.selected,dependencies:f.input.dependencies})});
 const started=structuredClone(sample.started);started.sequence='10';
 const save=frame=>db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?,?,?)').run('channel','w2c',frame.sequence,frame.type,canonical(frame),digest(frame),frame.request_id);
 save(started);assert.equal(store.currentEventCapture('channel','device','session').capture_message_id,started.request_id);
 const invalid=structuredClone(sample.frame),now=openNativeClock().tick();invalid.sequence='11';invalid.issued_tick_ns=String(now);invalid.deadline_tick_ns=String(now+2000000000n);
 invalid.body.result.batch.events[0].payload.value='wrong';invalid.body.result.batch_digest=digest(invalid.body.result.batch);save(invalid);
 assert.throws(()=>store.receive(invalid),{code:'module_event_source_schema'});
 db.prepare('DELETE FROM device_module_frame WHERE sequence=?').run('11');
 const failed=structuredClone(sample.frame);failed.sequence='12';failed.body.result.state='failed';failed.body.result.failure={reason:'capacity',loss_extent:'none',missing_sequence:null};save(failed);
 assert.throws(()=>store.currentEventCapture('channel','device','session'),{code:'module_event_source_failed'});
 const later=structuredClone(sample.frame);later.sequence='13';save(later);
 assert.throws(()=>store.currentEventCapture('channel','device','session'),{code:'module_event_source_failed'});
 const stopped={...started,sequence:'14',request_id:'stop',type:'EVENT_STOPPED',body:{device_id:'device',device_session_id:'session',capture_id:'capture'}};save(stopped);
 assert.throws(()=>store.currentEventCapture('channel','device','session'),{code:'module_event_source_inactive'});
});
