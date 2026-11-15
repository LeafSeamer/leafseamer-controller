import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import Database from 'better-sqlite3';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));assert.ok(path.isAbsolute(root));
const asset=name=>path.join(root,'dist',name),load=name=>import(pathToFileURL(asset(name)));
const {canonical,digest}=await load('auth-clock-value.mjs');
const {readDeviceCapabilities}=await load('device-capability-view.mjs');
const {deviceBindingsBundle}=await load('peer-device-bindings.mjs');
const {qualifyDeviceFootprint}=await load('device-footprint-qualification.mjs');
const {registerDeviceAutomation,readDeviceAutomationBindings}=await load('device-automation-binding.mjs');

import {fixture,registered} from './fixtures/device-bindings.mjs';
// 仅验证存储投影与原件一致性；实际运行装配另由原生模拟器集成覆盖。
test('能力读取保留全部Schema原件，不授完整作用范围资格',t=>{
 const f=fixture(t),result=f.read(),action=result.devices[0].actions[0];
 assert.equal(result.module_version,'1.0.0');assert.equal(result.provider_boot_id,'boot');
 assert.deepEqual(result.devices[0].state_schema,f.template.state_schema);
 for(const key of ['parameters_schema','result_schema','preconditions_schema'])assert.deepEqual(action[key],f.template.actions[0][key]);
 assert.equal(action.footprint.complete,false);assert.deepEqual(action.footprint.safe_failure_classes,[]);
 assert.throws(()=>readDeviceCapabilities(f.db,f.input),{code:'device_capabilities_writer'});
});
test('断开与新会话不得复用旧目录，序号10晚于序号9',t=>{
 const f=fixture(t),frame={...f.connected,request_id:'disconnected'};
 f.db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?,?)').run('channel','w2c','10','DISCONNECTED',canonical(frame),digest(frame));
 assert.throws(f.read,{code:'device_capabilities_unavailable'});
 const next={...frame,body:{...frame.body,device_session_id:'new-session'}};
 f.db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?,?)').run('channel','w2c','11','CONNECTED',canonical(next),digest(next));
 assert.throws(f.read,{code:'device_capabilities_unavailable'});
});
test('原件摘要、平台绑定与Schema内容错配均拒绝',t=>{
 const f=fixture(t);f.input.runtime.binding.launch_intent.extension_binding.platform_profile_ref={object_id:'other'};
 assert.throws(f.read,{code:'device_capabilities_binding'});
 f.input.runtime.binding.launch_intent.extension_binding.platform_profile_ref={object_id:'platform'};
 f.db.prepare('UPDATE device_module_frame SET frame_digest=?').run(digest('changed'));
 assert.throws(f.read,{code:'device_capabilities_integrity'});
 const broken=fixture(t,template=>{template.actions[0].parameters_schema.document.properties.value.type='string';});
 assert.throws(broken.read,{code:'device_capabilities_integrity'});
});
test('已保存资格按当前模块与全部正文读取，不信任自报完整或过期制品',t=>{
 const f=fixture(t),review=JSON.parse(fs.readFileSync(asset('simulator-control-footprint.json')));
 Object.assign(f.approved.qualification,{qualification:'fixed_memory_control_catalog/1',module_digest:review.module_digest,protocol_io_policy_digest:review.protocol_io_policy_digest});
 f.approved.format='leafseamer-catalog-approval/2';f.approved.device_session_id='session';
 f.approved.footprint_qualification=qualifyDeviceFootprint({...f.approved,runtime:f.input.runtime});
 f.input.selected.entry={file_id:'module',io_policy_file_id:'policy'};
 f.input.selected.content.inventory={files:[{file_id:'module',digest:review.module_digest},{file_id:'policy',digest:review.protocol_io_policy_digest}]};
 const save=()=>f.db.prepare('UPDATE device_catalog_approval SET body_jcs=?,body_digest=?').run(canonical(f.approved),digest(f.approved));save();
 assert.deepEqual(f.read().devices[0].actions[0].footprint,f.approved.footprint_qualification.action_footprints[0]);
 f.input.selected.content.inventory.files[0].digest=digest('new-module');assert.throws(f.read,{code:'device_capabilities_binding'});
 f.input.selected.content.inventory.files[0].digest=review.module_digest;
 f.approved.footprint_qualification.action_footprints[0].resources=[];save();assert.throws(f.read,{code:'device_footprint_integrity'});
});
test('固定注册生成已校验观察与动作绑定，不生成不存在的事件或发送权限',t=>{
 const f=registered(t),result=f.bindings();assert.deepEqual(f.bindings(result.registration_ref),result);
 assert.deepEqual(deviceBindingsBundle(result,{scope:result.registration_ref.scope,device_id:f.input.device,expected_registration_ref:result.registration_ref}),result);
 assert.equal(result.registration.source_kind,'observation');assert.equal(result.bindings.length,2);
 assert.equal(result.registration.binding_review_ref.revision,'3');assert.equal(result.registration.binding_review.revision,'3');
 assert.equal(result.registration.binding_review_ref.digest,digest(result.registration.binding_review));
 assert.equal(result.registration.binding_review.footprint_review_digest,digest(f.approved.footprint_qualification.review));
 const input=result.bindings.find(v=>v.kind==='input'),action=result.bindings.find(v=>v.kind==='action');
 assert.equal(input.value.source,'observation');assert.equal(input.value.producer_step_id,null);assert.equal(action.value.device_id,'device');
 assert.equal(action.value.parameter_schema_ref.digest,digest(result.schemas[0].document));assert.equal(result.input_schemas[0].schema_ref.digest,digest(result.input_schemas[0].document));
 for(const binding of result.bindings)assert.equal(binding.content_ref.digest,digest(binding.value));
 assert.deepEqual(action.value.footprint.safe_failure_classes,[]);assert.deepEqual(result.alias_table.entries,[]);
 result.registration.binding_review.parameter_slots.length=0;assert.equal(f.bindings().registration.binding_review.parameter_slots.length,1);
});
test('绑定读取拒绝旧注册、缺登记、被改写的投影与断开的当前会话',t=>{
 const f=registered(t),expected=f.bindings().registration_ref;
 assert.throws(()=>f.bindings({...expected,digest:digest('other')}),{code:'device_automation_registration_stale'});
 const original=structuredClone(f.approved.automation_registration);f.approved.automation_registration.binding_review.observation_projections=[];f.save();
 assert.throws(()=>f.bindings(),{code:'device_automation_registration_stale'});
 f.approved.automation_registration=structuredClone(original);f.approved.automation_registration.binding_review_ref.revision='1';f.save();
 assert.throws(()=>f.bindings(),{code:'device_automation_registration_stale'});
 f.approved.automation_registration=null;f.save();assert.throws(()=>f.bindings(),{code:'device_automation_registration_required'});
 f.approved.automation_registration=original;f.save();const disconnected={...f.connected,request_id:'disconnected'};
 f.db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?,?)').run('channel','w2c','10','DISCONNECTED',canonical(disconnected),digest(disconnected));
 assert.throws(()=>f.bindings(expected),{code:'device_capabilities_unavailable'});
});
