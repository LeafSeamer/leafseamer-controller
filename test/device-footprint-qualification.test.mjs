import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));assert.ok(path.isAbsolute(root));
const asset=name=>path.join(root,'dist',name),load=name=>import(pathToFileURL(asset(name)));
const {digest}=await load('auth-clock-value.mjs');
const {qualifyDeviceFootprint,readDeviceFootprint}=await load('device-footprint-qualification.mjs');
const {simulatorControlCatalog}=await load('simulator-control-module.mjs');
const review=JSON.parse(fs.readFileSync(asset('simulator-control-footprint.json')));
function input(){return {runtime:{ref:{object_id:'runtime',digest:digest('runtime')},binding:{service_id:'service',database_instance_id:'database'}},
 qualification:{qualification:'fixed_memory_control_catalog/1',module_digest:review.module_digest,protocol_io_policy_digest:review.protocol_io_policy_digest,
  template_digest:review.template_digest,manifest_digest:digest('manifest'),resource_ref:{object_id:'resource',digest:digest('resource')}},channel_id:'channel',device_session_id:'session',catalog:simulatorControlCatalog()};}
test('固定审阅绑定实际模块、策略及完整模板，覆盖全部参数并包含整设备和共享worker',()=>{
 const raw=name=>'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(asset(name))).digest('hex');
 assert.equal(review.module_digest,raw('simulator-control-module.mjs'));assert.equal(review.protocol_io_policy_digest,raw('simulator-control-policy.json'));
 assert.equal(review.template_digest,digest(JSON.parse(fs.readFileSync(asset('simulator-control-capability.json')))));
 const a=input(),q=qualifyDeviceFootprint(a),effect=q.action_footprints[0];assert.equal(q.parameter_scope,'all_allowed_parameters');
 assert.deepEqual(effect.reads,effect.writes);assert.deepEqual(effect.writes,effect.failure_writes);assert.equal(effect.resources.length,2);assert.deepEqual(effect.safe_failure_classes,[]);
 const b=input();b.qualification.resource_ref.object_id='another';const other=qualifyDeviceFootprint(b).action_footprints[0];
 assert.notEqual(effect.resources[0],other.resources[0]);assert.equal(effect.resources[1],other.resources[1]);
 const db=input();db.runtime.binding.database_instance_id='other';assert.notEqual(qualifyDeviceFootprint(db).action_footprints[0].resources[0],effect.resources[0]);
 q.review.module_digest='changed';assert.equal(qualifyDeviceFootprint(a).review.module_digest,review.module_digest);
});
test('模块、策略、模板或资格变动不自动续批；伪造complete不能取得资格',()=>{
 for(const field of ['module_digest','protocol_io_policy_digest','template_digest','qualification']){const value=input();value.qualification[field]='changed';value.qualification.complete=true;assert.equal(qualifyDeviceFootprint(value),null);}
 const value=input();value.catalog.action_ids.push('unreviewed');assert.throws(()=>qualifyDeviceFootprint(value),{code:'device_footprint_integrity'});
});
test('事件采集模块使用独立修订，旧审阅原件保留且不能批准新模块',()=>{
 const previous=JSON.parse(fs.readFileSync(asset('simulator-control-footprint-v1.json')));
 const bindings=JSON.parse(fs.readFileSync(asset('simulator-control-bindings-v1.json')));
 const raw=name=>crypto.createHash('sha256').update(fs.readFileSync(asset(name))).digest('hex');
 assert.equal(raw('simulator-control-footprint-v1.json'),'cc12151f84f27142ff7a6e803ed2129a41834514ad265af44e5a3efe845c1b6b');
 assert.equal(raw('simulator-control-bindings-v1.json'),'fb5ffa6c2d7985f196c16d9f2bf76ba820f1d888e46a2a27cf72b8df45fea72b');
 assert.equal(previous.revision,'1');assert.equal(bindings.revision,'1');assert.equal(bindings.footprint_review_digest,digest(previous));
 assert.equal(raw('simulator-control-footprint-v2.json'),'16e60c903245249a83a5990e9ce51e57174c432ed539c9ec6fc5961c9fea8ae7');
 assert.equal(raw('simulator-control-bindings-v2.json'),'b95f88e0cf72021aa5002d31489f1d55203dc04dbfb1a7ee12d0d0086ba9da30');
 assert.equal(review.revision,'3');assert.equal(review.semantics_revision,'3');assert.notEqual(review.module_digest,previous.module_digest);
 const current=input();assert.equal(qualifyDeviceFootprint(current).review_ref.revision,'3');
 current.qualification.module_digest=JSON.parse(fs.readFileSync(asset('simulator-control-footprint-v2.json'))).module_digest;assert.equal(qualifyDeviceFootprint(current),null);
 current.qualification.module_digest=previous.module_digest;assert.equal(qualifyDeviceFootprint(current),null);
 const approved={...input(),format:'leafseamer-catalog-approval/3',footprint_qualification:qualifyDeviceFootprint(input())};
 approved.footprint_qualification.review=previous;approved.footprint_qualification.review_ref={id:previous.review_id,revision:'1',digest:digest(previous)};
 assert.throws(()=>readDeviceFootprint(approved,approved.runtime),{code:'device_footprint_integrity'});
});
test('历史原件不补授；资格与原运行、会话、全部正文及当前审阅必须一致',()=>{
 const value=input(),approved={format:'leafseamer-catalog-approval/2',qualification:value.qualification,channel_id:value.channel_id,device_session_id:value.device_session_id,catalog:value.catalog};
 assert.equal(readDeviceFootprint(approved,value.runtime),null);approved.footprint_qualification=qualifyDeviceFootprint(value);assert.deepEqual(readDeviceFootprint(approved,value.runtime),approved.footprint_qualification);
 for(const mutate of [v=>{v.device_session_id='other';},v=>{v.channel_id='other';},v=>{v.footprint_qualification.parameter_scope='selected_parameters';},v=>{v.footprint_qualification.action_footprints[0].resources.pop();},v=>{v.qualification.module_digest='changed';}]){
  const changed=structuredClone(approved);mutate(changed);assert.throws(()=>readDeviceFootprint(changed,value.runtime),{code:'device_footprint_integrity'});
 }
 const runtime=structuredClone(value.runtime);runtime.ref.object_id='new';assert.throws(()=>readDeviceFootprint(approved,runtime),{code:'device_footprint_integrity'});
});
