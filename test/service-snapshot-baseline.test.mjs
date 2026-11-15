import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {snapshotFixture,buildSnapshot} from './service-snapshot.test.mjs';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));
const {serviceEventChannel}=await import(pathToFileURL(path.join(root,'dist/service-event-channel.mjs')));
const id=()=>crypto.randomUUID();
function start(t){const f=snapshotFixture(t,70),created=f.store.create('binding',null,f.request).view;buildSnapshot(f.store);const c=f.store.channels,h=c.open('binding',{}),input={schema_version:'event-channel/0.1.0-draft.1',type:'client.attach',subscription_id:created.binding.subscription_id,owner:created.owner,stream_id:created.binding.stream_id,stream_epoch:created.binding.stream_epoch,scope_digest:created.binding.scope_digest,authorization_revision:'1',expected_connection_generation:'0',replace_existing:false,resume:null,connection_attempt_id:id()};
 const result=c.attach(h,input),applied={schema_version:'event-channel/0.1.0-draft.1',type:'client.snapshot.applied',binding:result.attached.binding,snapshot:result.attached.snapshot_ref};return {...f,c,h,input,applied};}
test('基线确认同事务保存内部映射和独立摘要，进入catching_up，重复不新增修订',t=>{
 const f=start(t),view=f.c.applied(f.h,f.applied),manifest=f.db.prepare('SELECT marker_digest,journal_sequence FROM service_snapshot_manifest').raw().get();
 assert.equal(view.state,'catching_up');assert.equal(view.ack_cursor,'0');assert.equal(view.ack_payload_digest,manifest[0]);assert.notEqual(view.ack_payload_digest,view.snapshot_ref.manifest_digest);
 assert.equal(f.db.prepare('SELECT journal_sequence FROM service_snapshot_baseline').pluck().get(),manifest[1]);const revisions=f.count('service_event_subscription_revision');
 assert.deepEqual(f.c.applied(f.h,f.applied),view);assert.equal(f.count('service_snapshot_baseline'),1);assert.equal(f.count('service_event_subscription_revision'),revisions);
 assert.deepEqual(f.store.access('binding',null,view.binding.subscription_id).view,view);assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
 f.state.tick+=30000000000n;assert.deepEqual(f.c.applied(f.h,f.applied),view);assert.equal(f.c.check(f.h).state,'catching_up');
 assert.throws(()=>f.store.create('binding',null,{...f.request,request_id:id()}),{code:'subscription_slot_busy'});
 assert.equal(f.store.access('binding',null,view.binding.subscription_id,{expected_revision:view.revision}).view.state,'closed');assert.throws(()=>f.c.applied(f.h,f.applied));
});
test('旧代、错误manifest和额外字段均不创建基线；新代完整重下载后方可确认',t=>{
 const f=start(t);for(const input of [{...f.applied,binding:{...f.applied.binding,connection_generation:'0'}},{...f.applied,snapshot:{...f.applied.snapshot,manifest_digest:'b'.repeat(64)}},{...f.applied,client_durable:true}])assert.throws(()=>f.c.applied(f.h,input));
 const other=f.c.open('binding',{}),attached=f.c.attach(other,{...f.input,connection_attempt_id:id(),expected_connection_generation:'1',replace_existing:true});assert.throws(()=>f.c.applied(f.h,f.applied));assert.equal(f.count('service_snapshot_baseline'),0);
 assert.equal(f.c.applied(other,{...f.applied,binding:attached.attached.binding}).state,'catching_up');
});
test('原采用截止等号、撤权、域变化在确认前拒绝，已确认后的撤权和域变化仍关闭',t=>{
 for(const committed of [false,true])for(const kind of ['deadline','revoke','domain']){if(committed&&kind==='deadline')continue;const f=start(t);if(committed)f.c.applied(f.h,f.applied);
  if(kind==='deadline')f.state.tick+=30000000000n;if(kind==='revoke')f.state.allowed=false;if(kind==='domain')f.state.domain={...f.state.domain,descriptor_digest:'sha256:'+'b'.repeat(64)};
  assert.throws(()=>f.c.applied(f.h,f.applied));assert.equal(f.count('service_snapshot_baseline'),committed?1:0);
 }
});
test('基线、修订、head、审计和outbox缺写全部回滚，随后原确认可重试',t=>{
 for(const [table,event]of [['service_snapshot_baseline','INSERT'],['service_event_subscription_revision','INSERT'],['service_event_subscription_head','UPDATE'],['service_event_subscription_audit','INSERT'],['service_event_subscription_outbox','INSERT']]){
  const f=start(t),count=f.count('service_event_subscription_revision');f.db.exec('CREATE TRIGGER omit_baseline BEFORE '+event+' ON '+table+' BEGIN SELECT RAISE(IGNORE); END');assert.throws(()=>f.c.applied(f.h,f.applied));assert.equal(f.count('service_snapshot_baseline'),0);assert.equal(f.count('service_event_subscription_revision'),count);f.db.exec('DROP TRIGGER omit_baseline');assert.equal(f.c.applied(f.h,f.applied).state,'catching_up');
 }
});
test('确认提交前的重新授权失败回滚，不留下可供GET使用的ACK',t=>{
 const f=start(t);f.db.function('revoke_baseline',()=>{f.state.allowed=false;return 1;});f.db.exec('CREATE TRIGGER revoke_baseline AFTER INSERT ON service_snapshot_baseline BEGIN SELECT revoke_baseline(); END');
 assert.throws(()=>f.c.applied(f.h,f.applied));assert.equal(f.count('service_snapshot_baseline'),0);f.state.allowed=true;const view=f.store.access('binding',null,f.applied.binding.subscription_id).view;assert.equal(view.state,'snapshot_ready');assert.equal(view.ack_payload_digest,'0'.repeat(64));
});
test('固定SDK接收snapshot.applied后无自创响应帧，GET读取原确认',async t=>{
 const f=snapshotFixture(t,70),view=f.store.create('binding',null,f.request).view;buildSnapshot(f.store);const app=serviceEventChannel(f.store).open('binding',{});
 const attach={schema_version:'event-channel/0.1.0-draft.1',type:'client.attach',subscription_id:view.binding.subscription_id,owner:view.owner,stream_id:view.binding.stream_id,stream_epoch:view.binding.stream_epoch,scope_digest:view.binding.scope_digest,authorization_revision:'1',expected_connection_generation:'0',replace_existing:false,resume:null,connection_attempt_id:id()};
 const result=await app.receive(Buffer.from(JSON.stringify(attach))),attached=JSON.parse(result.messages[1]),input={schema_version:'event-channel/0.1.0-draft.1',type:'client.snapshot.applied',binding:attached.binding,snapshot:attached.snapshot_ref};
 const confirmed=await app.receive(Buffer.from(JSON.stringify(input)));assert.deepEqual(confirmed.messages,[]);confirmed.beforeSend();assert.equal(f.store.access('binding',null,view.binding.subscription_id).view.state,'catching_up');app.close();
});
