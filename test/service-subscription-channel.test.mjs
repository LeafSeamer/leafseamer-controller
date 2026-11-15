import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {snapshotFixture,buildSnapshot} from './service-snapshot.test.mjs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url)),load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const {serviceSubscriptionStore}=await load('service-subscription-store.mjs'),{serviceEventChannel}=await load('service-event-channel.mjs'),{IdentityError}=await load('identity-error.mjs'),{createSubscriptionEndpoint}=await load('service-subscription-http.mjs'),{sealSourceSnapshot}=await load('service-snapshot-content.mjs'),{contractSelection}=await load('sdk/selection.mjs');
const id=()=>crypto.randomUUID();
const attach=(view,overrides={})=>({schema_version:'event-channel/0.1.0-draft.1',type:'client.attach',subscription_id:view.binding.subscription_id,owner:view.owner,stream_id:view.binding.stream_id,stream_epoch:view.binding.stream_epoch,scope_digest:view.binding.scope_digest,authorization_revision:view.binding.authorization_revision,expected_connection_generation:view.binding.connection_generation,replace_existing:false,resume:null,connection_attempt_id:id(),...overrides});
test('building附着后发布不重置代际，只有当前活连接可以下载，关闭采用当前修订',t=>{
 const f=snapshotFixture(t,69),created=f.store.create('binding',null,f.request).view,c=f.store.channels,h=c.open('binding',{}),request=attach(created),result=c.attach(h,request);
 assert.equal(result.attached.binding.connection_generation,'1');assert.equal(result.ready.channel.owner.principal_id,f.proof.owner.principal_id);assert.deepEqual(c.attach(h,request),result);
 buildSnapshot(f.store);const view=f.store.access('binding',null,created.binding.subscription_id).view;assert.equal(view.revision,'3');assert.equal(view.state,'snapshot_ready');assert.equal(view.binding.connection_generation,'1');
 assert.throws(()=>c.snapshot('binding',null,view.binding.subscription_id,'0'),{code:'subscription_generation'});
 const manifest=c.snapshot('binding',null,view.binding.subscription_id,'1'),page=c.snapshot('binding',null,view.binding.subscription_id,'1',{snapshot_id:manifest.binding.snapshot_id,page_index:0});assert.equal(page.delivery_binding.connection_generation,'1');assert.equal(page.content.binding.connection_generation,undefined);
 c.close(h);assert.throws(()=>c.snapshot('binding',null,view.binding.subscription_id,'1'),{code:'subscription_generation'});assert.equal(c.attempt('binding',null,view.binding.subscription_id,request.connection_attempt_id).current,false);
 assert.equal(f.store.access('binding',null,view.binding.subscription_id,{expected_revision:'3'}).view.state,'closed');assert.equal(c.attempt('binding',null,view.binding.subscription_id,request.connection_attempt_id).current,false);assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
});
test('同代竞争只有一个成功，替换立即阻断原连接、原attempt换连接和旧代下载',t=>{
 const f=snapshotFixture(t,69),created=f.store.create('binding',null,f.request).view;buildSnapshot(f.store);const c=f.store.channels,a=c.open('binding',{}),b=c.open('binding',{}),request=attach(created),first=c.attach(a,request);
 assert.throws(()=>c.attach(b,request),{code:'subscription_conflict'});assert.throws(()=>c.attach(b,attach(created)),{code:'subscription_conflict'});
 const latest=f.store.access('binding',null,created.binding.subscription_id).view;assert.throws(()=>c.attach(b,attach(latest)),{code:'subscription_conflict'});assert.throws(()=>c.attach(a,attach(latest,{replace_existing:true})),{code:'subscription_conflict'});
 const replaced=c.attach(b,attach(latest,{replace_existing:true}));assert.equal(replaced.attached.binding.connection_generation,'2');assert.throws(()=>c.check(a),{code:'subscription_generation'});assert.throws(()=>c.snapshot('binding',null,created.binding.subscription_id,'1'),{code:'subscription_generation'});
 assert.equal(c.attempt('binding',null,created.binding.subscription_id,request.connection_attempt_id).current,false);assert.equal(c.snapshot('binding',null,created.binding.subscription_id,'2').manifest_digest,first.attached.snapshot_ref.manifest_digest);
});
test('快照各阶段之间附着采用最新订阅修订，固定内容不依赖连接代际',t=>{
 for(const phase of [1,2,3]){const f=snapshotFixture(t,69),view=f.store.create('binding',null,f.request).view;for(let i=0;i<phase;i++)f.store.sweep();
  const channel=f.store.channels,handle=channel.open('binding',{});channel.attach(handle,attach(view));buildSnapshot(f.store);
  const ready=f.store.access('binding',null,view.binding.subscription_id).view;assert.equal(ready.revision,'3');assert.equal(ready.binding.connection_generation,'1');assert.equal(ready.state,'snapshot_ready');
  assert.equal(channel.snapshot('binding',null,view.binding.subscription_id,'1').binding.connection_generation,undefined);assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
 }
});
test('代际原件、修订和连接头任一缺写回滚；失败尝试不取得下载资格',t=>{
 for(const table of ['service_subscription_attempt','service_event_subscription_revision','service_subscription_connection']){const f=snapshotFixture(t,69),view=f.store.create('binding',null,f.request).view,c=f.store.channels,h=c.open('binding',{});f.db.exec('CREATE TRIGGER omit_connection BEFORE INSERT ON '+table+' BEGIN SELECT RAISE(IGNORE); END');assert.throws(()=>c.attach(h,attach(view)));assert.equal(f.count('service_subscription_attempt'),0);assert.equal(f.count('service_subscription_connection'),0);assert.equal(f.count('service_event_subscription_revision'),1);}
});
test('撤权、超期和服务重开均使连接失效，重算owner或自报resume不能取得附着',t=>{
 const f=snapshotFixture(t,69),view=f.store.create('binding',null,f.request).view,c=f.store.channels,h=c.open('binding',{});
 assert.throws(()=>c.attach(h,attach(view,{owner:{...view.owner,principal_id:id()}})),{code:'subscription_binding'});assert.throws(()=>c.attach(h,attach(view,{resume:{cursor:'0'}})),{code:'subscription_resume_unavailable'});
 c.attach(h,attach(view));f.state.allowed=false;assert.throws(()=>c.check(h));f.state.allowed=true;assert.throws(()=>c.check(h),{code:'subscription_state'});
 const restarted=serviceSubscriptionStore({...f.args,bootId:id()});assert.throws(()=>restarted.channels.snapshot('binding',null,view.binding.subscription_id,'1'));
});
test('实际固定SDK帧只在合法attach后返回一次ready，未知正文不进入持久层',async t=>{
 const f=snapshotFixture(t,69),view=f.store.create('binding',null,f.request).view,channel=serviceEventChannel(f.store),app=channel.open('binding',{}),request=attach(view);
 await assert.rejects(app.receive(Buffer.from(JSON.stringify({...request,extra:true}))));assert.equal(f.count('service_subscription_attempt'),0);
 const first=await app.receive(Buffer.from(JSON.stringify(request)));assert.equal(first.messages.length,2);first.beforeSend();assert.equal(JSON.parse(first.messages[0]).type,'contract.ready');
 const second=await app.receive(Buffer.from(JSON.stringify(request)));assert.equal(second.messages.length,1);assert.equal(JSON.parse(second.messages[0]).type,'server.attached');app.close();assert.throws(first.beforeSend);
});
test('来源暂不可用形成受控拒绝，不触发身份writer的未知存储故障停机',t=>{
 const f=snapshotFixture(t,69);let stopped=false,fail=false;const store=serviceSubscriptionStore({...f.args,writer:work=>{assert.equal(stopped,false);try{return f.args.writer(work);}catch(error){if(!(error instanceof IdentityError))stopped=true;throw error;}},authorize:(...args)=>{if(fail)throw Object.assign(new Error('device_capabilities_unavailable'),{name:'WorkerLaunchError'});return f.args.authorize(...args);}});
 const view=store.create('binding',null,f.request).view,h=store.channels.open('binding',{});store.channels.attach(h,attach(view));fail=true;assert.throws(()=>store.channels.check(h),{code:'event_scope_unavailable'});assert.equal(stopped,false);fail=false;assert.equal(store.access('binding',null,view.binding.subscription_id).view.state,'building');
});
test('大于默认扫描预算的完整来源manifest和页面仍按固定SDK有界解码',async t=>{
 const f=snapshotFixture(t,69),view=f.store.create('binding',null,f.request).view;
 f.cut.records=Array.from({length:32},(_,i)=>{const r=structuredClone(f.cut.records[0]);r.entity_id='source_'+i;r.view.source_key.registration_id=r.entity_id;r.view.gaps=Array.from({length:64},(_,n)=>({gap_id:String(n).padStart(128,'g'),loss_extent:'unknown',first_missing:null,last_missing:null,resolution_state:'open'}));return r;});
 f.cut.registration.selector.entity_ids=f.cut.records.map(r=>r.entity_id);f.cut.source_watermarks=f.cut.records.map(r=>({source_key:r.view.source_key,binding_ref:r.view.binding_ref,baseline_sequence:r.view.contiguous_sequence,source_state_revision:r.entity_revision,baseline_ref:null,gap_summary:r.view.gaps}));
 const sealed=sealSourceSnapshot({view,cut:f.cut,snapshotId:id(),domainRef:f.state.domain,createdAt:'2026-11-15T00:00:00Z',expiresAt:'2026-11-15T00:00:30Z'}),page={manifest_digest:sealed.manifest.manifest_digest,content_digest:sealed.pages[0].content_digest,content:JSON.parse(sealed.pages[0].body),delivery_binding:{...view.binding,connection_generation:'1'}};
 assert.ok(Buffer.byteLength(sealed.manifestBody)>262144);let changed=false;const endpoint=createSubscriptionEndpoint({store:{channels:{snapshot:(_b,_s,_id,_gen,requested)=>changed?{}:requested?page:sealed.manifest}}});
 const headers=[['x-leafseamer-contract',contractSelection.contract_id],['x-leafseamer-contract-digest',contractSelection.contract_digest]],prefix='/internal/subscriptions/'+view.binding.subscription_id;
 const manifest=await endpoint.handle({bindingId:'binding',socket:null,method:'GET',path:prefix+'/snapshot?expected_connection_generation=1',headers,body:Buffer.alloc(0)});assert.equal(manifest.status,200);manifest.beforeSend();
 const result=await endpoint.handle({bindingId:'binding',socket:null,method:'GET',path:prefix+'/snapshots/'+sealed.snapshotRef.snapshot_id+'/pages/0?expected_connection_generation=1',headers,body:Buffer.alloc(0)});assert.equal(result.status,200);assert.ok(result.body.length<=262144);result.beforeSend();changed=true;assert.throws(result.beforeSend,/subscription_changed/);
});
