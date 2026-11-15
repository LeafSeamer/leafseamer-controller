import test from 'node:test';import assert from 'node:assert/strict';import crypto from 'node:crypto';import fs from 'node:fs';import path from 'node:path';import {fileURLToPath,pathToFileURL} from 'node:url';
import {snapshotFixture,buildSnapshot} from './service-snapshot.test.mjs';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url)),load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const {serviceSubscriptionStore}=await load('service-subscription-store.mjs'),{createSubscriptionEndpoint}=await load('service-subscription-http.mjs'),{contractSelection:selection}=await load('sdk/selection.mjs'),{digest}=await load('auth-clock-value.mjs');
const id=()=>crypto.randomUUID(),ref=()=>({id:id(),revision:'1',digest:'sha256:'+'a'.repeat(64)});
function fixture(t){
 const f=snapshotFixture(t,69),common={format_version:'scope-registry/0.1.0-draft.1',authority_service_id:f.args.service.service_id,database_instance_id:f.args.service.database_instance_id,entity_id:id(),entity_epoch:id(),revision:'1'},bytes=fs.readFileSync(path.join(root,'dist/sdk/contract/models.schema.json')),graph=JSON.parse(bytes),hash=crypto.createHash('sha256').update(bytes).digest('hex');
 const profile={...common,kind:'projection_profile',authority_role:'controller',selection,owner_kinds:['service'],purposes:['canonical_trigger'],graph_digest:hash,maximum_records:32,collections:[{entity_kind:'sources',permission:'status.read',view_schema_ref:{schema_id:graph.$id,definition:'snapshot__SourceSnapshotView',schema_digest:hash},relation_policies:['authorized_reference'],history_policies:['current']}]};
 const reference=v=>({authority_service_id:v.authority_service_id,database_instance_id:v.database_instance_id,entity_kind:v.kind,entity_id:v.entity_id,entity_epoch:v.entity_epoch,revision:v.revision,content_digest:digest(v).slice(7)});
 const selector={...common,kind:'selector',entity_id:id(),profile_ref:reference(profile),target_collection:'sources',mode:'entity_set',entity_ids:f.cut.records.map(r=>r.entity_id),relation_policy:'authorized_reference',history_policy:'current',window:null};
 f.request.scope.projection_profile_ref=reference(profile);f.request.scope.collections[0].selector_ref=reference(selector);f.cut.registration={scope:f.request.scope,profile,selector};
 const sample={acquisition_ref:ref(),duration_bounds:{policy_ref:ref(),drift_ppb:1000000,monotonic_quantization_ns:'10'},valid_before_tick_ns:'5000000100'};
 const store=serviceSubscriptionStore({...f.args,scopeCurrent:()=>{if(f.state.sourceFailed)throw Object.assign(new Error('worker_runtime_withdrawn'),{name:'WorkerRuntimeError',code:'worker_runtime_withdrawn'});return {registration:f.cut.registration};},durationSample:()=>({...sample,tick_ns:String(f.state.tick),upper_ns:String(f.state.upper),runtime_domain_ref:f.state.domain})});
 const created=store.create('binding',null,f.request).view,c=store.channels,h=c.open('binding',{});c.attach(h,{schema_version:'event-channel/0.1.0-draft.1',type:'client.attach',subscription_id:created.binding.subscription_id,owner:created.owner,stream_id:created.binding.stream_id,stream_epoch:created.binding.stream_epoch,scope_digest:created.binding.scope_digest,authorization_revision:'1',expected_connection_generation:'0',replace_existing:false,resume:null,connection_attempt_id:id()});
 buildSnapshot(store);const view=store.access('binding',null,created.binding.subscription_id).view,input={challenge_id:id(),expected_connection_generation:'1',snapshot_ref:view.snapshot_ref};
 return {...f,store,c,h,view,input,sample,key:view.binding.subscription_id};
}
test('当前连接查询固定范围与原租期，不更新快照、订阅或ACK；释放前复核原截止',t=>{
 const f=fixture(t),first=f.c.context('binding',null,f.key,f.input);assert.deepEqual(first.projection_profile,f.cut.registration.profile);assert.equal(first.lease.valid_before_tick_ns,'5000000100');
 const revision=f.view.revision;f.state.tick+=100000000n;assert.deepEqual(f.c.context('binding',null,f.key,f.input,first),first);assert.equal(f.store.access('binding',null,f.key).view.revision,revision);assert.equal(f.store.access('binding',null,f.key).view.ack_payload_digest,'0'.repeat(64));
 assert.throws(()=>f.c.context('binding',null,f.key,{...f.input,expected_connection_generation:'0'}),{code:'subscription_generation'});
 assert.throws(()=>f.c.context('binding',null,f.key,{...f.input,snapshot_ref:{...f.input.snapshot_ref,manifest_digest:'b'.repeat(64)}}),{code:'snapshot_context_binding'});
 f.state.tick=BigInt(first.lease.valid_before_tick_ns);assert.throws(()=>f.c.context('binding',null,f.key,f.input,first),{code:'snapshot_context_expired'});
});
test('固定product8 HTTP上下文查询通过实际SDK，POST不进入创建路径，关闭后不可释放',async t=>{
 const f=fixture(t),endpoint=createSubscriptionEndpoint({store:f.store}),body=Buffer.from(JSON.stringify(f.input)),headers=[['x-leafseamer-contract',selection.contract_id],['x-leafseamer-contract-digest',selection.contract_digest],['content-type','application/json'],['content-length',String(body.length)]];
 const reply=await endpoint.handle({bindingId:'binding',socket:null,method:'POST',path:'/internal/subscriptions/'+f.key+'/snapshot-context',headers,body});assert.equal(reply.status,200);assert.equal(JSON.parse(reply.body).challenge_id,f.input.challenge_id);reply.beforeSend();assert.equal(f.count('service_event_subscription'),1);f.c.close(f.h);assert.throws(reply.beforeSend,{code:'subscription_generation'});
});
test('授权、健康更早截止和策略变化不允许释放旧上下文，查询不修改原截止',t=>{
 const f=fixture(t),original=f.c.context('binding',null,f.key,f.input),deadline=f.db.prepare('SELECT deadline_tick FROM service_snapshot_manifest').pluck().get();
 f.sample.valid_before_tick_ns='1000000100';assert.throws(()=>f.c.context('binding',null,f.key,f.input,original),{code:'snapshot_context_expired'});f.sample.valid_before_tick_ns='5000000100';
 f.sample.duration_bounds.policy_ref=ref();assert.throws(()=>f.c.context('binding',null,f.key,f.input,original),{code:'snapshot_context_changed'});
 f.state.allowed=false;assert.throws(()=>f.c.context('binding',null,f.key,f.input,original));assert.equal(f.db.prepare('SELECT deadline_tick FROM service_snapshot_manifest').pluck().get(),deadline);
});
test('上下文范围复核遇到运行撤回返回受控来源错误，不冒充未知存储故障',t=>{
 const f=fixture(t);f.state.sourceFailed=true;assert.throws(()=>f.c.context('binding',null,f.key,f.input),error=>error.name==='IdentityError'&&error.code==='event_scope_unavailable');assert.equal(f.store.access('binding',null,f.key).view.state,'snapshot_ready');
});
