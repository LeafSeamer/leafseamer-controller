import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {setTimeout as delay} from 'node:timers/promises';
import {setup} from './fixtures/extension-capabilities.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {bind,workerIntent} from './fixtures/core-binding.mjs';
import {hash,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
const key=intent=>({launch_id:intent.launch_id,launch_intent_digest:hash(intent)});
async function ready(t,options={}){
 const x=await setup(t,{revision:19,...options});
 if(options.inject){x.f.close();inspect(x.f.dir,db=>db.exec(options.inject));x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);}
 const a=await authenticated(t,x.f),token=a.token(),approved=await a.sessions.approveExtension(token,x.request);
 const p=x.host.content.receipt.platform_profile_ref,core=bind(x.f.store,{profile_id:p.object_id,revision:p.revision});
 const intent=workerIntent(x.f.store,core,x.host.content,approved,[x.registered.device_id]);
 await x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(intent)));
 // 仅此单元夹具提供合成监督身份；业务库、设备、人员审批及采用事务均为真实实现。
 let current=true,epoch=0;const listeners=new Set(),observations=new WeakMap();
 const source={scope:{service_id:x.f.store.identity.service_id,database_instance_id:x.f.store.identity.database_instance_id,
  supervisor_instance_id:core.descriptor.supervisor_instance_id,domain_ref:core.receipt.domain_ref},mutate:()=>{},unavailable:false,retirements:[],
  assertCurrent(){if(!current)throw new Error('source_lost');},current(){return {payload:{record:{admission_receipt:core.receipt}}};},
  subscribeLost(fn){listeners.add(fn);return ()=>listeners.delete(fn);},
  async observeWorker(value){this.assertCurrent();await this.beforeObserve?.();if(this.unavailable)throw new Error('worker_exited');
   const receipt={...core.receipt,bootstrap_id:value.launch_id+'.bootstrap',receipt_id:value.launch_id+'.receipt',member_boot_id:value.launch_id+'.boot',member_id:value.member_id,
    launch_id:value.launch_id,launch_intent_digest:hash(value),role:'worker',containment_ref:value.containment_ref,channel_binding_id:'worker.channel',os_observation_ref:'worker.os'};
   this.mutate(receipt);const observed={key:key(value),descriptor:core.descriptor,receipt};observations.set(observed,{epoch,deadline:performance.now()+2000});return observed;},
  assertWorkerObservation(value){this.assertCurrent();const held=observations.get(value);assert.ok(held&&held.epoch===epoch&&performance.now()<held.deadline,'withdrawn');},
  async retireWorker(value){this.retirements.push(value.launch_id);return {result:'indeterminate'};},
  invalidate(){epoch++;},lose(){current=false;for(const fn of listeners)fn(new Error('source_lost'));}
 };
 const runtime=x.f.store.workerLaunches.runtime;runtime.bindSource(source);
 return {...x,a,token,approved,core,intent,source,runtime,key:key(intent)};
}
test('真实业务writer采用完整worker回执与审计，查原不激活，重启保留历史并撤回',{timeout:20000},async t=>{
 const x=await ready(t),result=await x.runtime.adopt(x.key);
 assert.equal(result.ref.kind,'runtime_binding');assert.equal(result.binding.gate_state,'closed');assert.deepEqual(result.binding.launch_intent,x.intent);
 assert.deepEqual(x.runtime.current(x.key),result);assert.deepEqual(await x.runtime.adopt(x.key),result);
 x.a.real.stop();x.f.close();
 inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM worker_runtime_binding').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM worker_runtime_commit').pluck().get(),1);assert.throws(()=>db.exec('DELETE FROM worker_runtime_binding'),/immutable_runtime/);});
 x.f.reopen();const history=x.f.store.workerLaunches.runtime.query(x.key);
 assert.equal(history.current_boot,false);assert.ok(history.withdrawal);assert.deepEqual(history.ref,result.ref);
 await assert.rejects(x.f.store.workerLaunches.runtime.adopt(x.key),/worker_runtime_preparation/);
});
test('等待安装来源时审批撤销，错成员/组/域回执均不能进入核心运行绑定',{timeout:20000},async t=>{
 let hook=()=>{};const x=await ready(t,{recheck:()=>hook()});
 hook=()=>{hook=()=>{};x.a.sessions.revokeExtensionApproval(x.token,{request_id:'race',approval_ref:x.approved.approval_ref,reason:'等待中撤销'});};
 await assert.rejects(x.runtime.adopt(x.key),/extension_launch_revoked/);assert.equal(x.runtime.query(x.key),null);
 const y=await ready(t);
 for(const mutate of [r=>{r.member_id='wrong';},r=>{r.containment_ref={...r.containment_ref,group_id:'wrong'};},r=>{r.domain_ref={...r.domain_ref,clock_domain_id:'wrong'};},r=>{r.launch_intent_digest=hash('wrong');}]){
  y.source.mutate=mutate;await assert.rejects(y.runtime.adopt(y.key),/worker_runtime_binding/);assert.equal(y.runtime.query(y.key),null);
 }
});
test('采用审计写入失败回滚并锁存，后续调用不能自动补发成功',{timeout:20000},async t=>{
 const x=await ready(t,{inject:"CREATE TRIGGER fail_runtime_commit BEFORE INSERT ON worker_runtime_commit BEGIN SELECT RAISE(ABORT,'synthetic_runtime_commit'); END"});
 await assert.rejects(x.runtime.adopt(x.key),/synthetic_runtime_commit/);assert.equal(x.runtime.query(x.key),null);
 await assert.rejects(x.runtime.adopt(x.key),/worker_runtime_source/);
 x.a.real.stop();x.f.close();inspect(x.f.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM worker_runtime_binding').pluck().get(),0));
});
test('监督撤回及实际审批撤销先关闭本地资格，失效历史不能被再次adopt复活',{timeout:20000},async t=>{
 const x=await ready(t),original=await x.runtime.adopt(x.key);x.source.invalidate();
 assert.throws(()=>x.runtime.current(x.key),/withdrawn/);assert.equal(x.runtime.query(x.key).withdrawal.reason,'source_changed');
 assert.deepEqual((await x.runtime.adopt(x.key)).ref,original.ref);assert.throws(()=>x.runtime.current(x.key),/worker_runtime_unavailable/);
 const y=await ready(t);await y.runtime.adopt(y.key);
 y.a.sessions.revokeExtensionApproval(y.token,{request_id:'revoke',approval_ref:y.approved.approval_ref,reason:'采用后撤销'});
 assert.throws(()=>y.runtime.current(y.key),/extension_launch_revoked/);assert.equal(y.runtime.query(y.key).withdrawal.reason,'approval_changed');
 const z=await ready(t);await z.runtime.adopt(z.key);z.source.unavailable=true;
 const deadline=performance.now()+4000;while(!z.runtime.query(z.key).withdrawal){assert.ok(performance.now()<deadline);await delay(25);}
 assert.throws(()=>z.runtime.current(z.key),/worker_runtime_unavailable/);assert.deepEqual(z.source.retirements,['worker']);
});
test('监督连接丢失时撤回写入故障不保留本地资格',{timeout:20000},async t=>{
 const x=await ready(t,{inject:"CREATE TRIGGER fail_withdraw BEFORE INSERT ON worker_runtime_withdrawal BEGIN SELECT RAISE(ABORT,'synthetic_withdraw'); END"});await x.runtime.adopt(x.key);
 x.source.lose();assert.throws(()=>x.runtime.current(x.key),/worker_runtime_unavailable/);
 assert.equal(x.runtime.query(x.key).withdrawal,null); // 持久失败如实保留，不能把该历史当current。
 x.a.real.stop();x.f.close();inspect(x.f.dir,db=>db.exec('DROP TRIGGER fail_withdraw'));
 x.f.reopen();assert.equal(x.f.store.workerLaunches.runtime.query(x.key).withdrawal.reason,'restarted');
});
test('schema18显式备份升级到19，保留审批历史，旧库无运行采用入口',{timeout:20000},async t=>{
 const x=await setup(t,{revision:18}),identity=x.f.store.identity;assert.equal(x.f.store.workerLaunches.runtime,null);x.f.close();
 const result=await migrateStorage(x.f.dir,19);assert.equal(result.steps.length,1);assert.equal(result.schema_revision,'19');
 assert.ok(fs.readdirSync(x.f.dir).some(name=>name.startsWith('controller-before-v19-')));
 x.f.reopen();assert.equal(x.f.store.identity.service_id,identity.service_id);x.f.close();
 inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM worker_runtime_binding').pluck().get(),0);assert.ok(db.prepare('SELECT count(*) FROM extension_candidate').pluck().get());});
 assert.deepEqual(await migrateAfterClose(x.f),{schema_revision:'19',changed:false});
});
async function migrateAfterClose(f){f.close();return migrateStorage(f.dir,19);}

test('多个worker并发采用按来源串行复核，保持独立回执和运行绑定',{timeout:20000},async t=>{
 const x=await ready(t),second={...x.intent,launch_id:'worker.second',member_id:'member.second',containment_ref:{...x.intent.containment_ref,group_id:'group.second'}};
 await x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(second)));let busy=false,maximum=0;
 x.source.beforeObserve=async()=>{assert.equal(busy,false);busy=true;maximum++;await delay(40);busy=false;};
 const [a,b]=await Promise.all([x.runtime.adopt(x.key),x.runtime.adopt(key(second))]);assert.notEqual(a.ref.object_id,b.ref.object_id);
 assert.notEqual(a.binding.admission_receipt.receipt_id,b.binding.admission_receipt.receipt_id);assert.equal(maximum,2);
 assert.equal(x.runtime.current(x.key).withdrawal,null);assert.equal(x.runtime.current(key(second)).withdrawal,null);
});
