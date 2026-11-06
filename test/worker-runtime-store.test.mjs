import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {setTimeout as delay} from 'node:timers/promises';
import {Duplex} from 'node:stream';
import {setup} from './fixtures/extension-capabilities.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {bind,workerIntent} from './fixtures/core-binding.mjs';
import {hash,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {deviceExecutionVersion} from '../dist/sdk/device-execution.mjs';
import {executionSessionIdentity,executionTransport} from '../dist/device-execution-channel.mjs';
import {executionFrameReceipt} from '../dist/device-execution-frames.mjs';
const key=intent=>({launch_id:intent.launch_id,launch_intent_digest:hash(intent)});
async function ready(t,options={}){
 const x=await setup(t,{revision:19,...options});
 if(options.inject){x.f.close();inspect(x.f.dir,db=>db.exec(options.inject));x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);}
 const a=await authenticated(t,x.f),token=a.token(),approved=await a.sessions.approveExtension(token,x.request);
 const p=x.host.content.receipt.platform_profile_ref,core=bind(x.f.store,{profile_id:p.object_id,revision:p.revision});
 const intent=workerIntent(x.f.store,core,x.host.content,approved,[x.registered.device_id]);
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
 if(Number(x.f.store.identity.schema_revision)>=22){
  x.f.store.configureVirtualDevice({request_id:'resource',device_id:x.registered.device_id});
  x.f.store.extensionInstallations.bindRuntimeSource(source);
  const plan=await a.sessions.planExtension(token,{request_id:'plan',slot_id:x.installed.slot.record.slot_id,expected_slot_revision:x.installed.slot.slot_ref.revision,
   selection:{kind:'activate',source_installation_ref:null,target_installation_ref:x.installed.installation_ref,reuse_content_ref:null,configuration_ref:x.config.configuration_ref}});
  await a.sessions.activateExtension(token,{request_id:'activate',slot_id:plan.slot_ref.object_id,expected_slot_revision:plan.slot_ref.revision,
   target_installation_ref:x.installed.installation_ref,approval_ref:approved.approval_ref,dependency_plan_ref:plan.plan_ref});
 }
 await x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(intent)));
 const runtime=x.f.store.workerLaunches.runtime;runtime.bindSource(source);
 return {...x,a,token,approved,core,intent,source,runtime,key:key(intent)};
}
test('显式运行刷新共享同一观察，失败撤回后不能靠刷新复活',{timeout:20000},async t=>{
 const x=await ready(t),original=await x.runtime.adopt(x.key);
 let release,entered,calls=0;const held=new Promise(resolve=>{release=resolve;}),waiting=new Promise(resolve=>{entered=resolve;});
 x.source.beforeObserve=async()=>{calls++;entered();await held;};
 const first=x.runtime.refreshCurrent(x.key),second=x.runtime.refreshCurrent(x.key);await waiting;
 assert.equal(calls,1);release();const refreshed=await Promise.all([first,second]);
 assert.deepEqual(refreshed,[original,original]);assert.equal(calls,1);
 x.source.beforeObserve=null;x.source.unavailable=true;
 await assert.rejects(x.runtime.refreshCurrent(x.key),/worker_runtime_withdrawn/);
 x.source.unavailable=false;
 await assert.rejects(x.runtime.refreshCurrent(x.key),/worker_runtime_unavailable/);
 assert.ok(x.runtime.query(x.key).withdrawal);assert.throws(()=>x.runtime.current(x.key),/worker_runtime_unavailable/);
});

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

test('业务writer内复核采用运行使用同库事务，不允许事务外借用当前资格',{timeout:20000},async t=>{
 const x=await ready(t),adopted=await x.runtime.adopt(x.key);let checked=null;
 assert.throws(()=>x.runtime.currentInTransaction(x.key),{code:'worker_runtime_writer'});
 // 认证时钟夹具只在真实session writer持锁后触发一次观察，不替换运行来源。
 x.a.state.onRead=()=>{delete x.a.state.onRead;checked=x.runtime.currentInTransaction(x.key);};
 x.a.sessions.presentation(x.a.auth);assert.deepEqual(checked,adopted);assert.equal(x.runtime.query(x.key).withdrawal,null);
});

test('writer内来源失效先撤下本地资格，外层回滚后仍单独提交撤回',{timeout:20000},async t=>{
 const x=await ready(t);await x.runtime.adopt(x.key);
 x.a.state.onRead=()=>{delete x.a.state.onRead;x.source.invalidate();x.runtime.currentInTransaction(x.key);};
 assert.throws(()=>x.a.sessions.presentation(x.a.auth),/withdrawn/);
 assert.equal(x.runtime.query(x.key).withdrawal,null);
 assert.throws(()=>x.runtime.current(x.key),{code:'worker_runtime_unavailable'});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(x.runtime.query(x.key).withdrawal.reason,'source_changed');assert.deepEqual(x.source.retirements,['worker']);
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

function hello(x,journal,changes={}){
 const binding=journal.binding,descriptor=x.core.descriptor;
 const models=JSON.parse(fs.readFileSync(new URL('../dist/sdk/contract/models.schema.json',import.meta.url),'utf8'));
 // 远端合成输入声明特性；产品实现仅拒收，绝不据此宣告本端支持。
 const features=models.$defs.command__S9__HELLOBody.properties.supported_features.items.enum;
 return {ipc_version:deviceExecutionVersion,type:'HELLO',message_id:'hello.1',reply_to:null,
  ipc_session_id:binding.ipc_session_id,controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,
  seq:'1',device_id:null,clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',
  body:{module_id:'synthetic.module',module_digest:hash('synthetic.module'),clock_domain_id:descriptor.clock_domain_id,
   supported_ipc_versions:[deviceExecutionVersion],supported_features:features,descriptor_digest:descriptor.descriptor_digest,clock_domain_descriptor:descriptor},...changes};
}

function installedHello(x,journal){
 const frame=hello(x,journal),manifest=x.host.content.manifest,entry=manifest.entrypoints.find(e=>e.entry_id===x.intent.extension_binding.entry_id);
 frame.body.module_id=manifest.extension_id;frame.body.module_digest=x.host.content.inventory.files.find(f=>f.file_id===entry.file_id).digest;return frame;
}

test('schema30成功握手提交双向原件、能力与ACK预约，写尝试先持久再交字节',{timeout:20000},async t=>{
 const x=await ready(t,{revision:30});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
 const frame=installedHello(x,journal),bytes=Buffer.from(JSON.stringify(frame,null,1));
 const receipt=await journal.negotiate(bytes);assert.equal(receipt.gate_state,'closed');assert.equal(receipt.selected_features.length,3);
 assert.deepEqual(await journal.negotiate(bytes),receipt);assert.ok(Object.isFrozen(receipt.selected_features));
 const write=journal.beginHandshakeWrite(),ack=JSON.parse(write.payload);
 assert.equal(ack.type,'HELLO_ACK');assert.equal(ack.reply_to,frame.message_id);assert.equal(ack.seq,'1');assert.equal(ack.body.gate_state,'closed');
 assert.deepEqual(ack.body.selected_features,receipt.selected_features);
 assert.deepEqual(journal.finishHandshakeWrite(write.attempt_id,'complete'),{attempt_id:write.attempt_id,result:'complete'});
 assert.deepEqual(x.f.store.workerLaunches.queryExecutionJournal(journal.binding.ipc_session_id).negotiation,receipt);
 x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM execution_frame_record').pluck().get(),2);
  assert.equal(db.prepare('SELECT count(*) FROM execution_effect_commit').pluck().get(),2);
  assert.equal(db.prepare('SELECT count(*) FROM execution_handshake_frame').pluck().get(),2);
  assert.equal(db.prepare('SELECT count(*) FROM execution_write_attempt').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM execution_write_result').pluck().get(),1);
  assert.deepEqual(db.prepare("SELECT wire FROM execution_frame_record WHERE direction='w2c'").pluck().get().subarray(4),bytes);
  assert.equal(db.prepare('SELECT count(*) FROM execution_rejection').pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
  assert.throws(()=>db.exec('DELETE FROM execution_handshake'),/immutable/);
 });
 x.f.reopen();const old=x.f.store.workerLaunches.queryExecutionJournal(journal.binding.ipc_session_id);
 assert.equal(old.ended,true);assert.deepEqual(old.negotiation,receipt);
});

for(const target of [31,51,52,53,54,55])test('schema30升级'+target+'保留原握手能力与字节，旧会话不获新增屏障资格',{timeout:20000},async t=>{
 const x=await ready(t,{revision:30});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
 const original=Buffer.from(JSON.stringify(installedHello(x,journal),null,1)),receipt=await journal.negotiate(original),session=journal.binding.ipc_session_id;
 const write=journal.beginHandshakeWrite();journal.finishHandshakeWrite(write.attempt_id,'complete');x.a.real.stop();x.f.close();
 const migration=await migrateStorage(x.f.dir,target);assert.equal(migration.schema_revision,String(target));assert.ok(migration.backup_ref);
 x.f.reopen();const history=x.f.store.workerLaunches.queryExecutionJournal(session);assert.equal(history.ended,true);assert.deepEqual(history.negotiation,receipt);assert.equal(receipt.selected_features.length,3);
 x.f.close();inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM execution_initial_fence').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM execution_initial_fence_ack').pluck().get(),0);
  if(target===51)assert.equal(db.prepare('SELECT count(*) FROM command_encoding_request').pluck().get(),0);
  assert.deepEqual(db.prepare("SELECT wire FROM execution_frame_record WHERE direction='w2c'").pluck().get().subarray(4),original);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema30握手缺写或抛错整体回滚，不交付成功确认字节',{timeout:30000},async t=>{
 for(const [table,action] of [['execution_handshake','IGNORE'],['execution_handshake_frame',"ABORT,'synthetic_handshake'"],['execution_effect_commit','IGNORE']]){
  const x=await ready(t,{revision:30,inject:`CREATE TRIGGER fail_handshake BEFORE INSERT ON ${table} BEGIN SELECT RAISE(${action}); END;`});
  await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
  await assert.rejects(journal.negotiate(Buffer.from(JSON.stringify(installedHello(x,journal)))));
  assert.throws(()=>journal.beginHandshakeWrite());x.a.real.stop();x.f.close();
  inspect(x.f.dir,db=>{for(const table of ['execution_frame_record','execution_handshake','execution_handshake_frame','execution_effect_commit','execution_write_attempt'])
   assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
 }
});

test('schema30明确拒收仍写原共享领域，不能被成功握手表替代',{timeout:20000},async t=>{
 const x=await ready(t,{revision:30});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
 const bytes=Buffer.from(JSON.stringify(hello(x,journal))),result=await journal.rejectUnsupported(bytes);
 assert.equal(result.journal.disposition,'rejected');assert.deepEqual(journal.lookup(bytes),result);
 x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM execution_handshake').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM execution_rejection_frame').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM execution_frame_record').pluck().get(),1);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema30握手发送器使用已预约原字节，传输失败只记未知且不重发',{timeout:20000},async t=>{
 for(const broken of [false,true]){
  const x=await ready(t,{revision:30});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
  const receipt=await journal.negotiate(Buffer.from(JSON.stringify(installedHello(x,journal)))),writes=[];
  // 合成字节流故障；使用交付传输实现和真实文件库，不表示受监督Execution进程已接线。
  const socket=new Duplex({read(){},write(bytes,encoding,callback){writes.push(Buffer.from(bytes));callback(broken?new Error('synthetic_write_failure'):null);}});
  const transport=executionTransport(socket,{incoming:'w2c',receive(){assert.fail('未安排入站帧');},failed(){}});t.after(()=>transport.close());
  if(broken)await assert.rejects(journal.sendHandshake(transport));else assert.equal((await journal.sendHandshake(transport)).result,'complete');
  assert.equal(writes.length,1);assert.equal(JSON.parse(writes[0].subarray(4)).type,'HELLO_ACK');
  x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
   assert.deepEqual(db.prepare('SELECT wire FROM execution_frame_record WHERE record_id=?').pluck().get(receipt.ack_record_ref.id),writes[0]);
   assert.equal(db.prepare('SELECT result FROM execution_write_result').pluck().get(),broken?'unknown':'complete');
   assert.equal(db.prepare('SELECT count(*) FROM execution_write_attempt').pluck().get(),1);
  });
 }
});

test('schema30握手拒绝模块冒名、改原wire及重复写尝试，未知写不恢复会话',{timeout:30000},async t=>{
 for(const mode of ['module','wire','repeat','unknown','write_failure']){
  const options={revision:30};if(mode==='write_failure')options.inject="CREATE TRIGGER fail_write BEFORE INSERT ON execution_write_attempt BEGIN SELECT RAISE(IGNORE); END;";
  const x=await ready(t,options);await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key),frame=installedHello(x,journal);
  if(mode==='module'){frame.body.module_digest=hash('wrong');await assert.rejects(journal.negotiate(Buffer.from(JSON.stringify(frame))),/execution_hello_module/);}
  else{
   await journal.negotiate(Buffer.from(JSON.stringify(frame)));
   if(mode==='wire')await assert.rejects(journal.negotiate(Buffer.from(JSON.stringify(frame,null,1))),/execution_replay_conflict/);
   else if(mode==='write_failure')assert.throws(()=>journal.beginHandshakeWrite(),/execution_handshake_storage/);
   else {const write=journal.beginHandshakeWrite();journal.finishHandshakeWrite(write.attempt_id,mode==='unknown'?'unknown':'complete');
    if(mode==='repeat')assert.throws(()=>journal.beginHandshakeWrite());}
  }
  assert.throws(()=>journal.beginHandshakeWrite());x.a.real.stop();x.f.close();
  inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM execution_session_end').pluck().get(),1);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
 }
});

test('执行日志由真实writer绑定已采用运行，拒收原wire与终止同提交且查原不重处理',{timeout:20000},async t=>{
 const x=await ready(t,{revision:27});await x.runtime.adopt(x.key);
 const journal=x.f.store.workerLaunches.openExecutionJournal(x.key),binding=journal.binding;
 assert.equal(binding.worker_boot_id,x.runtime.current(x.key).binding.admission_receipt.member_boot_id);
 assert.equal(binding.controller_boot_id,x.core.receipt.member_boot_id);assert.ok(Object.isFrozen(binding.device_ids));
 assert.equal(binding.ipc_session_id,executionSessionIdentity({authority_service_id:binding.service_id,database_instance_id:binding.database_instance_id,
  controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest}).ipc_session_id);
 const bytes=Buffer.from(JSON.stringify(hello(x,journal),null,1)),result=await journal.rejectUnsupported(bytes);
 assert.equal(result.disposition,'rejected');assert.deepEqual(journal.lookup(bytes),result);
 assert.throws(()=>journal.lookup(Buffer.from(JSON.stringify(hello(x,journal)))),/execution_replay_conflict/);
 await assert.rejects(journal.rejectUnsupported(bytes),/execution_session_ended/);
 x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM execution_session').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM execution_rejection_commit').pluck().get(),1);
  const [wire,end]=db.prepare('SELECT r.wire,e.reason FROM execution_rejection r JOIN execution_session_end e USING(ipc_session_id)').raw().get();
  assert.deepEqual(wire.subarray(4),bytes);assert.equal(end,'unsupported_message');
  assert.throws(()=>db.exec('DELETE FROM execution_session_end'),/immutable_execution_end/);
  assert.throws(()=>db.exec('UPDATE execution_rejection SET frame_digest=wire_digest'),/immutable_execution_rejection/);
 });
});

test('错会话或缺号消息终止会话，不保存伪造成功；同一worker不重建会话',{timeout:20000},async t=>{
 for(const changes of [{controller_boot_id:'foreign.core'},{seq:'2'}]){
  const x=await ready(t,{revision:27});await x.runtime.adopt(x.key);
  const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
  await assert.rejects(journal.rejectUnsupported(Buffer.from(JSON.stringify(hello(x,journal,changes)))),/execution_(frame_binding|handshake_required)/);
  assert.equal(journal.lookup(Buffer.from('{}')),null);
  assert.throws(()=>x.f.store.workerLaunches.openExecutionJournal(x.key),/worker_runtime_unavailable/);
  x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
   assert.equal(db.prepare('SELECT count(*) FROM execution_rejection').pluck().get(),0);
   assert.equal(db.prepare('SELECT reason FROM execution_session_end').pluck().get(),'protocol_error');
  });
 }
});

test('拒收提交失败回滚原件，终止先锁存；重启关闭未能落盘的旧会话',{timeout:20000},async t=>{
 const x=await ready(t,{revision:27,inject:"CREATE TRIGGER synthetic_rejection_failure BEFORE INSERT ON execution_rejection_commit BEGIN SELECT RAISE(ABORT,'synthetic_execution_failure'); END; CREATE TRIGGER synthetic_end_failure BEFORE INSERT ON execution_session_end BEGIN SELECT RAISE(ABORT,'synthetic_end_failure'); END;"});
 await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key),bytes=Buffer.from(JSON.stringify(hello(x,journal)));
 await assert.rejects(journal.rejectUnsupported(bytes),/synthetic_execution_failure/);
 await assert.rejects(journal.rejectUnsupported(bytes),/execution_session_ended/);
 x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM execution_rejection').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM execution_rejection_commit').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM execution_session_end').pluck().get(),0);
  db.exec('DROP TRIGGER synthetic_end_failure');
 });
 x.f.reopen();assert.throws(()=>x.f.store.workerLaunches.openExecutionJournal(x.key),/worker_runtime_unavailable/);
 const history=x.f.store.workerLaunches.queryExecutionJournal(journal.binding.ipc_session_id);
 assert.equal(history.ended,true);assert.equal(history.end_reason,'restarted');assert.equal(history.rejection,null);x.f.close();
 inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT reason FROM execution_session_end').pluck().get(),'restarted');});
});

test('执行日志随运行撤回终止，缺少反向提交的SQL写入不能提交',{timeout:20000},async t=>{
 const x=await ready(t,{revision:27});await x.runtime.adopt(x.key);
 const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);x.runtime.invalidate(x.key);
 const history=x.f.store.workerLaunches.queryExecutionJournal(journal.binding.ipc_session_id);
 assert.equal(history.end_reason,'runtime_lost');assert.equal(history.rejection,null);
 x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
  db.pragma('foreign_keys=ON');
  for(const statement of ["INSERT INTO execution_session_commit VALUES('missing','missing','{}')","INSERT INTO execution_rejection_commit VALUES('missing','missing','missing')"])
   assert.throws(()=>db.transaction(()=>db.exec(statement)).immediate(),/FOREIGN KEY/);
  assert.equal(db.prepare('SELECT count(*) FROM execution_session_commit').pluck().get(),1);
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);
 });
});

test('schema26显式备份迁移27保留身份和运行历史，不恢复执行会话',{timeout:20000},async t=>{
 const x=await ready(t,{revision:26});const adopted=await x.runtime.adopt(x.key),identity=x.f.store.identity;
 assert.throws(()=>x.f.store.workerLaunches.openExecutionJournal(x.key),/execution_migration_required/);
 x.a.real.stop();x.f.close();const migrated=await migrateStorage(x.f.dir,27);
 assert.equal(migrated.schema_revision,'27');assert.equal(migrated.steps.length,1);
 assert.ok(fs.existsSync(x.f.dir+'/'+migrated.backup_file));x.f.reopen();
 assert.equal(x.f.store.identity.service_id,identity.service_id);assert.equal(x.f.store.identity.database_instance_id,identity.database_instance_id);
 assert.equal(x.f.store.workerLaunches.runtime.query(x.key).ref.digest,adopted.ref.digest);x.f.close();
 inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM execution_session').pluck().get(),0);assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);});
 assert.deepEqual(await migrateStorage(x.f.dir,27),{schema_revision:'27',changed:false});
});

test('schema28共享FrameRecord和EffectCommit与真实拒收领域同事务，保留原wire而不伪造成功',{timeout:20000},async t=>{
 const x=await ready(t,{revision:28});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
 const frame=hello(x,journal),bytes=Buffer.from(JSON.stringify(frame,null,2)),result=await journal.rejectUnsupported(bytes);
 assert.equal(result.journal.sequence,'1');assert.equal(result.journal.direction,'w2c');assert.equal(result.journal.disposition,'rejected');
 assert.deepEqual(journal.lookup(bytes),result);assert.throws(()=>journal.lookup(Buffer.from(JSON.stringify(frame))),/execution_replay_conflict/);
 x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
  assert.deepEqual(executionFrameReceipt(db,journal.binding.ipc_session_id,frame.message_id),result.journal);
  const [wire,recordText,effectText,domainText,auditText]=db.prepare(`SELECT f.wire,f.record_jcs,e.effect_jcs,x.domain_jcs,e.audit_jcs
   FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id) JOIN execution_rejection_frame x USING(record_id,transaction_id)`).raw().get();
  assert.deepEqual(wire.subarray(4),bytes);const record=JSON.parse(recordText),effect=JSON.parse(effectText),domain=JSON.parse(domainText);
  assert.equal(record.frame_digest,hash(frame));assert.notEqual(record.wire_digest,record.frame_digest);assert.equal(record.wire_length,bytes.length+4);
  assert.equal(effect.record_ref.digest,record.record_digest);assert.equal(effect.domain_commit_refs.length,1);assert.equal(effect.domain_commit_refs[0].digest,hash(domain));
  assert.equal(effect.audit_ref.digest,hash(JSON.parse(auditText)));assert.deepEqual(effect.reply_record_refs,[]);assert.ok(BigInt(effect.committed_tick_ns)>0n);
  assert.equal(domain.transaction_id,result.transaction_id);assert.equal(domain.reason,'unsupported_message');
  assert.equal(db.prepare("SELECT count(*) FROM execution_effect_commit WHERE disposition='applied'").pluck().get(),0);
  for(const table of ['execution_frame_record','execution_effect_commit','execution_rejection_frame'])assert.throws(()=>db.exec('DELETE FROM '+table),/immutable_execution/);
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);
 });
});

test('共享帧、领域、终止或EffectCommit缺写均整笔回滚，重试不产生第二次效果',{timeout:30000},async t=>{
 for(const table of ['execution_rejection_frame','execution_rejection_commit','execution_session_end','execution_effect_commit']){
  const x=await ready(t,{revision:28,inject:`CREATE TRIGGER synthetic_frame_failure BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_frame_failure'); END;`});
  await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key),bytes=Buffer.from(JSON.stringify(hello(x,journal)));
  await assert.rejects(journal.rejectUnsupported(bytes),/synthetic_frame_failure/);await assert.rejects(journal.rejectUnsupported(bytes),/execution_session_ended/);
  assert.equal(journal.lookup(bytes),null);x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
   for(const name of ['execution_frame_record','execution_effect_commit','execution_rejection_frame','execution_rejection','execution_rejection_commit'])
    assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0,name);
   assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);
  });
 }
});

test('共享提交约束拒绝applied替代拒收与假领域引用，原始帧修改可被查原检出',{timeout:30000},async t=>{
 for(const foreign of [false,true]){
  // 在INSERT进入领域约束前改NEW不受SQLite支持，借固定触发器改为错误的替代INSERT，原事务必须失败。
  const replacement=foreign?"NEW.disposition":"'applied'";
  const effect=foreign?"json_set(NEW.effect_jcs,'$.domain_commit_refs[0].id','foreign')":"NEW.effect_jcs";
  const inject=`CREATE TRIGGER synthetic_effect_replace BEFORE INSERT ON execution_effect_commit
   WHEN NEW.disposition='rejected' AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].id')!='foreign' BEGIN
   INSERT INTO execution_effect_commit VALUES(NEW.record_id,NEW.transaction_id,${replacement},NEW.committed_tick,NEW.audit_jcs,NEW.audit_digest,${effect},NEW.effect_digest);
   SELECT RAISE(IGNORE); END;`;
  const x=await ready(t,{revision:28,inject});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
  await assert.rejects(journal.rejectUnsupported(Buffer.from(JSON.stringify(hello(x,journal)))),/execution_effect_domain/);
  x.a.real.stop();x.f.close();inspect(x.f.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM execution_frame_record').pluck().get(),0));
 }
 const x=await ready(t,{revision:28});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key),frame=hello(x,journal);
 await journal.rejectUnsupported(Buffer.from(JSON.stringify(frame)));x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
  db.exec('DROP TRIGGER execution_frame_no_update');db.prepare('UPDATE execution_frame_record SET wire=?').run(Buffer.from('corrupt'));
  assert.throws(()=>executionFrameReceipt(db,journal.binding.ipc_session_id,frame.message_id),/execution_frame_integrity/);
 });
});

test('忽略帧或效果写入也不能提交悬空领域，双向约束不依赖主动抛错',{timeout:20000},async t=>{
 for(const table of ['execution_frame_record','execution_effect_commit']){
  const x=await ready(t,{revision:28,inject:`CREATE TRIGGER synthetic_missing BEFORE INSERT ON ${table} BEGIN SELECT RAISE(IGNORE); END;`});
  await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
  await assert.rejects(journal.rejectUnsupported(Buffer.from(JSON.stringify(hello(x,journal)))),/FOREIGN KEY|execution_rejection_frame_required/);
  x.a.real.stop();x.f.close();inspect(x.f.dir,db=>{
   for(const name of ['execution_frame_record','execution_effect_commit','execution_rejection_frame','execution_rejection','execution_rejection_commit'])
    assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0,name);
  });
 }
});

test('schema27备份迁移28保留旧拒收原件，不回填虚构时刻或重开旧会话',{timeout:20000},async t=>{
 const x=await ready(t,{revision:27});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
 const bytes=Buffer.from(JSON.stringify(hello(x,journal))),result=await journal.rejectUnsupported(bytes),identity=x.f.store.identity;
 x.a.real.stop();x.f.close();const migrated=await migrateStorage(x.f.dir,28);assert.equal(migrated.steps.length,1);assert.equal(migrated.schema_revision,'28');
 assert.ok(fs.existsSync(x.f.dir+'/'+migrated.backup_file));x.f.reopen();assert.equal(x.f.store.identity.service_id,identity.service_id);
 const history=x.f.store.workerLaunches.queryExecutionJournal(journal.binding.ipc_session_id);assert.equal(history.ended,true);assert.equal(history.rejection.transaction_id,result.transaction_id);
 x.f.close();inspect(x.f.dir,db=>{assert.deepEqual(db.prepare('SELECT wire FROM execution_rejection').pluck().get().subarray(4),bytes);
  assert.equal(db.prepare('SELECT count(*) FROM execution_frame_record').pluck().get(),0);assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);});
 assert.deepEqual(await migrateStorage(x.f.dir,28),{schema_revision:'28',changed:false});
});

test('schema28迁移29保留共享帧提交及终止会话，执行绑定初始为空',{timeout:20000},async t=>{
 const x=await ready(t,{revision:28});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
 const bytes=Buffer.from(JSON.stringify(hello(x,journal))),result=await journal.rejectUnsupported(bytes),identity=x.f.store.identity;
 x.a.real.stop();x.f.close();const migrated=await migrateStorage(x.f.dir,29);assert.equal(migrated.steps.length,1);assert.equal(migrated.schema_revision,'29');
 assert.ok(fs.existsSync(x.f.dir+'/'+migrated.backup_file));x.f.reopen();assert.equal(x.f.store.identity.service_id,identity.service_id);
 const history=x.f.store.workerLaunches.queryExecutionJournal(journal.binding.ipc_session_id);assert.equal(history.ended,true);assert.equal(history.rejection.transaction_id,result.transaction_id);
 x.f.close();inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM execution_frame_record').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM execution_effect_commit').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM device_execution_binding').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM device_execution_binding_commit').pluck().get(),0);
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);
 });assert.deepEqual(await migrateStorage(x.f.dir,29),{schema_revision:'29',changed:false});
});

test('schema29迁移30保留共享拒收原字节与领域提交，新增握手表保持为空',{timeout:20000},async t=>{
 const x=await ready(t,{revision:29});await x.runtime.adopt(x.key);const journal=x.f.store.workerLaunches.openExecutionJournal(x.key);
 const bytes=Buffer.from(JSON.stringify(hello(x,journal))),result=await journal.rejectUnsupported(bytes);
 x.a.real.stop();x.f.close();const migrated=await migrateStorage(x.f.dir,30);assert.equal(migrated.steps.length,1);assert.ok(fs.existsSync(x.f.dir+'/'+migrated.backup_file));
 x.f.reopen();const history=x.f.store.workerLaunches.queryExecutionJournal(journal.binding.ipc_session_id);
 assert.deepEqual(history.rejection.journal,result.journal);assert.equal(history.negotiation,null);assert.equal(history.ended,true);
 x.f.close();inspect(x.f.dir,db=>{
  assert.deepEqual(db.prepare('SELECT wire FROM execution_frame_record').pluck().get().subarray(4),bytes);
  assert.equal(db.prepare('SELECT count(*) FROM execution_handshake').pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });assert.deepEqual(await migrateStorage(x.f.dir,30),{schema_revision:'30',changed:false});
});

test('多个worker并发采用按来源串行复核，保持独立回执和运行绑定',{timeout:20000},async t=>{
 const x=await ready(t),second={...x.intent,launch_id:'worker.second',member_id:'member.second',containment_ref:{...x.intent.containment_ref,group_id:'group.second'}};
 await x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(second)));let busy=false,maximum=0;
 x.source.beforeObserve=async()=>{assert.equal(busy,false);busy=true;maximum++;await delay(40);busy=false;};
 const [a,b]=await Promise.all([x.runtime.adopt(x.key),x.runtime.adopt(key(second))]);assert.notEqual(a.ref.object_id,b.ref.object_id);
 assert.notEqual(a.binding.admission_receipt.receipt_id,b.binding.admission_receipt.receipt_id);assert.equal(maximum,2);
 assert.equal(x.runtime.current(x.key).withdrawal,null);assert.equal(x.runtime.current(key(second)).withdrawal,null);
});
