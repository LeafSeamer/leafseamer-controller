import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {openLinuxCoreBootstrap} from '../../dist/linux-core-bootstrap.mjs';
import {openNativeClock} from '../../dist/native-clock.mjs';
import {setup} from './extension-capabilities.mjs';
import {authenticated} from './extension-auth.mjs';
import {workerIntent} from './core-binding.mjs';
import {hash} from './extension-installation.mjs';

const compose=process.argv[2]==='contained-compose-linux';
const inputFile=compose?path.join('/var/lib/leafseamer','worker-test.json'):process.argv[2];
const input=JSON.parse(fs.readFileSync(inputFile,'utf8'));
const cleanup=[];
const fixture={after(fn){cleanup.unshift(fn);}};
try{
  const clock=openNativeClock(),channel=openLinuxCoreBootstrap(input.policy,'controller',{compose,workerControl:true,workerChannelDirectory:input.channelDirectory});
  fixture.after(()=>channel.close());
  const {binding,supervision,policy}=await channel.accept({identity:input.policy,source:clock});
  if(compose){
    const until=performance.now()+10000;
    while(!fs.existsSync(input.start)){
      supervision.assertCurrent();assert.ok(performance.now()<until,'Compose supervisor did not finish admitting both cores');
      await delay(25);
    }
  }
  const capabilityTemplate=input.channelDirectory?JSON.parse(fs.readFileSync(new URL('../../dist/simulator-control-capability.json',import.meta.url),'utf8')):undefined;
  const x=await setup(fixture,{revision:109,directory:input.data,capabilityTemplate,reviewedActions:capabilityTemplate?.actions.map(action=>action.action_id),prepareHost(host){
    if(input.materialization){
      Object.assign(host.identity,input.materialization.identity);
      Object.assign(host.content,input.materialization.content);
    }else{
      host.content.manifest.platforms=['linux-x64'];
      host.content.receipt.platform_profile_ref.object_id=policy.platform_profile_ref.profile_id;
    }
  }});
  const store=x.f.store;
  store.bindCoreRuntime(binding,policy,supervision);
  store.extensionInstallations.bindRuntimeSource(supervision);
  store.workerLaunches.runtime.bindSource(supervision);
  const start=store.workerLaunches.authorization;start.bindSource(supervision);
  const a=await authenticated(fixture,x.f),token=a.token();
  const approved=await a.sessions.approveExtension(token,x.request);
  store.configureVirtualDevice({request_id:'resource',device_id:x.registered.device_id});
  const plan=await a.sessions.planExtension(token,{request_id:'plan',slot_id:x.installed.slot.record.slot_id,
    expected_slot_revision:x.installed.slot.slot_ref.revision,selection:{kind:'activate',source_installation_ref:null,
      target_installation_ref:x.installed.installation_ref,reuse_content_ref:null,configuration_ref:x.config.configuration_ref}});
  a.sessions.activateExtension(token,{request_id:'activate',slot_id:plan.slot_ref.object_id,expected_slot_revision:plan.slot_ref.revision,
    target_installation_ref:x.installed.installation_ref,approval_ref:approved.approval_ref,dependency_plan_ref:plan.plan_ref});
  const intent={...workerIntent(store,binding,x.host.content,approved,[x.registered.device_id]),launch_id:input.launchId,containment_ref:input.containment};
  const prepared=await store.workerLaunches.prepare(Buffer.from(JSON.stringify(intent)));
  const key={launch_id:intent.launch_id,launch_intent_digest:prepared.ref.digest};
  const first=await start.authorize(key);
  const {authorization_ref,...original}=first;
  const past={...original,lifetime:{...original.lifetime,issued_tick:'0',deadline_tick:'1'}};
  await assert.rejects(supervision.registerWorker(intent,{...past,authorization_ref:{...authorization_ref,digest:hash(past)}}),{code:'supervisor_expired'});
  assert.equal(await supervision.queryLaunch(key),null);
  assert.equal((await start.register(key)).state,'registered');
  assert.equal((await start.register(key)).state,'registered');
  assert.equal(store.workerLaunches.runtime.query(key),null);
  let adopted=null,module=null,execution=null;
  if(input.materialization){
    const proof=await supervision.prepareLinuxWorkerContent(key);
    await assert.rejects(start.create(key,{...proof,load_id:'unrelated-load'}),{code:'supervisor_unauthorized'});
    const created=await start.create(key,proof);
    assert.equal(created.state,'admitted_closed');assert.equal(created.creation_attempted,true);
    adopted=await store.workerLaunches.runtime.adopt(key);
    assert.deepEqual(adopted.binding.admission_receipt,created.admission_receipt);
    assert.equal(adopted.binding.gate_state,'closed');
    if(input.channelDirectory){
      // 同 UID/GID 和同 cgroup 的另一个进程也不能认领通道。
      const endpoint=path.join(input.channelDirectory,created.admission_receipt.member_boot_id+'.module');
      execFileSync(process.execPath,['--input-type=module','-e',
        "import {createConnection} from 'node:net'; const socket=createConnection(process.argv[1]); socket.on('error',()=>{process.exitCode=1;}); socket.on('data',()=>{process.exitCode=1;});",endpoint],{timeout:1000});
      const device=x.registered.device_id;
      module=await store.workerLaunches.openModule(key,{events:true});
      assert.equal((await module.connectReadOnly(device)).body.identity.model,'leafseamer.simulator.control');
      assert.deepEqual((await module.captureBaseline(device)).body.value,{value:0,sample_sequence:'1',write_sequence:'0'});
      assert.equal(module.currentBaseline(device).approval.evidence_policy.write_eligible,false);
      execution=await store.workerLaunches.openExecution(key);
      assert.equal(execution.binding.worker_boot_id,created.admission_receipt.member_boot_id);
      assert.equal(execution.binding.controller_boot_id,binding.receipt.member_boot_id);
      assert.equal(execution.state.gate_state,'closed');
      assert.equal((await module.configureExecution(device)).value.state,'bound_closed');
      await module.startEvents(device);
      assert.deepEqual((await module.readEvents(device)).body.result.batch.events,[]);
      await assert.rejects(store.workerLaunches.openModule(key,{events:true}),{code:'worker_module_capacity'});
      await assert.rejects(store.workerLaunches.openExecution(key),{code:'execution_client_capacity'});
    }
    await assert.rejects(start.create(key,proof),{code:'worker_authorization_creation_attempted'});
  }
  a.sessions.revokeExtensionApproval(token,{request_id:'revoke',approval_ref:approved.approval_ref,reason:'测试撤销'});
  const fence=await start.synchronize();
  assert.deepEqual(fence.items,[{...key,disposition:'deny'}]);
  const terminal=adopted?'retired':'rejected';
  assert.equal((await supervision.queryLaunch(key)).state,terminal);
  if(module){
    await assert.rejects(module.captureBaseline(x.registered.device_id));
    await assert.rejects(execution.initialFence(x.registered.device_id),{code:'execution_client_closed'});
    await assert.rejects(store.workerLaunches.openModule(key,{events:true}));
  }
  await assert.rejects(start.authorize(key),{code:'worker_authorization_denied'});
  const next={scope:fence.scope,revision:String(Number(fence.revision)+1),items:[{...key,disposition:'allow'}]};
  await assert.rejects(supervision.putFence({...next,digest:hash(next)}),{code:'supervisor_unauthorized'});
  assert.equal((await supervision.queryLaunch(key)).state,terminal);
  fs.writeFileSync(input.result,JSON.stringify({ok:true,key,deniedRevision:fence.revision,coreReceipt:binding.receipt.receipt_id,
    workerReceipt:adopted?.binding.admission_receipt??null}));
}catch(error){
  fs.writeFileSync(input.result,JSON.stringify({ok:false,error:error.stack}));process.exitCode=1;
}finally{
  for(const close of cleanup)await close();
}
