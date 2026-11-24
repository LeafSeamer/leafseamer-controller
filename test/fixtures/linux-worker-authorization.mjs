import assert from 'node:assert/strict';
import fs from 'node:fs';
import {openLinuxCoreBootstrap} from '../../dist/linux-core-bootstrap.mjs';
import {openNativeClock} from '../../dist/native-clock.mjs';
import {setup} from './extension-capabilities.mjs';
import {authenticated} from './extension-auth.mjs';
import {workerIntent} from './core-binding.mjs';
import {hash} from './extension-installation.mjs';

const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const cleanup=[];
const fixture={after(fn){cleanup.unshift(fn);}};
try{
  const clock=openNativeClock(),channel=openLinuxCoreBootstrap(input.policy,'controller',{workerControl:true});
  fixture.after(()=>channel.close());
  const {binding,supervision,policy}=await channel.accept({identity:input.policy,source:clock});
  const x=await setup(fixture,{revision:109,directory:input.data,prepareHost(host){
    host.content.manifest.platforms=['linux-x64'];
    host.content.receipt.platform_profile_ref.object_id=policy.platform_profile_ref.profile_id;
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
  a.sessions.revokeExtensionApproval(token,{request_id:'revoke',approval_ref:approved.approval_ref,reason:'测试撤销'});
  const fence=await start.synchronize();
  assert.deepEqual(fence.items,[{...key,disposition:'deny'}]);
  assert.equal((await supervision.queryLaunch(key)).state,'rejected');
  await assert.rejects(start.authorize(key),{code:'worker_authorization_denied'});
  const next={scope:fence.scope,revision:String(Number(fence.revision)+1),items:[{...key,disposition:'allow'}]};
  await assert.rejects(supervision.putFence({...next,digest:hash(next)}),{code:'supervisor_unauthorized'});
  assert.equal((await supervision.queryLaunch(key)).state,'rejected');
  fs.writeFileSync(input.result,JSON.stringify({ok:true,key,deniedRevision:fence.revision,coreReceipt:binding.receipt.receipt_id}));
}catch(error){
  fs.writeFileSync(input.result,JSON.stringify({ok:false,error:error.stack}));process.exitCode=1;
}finally{
  for(const close of cleanup)await close();
}
