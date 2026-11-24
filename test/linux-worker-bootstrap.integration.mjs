import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import canonicalize from '../dist/runtime/canonicalize.mjs';
import {openNativeClock} from '../dist/native-clock.mjs';
import {bootstrapVersion} from '../dist/sdk/bootstrap.mjs';
import {deviceModuleProtocol} from '../dist/sdk/device-module.mjs';
import {connectDeviceModule} from '../dist/device-module-client.mjs';

const helper = process.env.LEAFSEAMER_TEST_LINUX_WORKER_HELPER;
const options = {skip:process.platform!=='linux'||!helper,timeout:30000};
const id = () => crypto.randomUUID();
const bytesDigest = bytes => 'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const digest = value => bytesDigest(canonicalize(value));
const identity = {service_id:'test-controller',database_instance_id:'test-database'};
const ref = (kind, objectId=kind, value=digest(kind)) => ({kind,object_id:objectId,revision:'1',digest:value,
  authority_service_id:identity.service_id,database_instance_id:identity.database_instance_id});
const dist = fileURLToPath(new URL('../dist/',import.meta.url));

function stat(file) {
  const info=fs.statSync(file,{bigint:true});
  return {device:String(info.dev),inode:String(info.ino)};
}

async function launch(t, {misplaced=false,missingChannel=false}={}) {
  assert.equal(process.geteuid(),0);
  const clock=openNativeClock({linuxWithoutSystemSleep:true});
  const generation=id(),launchId=id();
  const parent='/leafseamer_'+generation.replaceAll('-','')+'_controller';
  const groupPath=parent+'/worker_'+launchId.replaceAll('-','');
  const actualPath=misplaced?parent+'/core':groupPath;
  const root='/sys/fs/cgroup';
  fs.mkdirSync(root+actualPath,{recursive:true});
  const directory=fs.mkdtempSync('/tmp/leafseamer-linux-worker-');
  fs.chmodSync(directory,0o755);
  let child,closed;
  t.after(async()=>{
    child?.stdin.destroy();
    if(closed)await closed;
    assert.match(fs.readFileSync(root+actualPath+'/cgroup.events','utf8'),/^populated 0$/m);
    fs.rmdirSync(root+actualPath);
    fs.rmdirSync(root+parent);
    fs.rmSync(directory,{recursive:true});
  });

  const bootId=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim();
  const descriptorBody={descriptor_version:'clock-domain/1',domain_kind:'supervised_runtime',authority_service_id:identity.service_id,
    runtime_generation:generation,supervisor_instance_id:id(),clock_backend_id:'linux_boottime',clock_backend_revision:'1',
    tick_unit:'ns',suspend_accounting:'included',namespace_identity:'linux_'+clock.capture().raw.namespace_after.replace(':','_'),
    os_boot_identity:{status:'verified',source:'linux-proc-boot-id',value:bootId,evidence_ref:bootId},
    platform_profile_id:'platform_profile',platform_profile_revision:'1'};
  const descriptorDigest=digest(descriptorBody),domain={clock_domain_id:'clock_'+descriptorDigest.slice(7),descriptor_digest:descriptorDigest};
  const descriptor={...descriptorBody,...domain};
  const manifest={extension_id:'test-simulator',entrypoints:[{kind:'worker',loader:'node_module',entry_id:'simulator',file_id:'simulator',io_policy_file_id:'policy'}],
    api_versions:['leafseamer-device-module/2'],ipc_versions:[deviceModuleProtocol]};
  const moduleSource=fs.readFileSync(path.join(dist,'simulator-module.mjs'));
  const inventory={files:[['simulator','module','simulator.mjs',moduleSource],['policy','policy','policy.json',Buffer.from('{}')]].map(([file_id,role,name,bytes])=>{
    fs.writeFileSync(path.join(directory,name),bytes,{mode:0o444});
    return {file_id,role,path:name,size_bytes:String(bytes.length),digest:bytesDigest(bytes)};
  })};
  const configurationRef=ref('configuration');
  const group=stat(root+actualPath);
  const intent={launch_id:launchId,service_id:identity.service_id,supervisor_instance_id:descriptor.supervisor_instance_id,
    runtime_generation:generation,role:'worker',member_id:id(),artifact_manifest_ref:{manifest_id:'controller',revision:'1',digest:digest('test-bundle')},
    containment_ref:{backend:'linux_cgroup_v2',generation,group_id:'group_'+digest({boot_id:bootId,group_path:actualPath,group}).slice(7)},
    object_scope:{kind:'devices',device_ids:['device.test']},policy_revision:'1',extension_binding:{installation_ref:ref('installation'),
      approval_ref:ref('approval'),review_ref:ref('review'),role_resolution_ref:ref('role_resolution'),configuration_ref:configurationRef,
      intake_ref:ref('intake'),platform_profile_ref:ref('platform_profile'),host_installation_id:'test-host',host_trust_epoch:'1',
      manifest_digest:digest(manifest),artifact_set_digest:digest(inventory),entry_id:'simulator',permissions_digest:digest('read-only')}};
  const timeout=5000;
  const context=canonicalize({format:'leafseamer-device-worker-start/3',descriptor,identity,intent,timeout_ms:timeout,
    module:{root_path:directory,manifest,inventory},execution:{controller_boot_id:id().replaceAll('-','')}});
  const configFile=path.join(directory,'worker.json');
  fs.writeFileSync(configFile,context,{mode:0o444});
  const node=fs.realpathSync(process.execPath),image=stat(node);
  child=spawn(helper,[root+actualPath,group.device,group.inode,node,image.device,image.inode,'65534','65534','--device-worker','--',
    '--disallow-code-generation-from-strings',path.join(dist,'device-worker-entry.mjs'),'--context-file',configFile,'--context-digest',bytesDigest(context)],
  {stdio:['pipe','pipe','pipe','pipe','pipe',missingChannel?'ignore':'pipe']});
  closed=once(child,'close');
  let stderr='';child.stderr.on('data',chunk=>{stderr+=chunk;});
  child.stdin.on('error',()=>{});
  for(const channel of child.stdio.slice(3))channel?.on('error',()=>{});
  if(missingChannel){
    assert.equal((await closed)[0],1);
    assert.match(stderr,/linux_member_inputs/);
    return null;
  }
  const stages=createInterface({input:child.stdout})[Symbol.asyncIterator]();
  const created=JSON.parse((await stages.next()).value);
  assert.equal(created.phase,'created_closed');
  assert.equal(fs.readFileSync('/proc/'+created.pid+'/cgroup','utf8'),'0::'+actualPath+'\n');
  child.stdin.write('R');
  assert.equal(JSON.parse((await stages.next()).value).phase,'executed');
  const bootstrap=child.stdio[3];
  const frames=createInterface({input:bootstrap})[Symbol.asyncIterator]();
  const key=crypto.randomBytes(32),now=clock.tick();
  const common={bootstrap_id:id(),launch_id:launchId,launch_intent_digest:digest(intent),member_id:intent.member_id,
    member_boot_id:id(),role:'worker',artifact_manifest_ref:intent.artifact_manifest_ref,channel_binding_id:id()};
  const challenge={...common,bootstrap_version:bootstrapVersion,challenge_id:id(),challenge_nonce:crypto.randomBytes(32).toString('base64url'),
    issued_tick_ns:String(now),expires_tick_ns:String(now+BigInt(timeout)*1000000n)};
  function send(type,payload){bootstrap.write(canonicalize({version:bootstrapVersion,type,payload})+'\n');}
  send('ASSIGNMENT',{...challenge,clock_domain_descriptor:descriptor,secret:key.toString('base64url')});
  let proof;
  try{proof=await frames.next();}catch(error){
    if(error.code!=='ECONNRESET')throw error;
    proof={done:true};
  }
  if(misplaced){assert.equal(proof.done,true);assert.equal((await closed)[0],1);return null;}
  if(proof.done){const result=await closed;assert.fail(`Worker stopped before proof (${result[0]}): ${stderr}`);}
  const expected=crypto.createHmac('sha256',key).update('leafseamer-bootstrap-proof/v1\0','ascii').update(canonicalize({...challenge,...domain})).digest('base64url');
  assert.equal(JSON.parse(proof.value).payload.proof,expected);
  const receipt={...common,receipt_id:id(),domain_ref:domain,containment_ref:intent.containment_ref,os_observation_ref:id(),
    gate_state:'closed',admitted_tick_ns:String(clock.tick())};
  send('ADMISSION',receipt);
  const binding={format:'leafseamer-worker-runtime-binding/1',runtime_binding_id:id(),...identity,service_boot_id:id(),
    launch_intent:intent,clock_domain_descriptor:descriptor,admission_receipt:receipt,gate_state:'closed'};
  return {child,closed,receipt,binding,configurationRef};
}

test('Linux 固定 Worker 经真实 cgroup 准入，并在继承通道内读取模拟器状态',options,async t=>{
  const {child,closed,receipt,binding,configurationRef}=await launch(t);
  const recorded=[];
  const module=await connectDeviceModule({socket:child.stdio[4],configuration:{reference:configurationRef,value:{}},
    current:()=>({current_boot:true,withdrawal:null,binding,ref:ref('runtime_binding',binding.runtime_binding_id,digest(binding))}),
    invalidate:()=>{},journal:{open(){},record(direction,frame){recorded.push([direction,frame.type]);}}});
  const opened=await module.connectReadOnly('device.test');
  assert.equal(opened.binding.member_boot_id,receipt.member_boot_id);
  assert.equal(opened.body.identity.model,'leafseamer.simulator');
  assert.deepEqual((await module.captureBaseline('device.test')).body.value,{sample_sequence:'1',value:0});
  assert.deepEqual((await module.captureBaseline('device.test')).body.value,{sample_sequence:'2',value:0});
  assert.deepEqual(recorded.slice(0,2),[['c2w','LOAD'],['w2c','LOADED']]);
  child.stdio[3].end();
  assert.equal((await closed)[0],1);
  assert(child.stdio[4].destroyed);
});

test('Linux Worker 拒绝核心 cgroup 和缺失的专属通道',options,async t=>{
  await launch(t,{misplaced:true});
  await launch(t,{missingChannel:true});
});
