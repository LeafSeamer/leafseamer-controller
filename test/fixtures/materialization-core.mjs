import fs from 'node:fs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {setTimeout as delay} from 'node:timers/promises';
import {connectCoreSupervisor} from '../../dist/supervisor-control.mjs';
import {openNativeClock} from '../../dist/native-clock.mjs';
import {createCoreBootstrapChannel,verifyCoreAdmission} from '../../dist/core-bootstrap.mjs';
import {openStorage} from '../../dist/storage.mjs';
import {authenticated} from './extension-auth.mjs';
let business=null,intakeClient=null,manager=null,moduleClient=null,intakeTail=Promise.resolve();
// 运行刷新与启动授权共享单请求安装连接；装配层串行查询，不重发或复用旧观察。
function queryIntake(request){const result=intakeTail.then(()=>intakeClient.queryIntake(request));intakeTail=result.catch(()=>{});return result;}
const args=process.argv.slice(3),options=Object.fromEntries(Array.from({length:args.length/2},(_,i)=>[args[i*2],args[i*2+1]]));
const report=value=>process.stderr.write(JSON.stringify(value)+'\n');
const boot=createCoreBootstrapChannel(process.stdin,process.stdout,{timeoutMs:10000});
const assignment=await boot.assignment(),receipt=await boot.proveAndReceive(assignment);boot.release();
const policy=JSON.parse(options['--bootstrap-policy']),input=JSON.parse(fs.readFileSync(options['--fixture']));
const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],policy,binding:{descriptor:assignment.clock_domain_descriptor,receipt}});
const clock=openNativeClock(),hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const ref=kind=>({kind,authority_service_id:policy.service_id,database_instance_id:policy.database_instance_id,object_id:kind,revision:'1',digest:hash(kind)});
const intent={launch_id:'worker.launch',service_id:policy.service_id,supervisor_instance_id:source.scope.supervisor_instance_id,
  runtime_generation:assignment.clock_domain_descriptor.runtime_generation,member_id:'worker.member',role:'worker',artifact_manifest_ref:policy.artifact_manifest_ref,
  containment_ref:{group_id:'worker.group',generation:'worker.generation',backend:'windows_job'},object_scope:{kind:'devices',device_ids:input.runtime?.devices??['device.synthetic']},policy_revision:policy.policy_revision,
  extension_binding:{installation_ref:ref('installation'),approval_ref:ref('approval'),review_ref:ref('review'),role_resolution_ref:ref('role_resolution'),configuration_ref:ref('configuration'),
    ...input.binding,entry_id:input.mode==='supervisor_bad_entry'?'missing':input.materials?'worker':'simulator',permissions_digest:hash('permissions'),...(input.runtime?{installation_ref:input.runtime.approved.record.installation_ref,approval_ref:input.runtime.approved.approval_ref,review_ref:input.runtime.approved.record.review_ref,role_resolution_ref:input.runtime.approved.record.role_resolution_ref,configuration_ref:input.runtime.approved.record.configuration_ref,permissions_digest:input.runtime.approved.record.permissions_digest}:{})}};
const key={launch_id:intent.launch_id,launch_intent_digest:hash(intent)};
const seal=grant=>{const {authorization_ref,...body}=grant;return {...body,authorization_ref:{...authorization_ref,digest:hash(body)}};};
const authorization=()=>{const now=clock.tick();return seal({authorization_ref:ref('launch_authorization'),...key,installation_ref:intent.extension_binding.installation_ref,approval_ref:intent.extension_binding.approval_ref,
  role_resolution_ref:intent.extension_binding.role_resolution_ref,permissions_digest:intent.extension_binding.permissions_digest,supervisor_instance_id:source.scope.supervisor_instance_id,fence_revision:'1',
  lifetime:{clock:source.scope.domain_ref,issued_tick:String(now),deadline_tick:String(now+2000000000n)}});};
const fence=(revision,disposition)=>{const value={scope:source.scope,revision,items:[{...key,disposition}]};return {...value,digest:hash(value)};};
if(!input.runtime){await source.putFence(fence('1','allow'));await source.registerWorker(intent,authorization());report({event:'registered',key});}
if(input.runtime){
 business=openStorage(options['--data-dir']);business.bindCoreRuntime(await verifyCoreAdmission(assignment,receipt,policy),policy);
 const clientConfig=input.runtime.installation_client;
 const {captureInstallationPeer,createInstallationChannel}=await import(clientConfig.peer_module);
 const {createInstallationClient}=await import(clientConfig.client_module);
 report({event:'intake-peer',pid:process.pid});
 const intakeDeadline=performance.now()+10000;
 while(!fs.existsSync(options['--fixture']+'.intake-ready')){if(performance.now()>=intakeDeadline)throw new Error('fixture_intake_ready_timeout');await delay(20);}
 const channel=createInstallationChannel({name:clientConfig.name,peer:captureInstallationPeer(clientConfig.server_pid),server:false});await channel.ready;
 intakeClient=createInstallationClient({channel,channel_id:clientConfig.channel_id});
 const content=input.runtime.content;business.extensionInstallations.bindSource({identity:{host_installation_id:content.receipt.host_installation_id,authority_service_id:content.intake_ref.authority_service_id,database_instance_id:content.intake_ref.database_instance_id},
  async describeIntake(request){if(request.intake_id!==content.intake_ref.object_id||request.target_authority_service_id!==policy.service_id)throw new Error('fixture_intake_binding');
   // 实际独立安装IPC查询；回执绑定已封存manifest/inventory的摘要，无须先登记worker。
   const response=await queryIntake(request);if(response.result?.status!=='available'||canonicalize(response.result.receipt)!==canonicalize(content.receipt))throw new Error('fixture_intake_unavailable');
   return {status:'available',content};}});
 business.workerLaunches.runtime.bindSource(source);business.extensionInstallations.bindRuntimeSource(source);business.workerLaunches.authorization.bindSource(source);
 manager=await authenticated({after(){}},{store:business});
 {
  const token=manager.token(),plan=await manager.sessions.planExtension(token,{request_id:'runtime.plan',slot_id:content.slot_id,expected_slot_revision:input.runtime.slot_ref.revision,
   selection:{kind:'activate',source_installation_ref:null,target_installation_ref:input.runtime.approved.record.installation_ref,reuse_content_ref:null,configuration_ref:input.runtime.approved.record.configuration_ref}});
  await manager.sessions.getCurrentExtensionPlan(token,plan.plan_ref);report({event:'plan-created',plan});
  const activation=await manager.sessions.activateExtension(token,{request_id:'runtime.activate',slot_id:content.slot_id,expected_slot_revision:input.runtime.slot_ref.revision,
   target_installation_ref:input.runtime.approved.record.installation_ref,approval_ref:input.runtime.approved.approval_ref,dependency_plan_ref:plan.plan_ref});report({event:'activation-accepted',activation});
  await business.workerLaunches.prepare(Buffer.from(canonicalize(intent)));
  try{await manager.sessions.getCurrentExtensionPlan(token,plan.plan_ref);report({event:'plan-invalidated',code:'unexpected_success'});}
  catch(error){report({event:'plan-invalidated',code:error.code});}
 }
 const registered=await business.workerLaunches.authorization.register(key);report({event:'registered',key,record:registered});
}
try{
 if(input.materials){
  const held=await source.loadWorkerContent(key,input.materials);report({event:'loaded',load_id:held.load_id});
  const until=performance.now()+10000;
  while(!fs.existsSync(options['--fixture']+'.continue')){if(performance.now()>=until)throw new Error('fixture_wait');await delay(20);}
  if(input.mode.startsWith('supervisor_create')){
    const fresh=await source.prepareWorkerMaterialization(key),{lifetime,...proof}=fresh.observation;report({event:'create-ready'});
    if(input.mode==='supervisor_create_bad_profile'){
      try{await source.createWorker({key,authorization:authorization(),load_id:held.load_id,...proof});report({event:'profile-rejected',code:'unexpected_success'});}
      catch(error){report({event:'profile-rejected',code:error.code});}
    }else{
    const first=business?await business.workerLaunches.authorization.create(key,{load_id:held.load_id,...proof}):await source.createWorker({key,authorization:authorization(),load_id:held.load_id,...proof});report({event:'created',record:first});
    if(input.mode==='supervisor_create_deny_pending')await source.putFence(fence('2','deny'));
    const deadline=performance.now()+10000;let current=first;
    while(current.state==='creating'||current.state==='awaiting_bootstrap'){
      if(performance.now()>=deadline)throw new Error('fixture_bootstrap_timeout');await delay(25);current=await source.queryLaunch(key);
    }
    report({event:'admitted',record:current});
    if(business){const adopted=await business.workerLaunches.runtime.adopt(key);business.workerLaunches.runtime.current(key);report({event:'runtime-adopted',binding:adopted});}
    if(input.mode.startsWith('supervisor_create_module')){
      moduleClient=await business.workerLaunches.openModule(key);const device=intent.object_scope.device_ids[0];
      const connected=await moduleClient.connectReadOnly(device),first=await moduleClient.captureBaseline(device),second=await moduleClient.captureBaseline(device);
      const disconnected=await moduleClient.stopReadOnly(device);
      try{await moduleClient.captureBaseline(device);report({event:'module-disconnected-read',code:'unexpected_success'});}
      catch(error){report({event:'module-disconnected-read',code:error.code});}
      const reconnected=await moduleClient.connectReadOnly(device),third=await moduleClient.captureBaseline(device);
      report({event:'module-samples',connected,first,second,disconnected,reconnected,third});
    }
    let observed;if(current.state==='admitted_closed'){observed=await source.observeWorker(intent);source.assertWorkerObservation(observed);report({event:'observed',receipt:observed.receipt});
      try{source.assertWorkerObservation(structuredClone(observed));report({event:'copied-observation',code:'unexpected_success'});}catch(error){report({event:'copied-observation',code:error.code});}}
    try{if(business)await business.workerLaunches.authorization.create(key,{load_id:held.load_id,...proof});else await source.createWorker({key,authorization:authorization(),load_id:held.load_id,...proof});report({event:'duplicate',code:'unexpected_success'});}
    catch(error){report({event:'duplicate',code:error.code});}
    if(business){manager.sessions.revokeExtensionApproval(manager.token(),{request_id:'runtime.deny',approval_ref:input.runtime.approved.approval_ref,reason:'人员撤销'});await business.workerLaunches.authorization.synchronize();}
    else if(input.mode!=='supervisor_create_deny_pending')await source.putFence(fence('2','deny'));report({event:'denied',record:await source.queryLaunch(key)});
    if(moduleClient){try{await moduleClient.captureBaseline(intent.object_scope.device_ids[0]);report({event:'module-revoked',code:'unexpected_success'});}
      catch(error){report({event:'module-revoked',code:error.code});}}

    if(observed){try{source.assertWorkerObservation(observed);report({event:'withdrawn-observation',code:'unexpected_success'});}catch(error){report({event:'withdrawn-observation',code:error.code});}}
    if(business){try{business.workerLaunches.runtime.current(key);}catch{}report({event:'runtime-withdrawn',binding:business.workerLaunches.runtime.query(key)});}
    const retirementDeadline=performance.now()+5000;
    for(;;){try{report({event:'retired',result:await source.retireWorker(intent,'revoked')});break;}
      catch(error){if(error.code!=='supervisor_indeterminate'||performance.now()>=retirementDeadline)throw error;await delay(25);}}
  }
  }
  if(input.mode==='supervisor_deny')await source.putFence(fence('2','deny'));
  const released=await held.release();report({event:'released',status:released.status});
 }else{
  const started=performance.now(),pending=source.prepareWorkerMaterialization(key);
  if(input.mode==='revoke_pending'){await delay(100);await source.putFence(fence('2','deny'));}
  const result=await pending;
  source.assertCurrent();report({event:'verified',result,elapsed_ms:performance.now()-started});
  const create=async(name,proof)=>{try{await source.createWorker({key,authorization:authorization(),load_id:'unresolved.load',...proof});report({event:name,code:'unexpected_success'});}catch(error){report({event:name,code:error.code});}};
  await create('forged',{materialization_evidence_id:'forged',materialization_challenge_id:'forged'});
  const {lifetime,...proof}=result.observation;
  await create('unapproved',proof);
  await delay(Number((BigInt(lifetime.deadline_tick)-clock.tick())/1000000n)+40);
  source.assertCurrent();await create('expired',proof);
  await source.putFence(fence('2','deny'));
  try{await source.prepareWorkerMaterialization(key);report({event:'revoked',code:'unexpected_success'});}catch(error){report({event:'revoked',code:error.code});}
 }
}catch(error){report({event:'unavailable',code:error.code,errors:error.errors?.map(e=>e.code)});
 if(input.mode.startsWith('supervisor_create_module')){
  const until=performance.now()+5000;
  for(;;){try{report({event:'module-failed-retired',result:await source.retireWorker(intent,'revoked')});break;}
   catch(error){if(error.code!=='supervisor_indeterminate'||performance.now()>=until)throw error;await delay(25);}}
 }
}
report({event:'done',record:await source.queryLaunch(key)});
process.stdin.setEncoding('utf8').on('data',data=>{if(data==='stop\n'){manager?.real.stop();intakeClient?.close();business?.close();source.close();process.stdin.destroy();}});process.stdin.resume();
