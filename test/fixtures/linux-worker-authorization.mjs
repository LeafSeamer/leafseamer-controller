import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import https from 'node:https';
import {once} from 'node:events';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {openLinuxCoreBootstrap} from '../../dist/linux-core-bootstrap.mjs';
import {openNativeClock} from '../../dist/native-clock.mjs';
import {setup} from './extension-capabilities.mjs';
import {authenticated} from './extension-auth.mjs';
import {workerIntent} from './core-binding.mjs';
import {hash,inspect} from './extension-installation.mjs';
import {createAuthenticationHttp} from '../../dist/auth-http.mjs';
import {createLocalExtensionManagement,localExtensionPath} from '../../dist/local-extension-management.mjs';
import {localPairingPath,runLocalExtensionAdmin,runLocalPairingAdmin} from '../../dist/local-pairing-admin.mjs';
import {manageLocalEvents} from '../../dist/local-event-management.mjs';
import {commandPermissions,prepareAutomaticSimulator,prepareManualSimulator,writeManualSimulator} from './linux-simulator-command.mjs';
import {simulatorPairingInputs,startSimulatorPairing} from './linux-simulator-pairing.mjs';

const compose=process.argv[2]==='contained-compose-linux';
const inputFile=compose?path.join('/var/lib/leafseamer','worker-test.json'):process.argv[2];
const input=JSON.parse(fs.readFileSync(inputFile,'utf8'));
const cleanup=[];
const fixture={after(fn){cleanup.unshift(fn);}};
async function localManagement(store,{sessions,auth},assertCurrent,pairing=null){
  const origin='https://127.0.0.1:8444',caFile=pairing?'/etc/leafseamer/pairing/ca.pem':'/etc/leafseamer/tls/certificate.pem';
  const ca=fs.readFileSync(caFile),cert=pairing?.tls.cert??ca,key=pairing?.tls.key??fs.readFileSync('/etc/leafseamer/tls/private-key.pem');
  const handler=createAuthenticationHttp({serviceId:store.identity.service_id,databaseInstanceId:store.identity.database_instance_id,
    serviceBootId:store.serviceBootId,origin,sessions,
    localPairing:pairing?.manage??((auth,operation,request)=>{assertCurrent();return manageLocalEvents(sessions,auth,operation,request);}),
    localExtension:createLocalExtensionManagement({sessions,workerLaunches:store.workerLaunches,assertCurrent})});
  const server=https.createServer({cert,key},(req,res)=>{if(!handler.handle(req,res))res.writeHead(404).end();});
  server.listen(8444,'127.0.0.1');await once(server,'listening');
  fixture.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
  return {
    request(operation,request,{csrf=auth.csrf,headers={},route=localExtensionPath}={}){
      const bytes=Buffer.from(canonicalize({operation,request}));
      return new Promise((resolve,reject)=>{
        const req=https.request(origin+route,{method:'POST',ca,agent:false,headers:{
          Origin:origin,Cookie:'leafseamer_session=v1.'+auth.credential_id+'.'+auth.secret,'X-CSRF-Token':csrf,
          'Content-Type':'application/json','Content-Length':String(bytes.length),...headers}},res=>{
          const chunks=[];
          res.on('data',chunk=>chunks.push(chunk)).on('error',reject);
          res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks))}));
        });
        req.on('error',reject);req.setTimeout(5000,()=>req.destroy());req.end(bytes);
      });
    },
    async cli(admin,operation,request){
      const result=await admin({origin,caFile,input:{...(input.paired?.login??{login:'role.test',password:'Synthetic-role-password-123'}),operation,request}});
      return JSON.parse(result.toString('utf8'));
    }
  };
}
async function waitForFile(file,assertCurrent,timeout){
  const until=performance.now()+timeout;
  while(!fs.existsSync(file)){
    assertCurrent();assert.ok(performance.now()<until,'Compose simulator did not receive '+path.basename(file));
    await delay(25);
  }
}
async function waitForEvent(store,device,sequence,value){
  const until=performance.now()+4000;
  for(;;){
    const published=store.workerLaunches.deviceEvents(device);
    const acknowledged=inspect(input.data,db=>db.prepare(
      "SELECT count(*) FROM device_module_frame WHERE direction='w2c' AND message_type='EVENT_ACKED'").pluck().get());
    if(published.events.length===sequence&&acknowledged===sequence){
      const event=published.events.at(-1);
      assert.deepEqual(event.origin.payload.value,{value,write_sequence:String(sequence)});
      assert.equal(event.origin.source_sequence,String(sequence));
      assert.equal(hash(event.origin),event.origin_digest);
      return event;
    }
    assert.ok(performance.now()<until,'没有提交实际模拟器事件');
    await delay(20);
  }
}
try{
  const clock=openNativeClock({linuxWithoutSystemSleep:compose}),channel=openLinuxCoreBootstrap(input.policy,'controller',{compose,workerControl:true,
    workerChannelDirectory:input.channelDirectory,installationRead:compose});
  fixture.after(()=>channel.close());
  const runtime=await channel.accept({identity:input.policy,source:clock});
  const {binding,supervision,policy,extensionInstallationSource}=runtime;
  let installation=null;
  if(compose){
    await waitForFile(input.start,supervision.assertCurrent,10000);
    const query={intake_id:input.intakeRef.object_id,target_authority_service_id:policy.service_id};
    assert.throws(()=>extensionInstallationSource.describeIntake({...query,target_authority_service_id:'unrelated-service'}),
      {code:'linux_installation_query'});
    assert.deepEqual(await extensionInstallationSource.describeIntake({...query,intake_id:'unrelated-intake'}),
      {status:'unavailable',content:null});
    const {status,content}=await extensionInstallationSource.describeIntake(query);
    assert.equal(status,'available');assert.deepEqual(content.intake_ref,input.intakeRef);
    installation={...extensionInstallationSource,content};
  }
  const capabilityTemplate=input.channelDirectory?JSON.parse(fs.readFileSync(new URL('../../dist/simulator-control-capability.json',import.meta.url),'utf8')):undefined;
  let targetDevice=null;
  const x=await setup(fixture,{revision:109,directory:input.data,installation,capabilityTemplate,withEnrolledIssuer:!!input.paired,
    reviewedActions:capabilityTemplate?.actions.map(action=>action.action_id),prepareBindings({f,api,request}){
    if(!input.paired?.armPreflight)return;
    targetDevice=f.store.registerDevice({request_id:'target-device',device_kind:'simulator',display_name:'模拟器动作目标'}).device_id;
    const {values}=request.bindings[0];
    values.push(api.roles.deviceReference(targetDevice));
    values.sort((left,right)=>Buffer.compare(Buffer.from(canonicalize(left)),Buffer.from(canonicalize(right))));
  },prepareHost(host){
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
  const pairing=input.paired?simulatorPairingInputs(store,runtime,clock):null;
  const a=await authenticated(fixture,x.f,{grant:!compose,...(compose&&{
    native:{source:clock,descriptor:binding.descriptor},sampleWindowPolicy:'authentication-clock-sample/2'}),
    ...(pairing&&{evidence:pairing.evidence,credentials:input.paired.login})});
  if(pairing)pairing.manage=await startSimulatorPairing(fixture,{store,sessions:a.sessions,real:a.real,profile:pairing.profile,assertCurrent:runtime.assertLive});
  const management=compose?await localManagement(store,a,supervision.assertCurrent,pairing&&{tls:pairing.profile.tls,manage:pairing.manage}):null;
  async function manage(operation,request){
    const result=await management.request(operation,request);
    assert.equal(result.status,200,JSON.stringify(result.body));
    return result.body;
  }
  let approved;
  if(compose){
    assert.equal((await management.request('approve',x.request,{csrf:crypto.randomBytes(32).toString('base64url')})).status,401);
    assert.equal((await management.request('approve',x.request,{headers:{'X-Forwarded-For':'127.0.0.1'}})).status,403);
    assert.equal((await management.request('approve',x.request)).status,403);
    const grant=a.sessions.localPermissions(a.auth);
    a.sessions.replaceLocalPermissions(a.auth,{request_id:crypto.randomUUID(),principal_id:a.logged.session.principal_id,
      expected_revision:grant.revision,permissions:[...new Set([...grant.permissions,'extension.read','extension.manage',...commandPermissions,
        ...(input.paired?.runApproval?['grant.manage','grant.read']:[]),...(targetDevice?['control.release']:[])])]});
    approved=await manage('approve',x.request);
  }
  const token=a.token();
  if(!compose)approved=await a.sessions.approveExtension(token,x.request);
  store.configureVirtualDevice({request_id:'resource',device_id:x.registered.device_id});
  if(targetDevice)store.configureVirtualDevice({request_id:'target-resource',device_id:targetDevice});
  const device=x.registered.device_id;
  const manual=compose?await prepareManualSimulator({store,operator:a,device}):null;
  if(targetDevice)await prepareAutomaticSimulator({store,operator:a,device:targetDevice});
  const planRequest={request_id:'plan',slot_id:x.installed.slot.record.slot_id,
    expected_slot_revision:x.installed.slot.slot_ref.revision,selection:{kind:compose?'enable':'activate',source_installation_ref:null,
      target_installation_ref:x.installed.installation_ref,reuse_content_ref:null,configuration_ref:x.config.configuration_ref}};
  const plan=compose?await manage('plan',planRequest):await a.sessions.planExtension(token,planRequest);
  const activationRequest={request_id:'activate',slot_id:plan.slot_ref.object_id,expected_slot_revision:plan.slot_ref.revision,
    target_installation_ref:x.installed.installation_ref,approval_ref:approved.approval_ref,dependency_plan_ref:plan.plan_ref};
  const activation=compose?await manage('enable',activationRequest):await a.sessions.activateExtension(token,activationRequest);
  let key,adopted=null,module=null,execution=null,simulatorEvent=null;
  if(compose){
    const request={activation_ref:activation.operation_ref,launch_id:input.launchId,containment_ref:input.containment};
    assert.deepEqual(await manage('lookup-plan',{request_id:planRequest.request_id}),plan);
    assert.deepEqual(await manage('lookup-activation',{request_id:activationRequest.request_id}),activation);
    assert.deepEqual(await manage('enable',activationRequest),activation);
    const wrong=await management.request('start',{...request,activation_ref:{...activation.operation_ref,digest:hash('unrelated-operation')}});
    assert.deepEqual(wrong,{status:409,body:{error:'extension_activation_operation_reference'}});
    const started=await management.cli(runLocalExtensionAdmin,'start',request);
    adopted=started.binding;
    key={launch_id:request.launch_id,launch_intent_digest:adopted.binding.admission_receipt.launch_intent_digest};
    assert.equal(adopted.binding.gate_state,'closed');
    assert.equal(started.execution.worker_boot_id,adopted.binding.admission_receipt.member_boot_id);
    assert.deepEqual(await manage('start',request),started);
    const command=await writeManualSimulator({store,operator:a,supervision,key,device,manual,value:7});
    simulatorEvent={command,device,event:await waitForEvent(store,device,1,7)};
    const scopeRequest={request_id:crypto.randomUUID(),device_ids:[device]},pairing=(operation,request)=>
      management.cli(runLocalPairingAdmin,operation,request);
    assert.equal((await management.request('register-event-scope',scopeRequest,{route:localPairingPath,csrf:crypto.randomBytes(32).toString('base64url')})).status,401);
    assert.equal((await management.request('register-event-scope',scopeRequest,{route:localPairingPath,headers:{'X-Forwarded-For':'127.0.0.1'}})).status,403);
    const scope=await pairing('register-event-scope',scopeRequest);
    assert.deepEqual(await pairing('register-event-scope',scopeRequest),scope);
    const current=store.workerLaunches.eventScopes.current(scope.scope_ref);
    assert.deepEqual(current.registration.scope,scope.scope);
    assert.deepEqual(current.current_frontiers.map(member=>member.source_key),[simulatorEvent.event.origin.source_key]);
    assert.equal(current.current_frontiers[0].registration_sequence,'1');
    if(input.paired){
      const {ready,proceed,finish}=input.paired;
      fs.writeFileSync(ready,canonicalize({device,scope,baseline:simulatorEvent.event,source_ref:current.current_frontiers[0].source_registration_ref,
        ...(targetDevice&&{target_device:targetDevice})}));
      await waitForFile(proceed,runtime.assertLive,input.paired.runApproval?45000:30000);
      simulatorEvent.incremental={command:await writeManualSimulator({store,operator:a,supervision,key,device,manual,value:23,successor:true}),
        event:await waitForEvent(store,device,2,23)};
      await waitForFile(finish,runtime.assertLive,12000);
    }
    assert.deepEqual(await pairing('revoke-event-scope',{scope_ref:scope.scope_ref}),{scope_ref:scope.scope_ref,state:'revoked'});
    assert.throws(()=>store.workerLaunches.eventScopes.current(scope.scope_ref),{code:'event_scope_inactive'});
    simulatorEvent.scope_ref=scope.scope_ref;
  }else{
    const intent={...workerIntent(store,binding,x.host.content,approved,[x.registered.device_id]),launch_id:input.launchId,containment_ref:input.containment};
    const prepared=await store.workerLaunches.prepare(Buffer.from(JSON.stringify(intent)));
    key={launch_id:intent.launch_id,launch_intent_digest:prepared.ref.digest};
    const first=await start.authorize(key);
    const {authorization_ref,...original}=first;
    const past={...original,lifetime:{...original.lifetime,issued_tick:'0',deadline_tick:'1'}};
    await assert.rejects(supervision.registerWorker(intent,{...past,authorization_ref:{...authorization_ref,digest:hash(past)}}),{code:'supervisor_expired'});
    assert.equal(await supervision.queryLaunch(key),null);
    assert.equal((await start.register(key)).state,'registered');
    assert.equal((await start.register(key)).state,'registered');
    assert.equal(store.workerLaunches.runtime.query(key),null);
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
    workerReceipt:adopted?.binding.admission_receipt??null,simulatorEvent}));
}catch(error){
  fs.writeFileSync(input.result,JSON.stringify({ok:false,error:error.stack}));process.exitCode=1;
}finally{
  for(const close of cleanup)await close();
}
