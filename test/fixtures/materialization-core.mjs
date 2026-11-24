import fs from 'node:fs';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import {once} from 'node:events';
import {monitorEventLoopDelay} from 'node:perf_hooks';
import https from 'node:https';
import canonicalize from 'canonicalize';
import {setTimeout as delay} from 'node:timers/promises';
import {connectCoreSupervisor} from '../../dist/supervisor-control.mjs';
import {openNativeClock} from '../../dist/native-clock.mjs';
import {createCoreBootstrapChannel,verifyCoreAdmission} from '../../dist/core-bootstrap.mjs';
import {openStorage} from '../../dist/storage.mjs';
import {openTimeProviderLink} from '../../dist/time-provider-link.mjs';
import {authenticated} from './extension-auth.mjs';
import {createAuthenticationHttp} from '../../dist/auth-http.mjs';
import {contractSelection} from '../../dist/sdk/index.mjs';
import {automationPeer} from './automation-peer.mjs';
import {referenceBundleAuthority} from './reference-bundle-authority.mjs';
import {loadGuiAssets} from '../../dist/gui-assets.mjs';
import {corePerformance} from './core-performance.mjs';
let business=null,intakeClient=null,manager=null,moduleClient=null,executionClient=null,intakeTail=Promise.resolve(),commandToken=null,commandRequest=null,evaluator=null,evaluatorSource=null,authorizationContext=null,authorizationEvidence=null;
// 运行刷新与启动授权共享单请求安装连接；装配层串行查询，不重发或复用旧观察。
function queryIntake(request){const result=intakeTail.then(()=>intakeClient.queryIntake(request));intakeTail=result.catch(()=>{});return result;}
const args=process.argv.slice(3),options=Object.fromEntries(Array.from({length:args.length/2},(_,i)=>[args[i*2],args[i*2+1]]));
const performanceCapture=await corePerformance(JSON.parse(fs.readFileSync(options['--fixture'],'utf8')).performance_capture);
const report=value=>{const entry={...value,reported_ms:performance.now()};performanceCapture.record(entry);process.stderr.write(JSON.stringify(entry)+'\n');if(['unavailable','core-source-lost'].includes(value.event))void performanceCapture.stop().catch(()=>{});};
let firstManualChallenge=null,initialResource=null,initialResourceRequest=null,initialOpening=null,initialOpeningRequest=null;const manualCoreObservations=new Map();
let commandServer=null,commandHttp=null,commandAgent=null,guiTimer=null,automationRegistration=null,bindingPeer=null;
let commandGui=null,configurePublicationGui=null;
async function startCommandHttp(material){
 let handler;commandServer=https.createServer(material,(req,res)=>{
  if(commandGui&&['GET','HEAD'].includes(req.method)&&commandGui.handle(req,res))return;
  if(!handler.handle(req,res)){res.writeHead(404);res.end();}
 });
 await new Promise(resolve=>commandServer.listen(0,'127.0.0.1',resolve));
 const origin='https://127.0.0.1:'+commandServer.address().port;
 commandAgent=new https.Agent({keepAlive:true,maxSockets:1,ca:material.cert,rejectUnauthorized:true});
 const sessions={...manager.sessions,async submitCommand(...args){try{return await manager.sessions.submitCommand(...args);}
  catch(error){report({event:'http-command-error',stage:'submit',code:error.code,cause:error.cause?.code});throw error;}},
  getCommand(...args){try{return manager.sessions.getCommand(...args);}catch(error){report({event:'http-command-error',stage:'read',code:error.code,message:error.message,cause:error.cause?.code});throw error;}},
  confirmCommandResult(...args){try{return manager.sessions.confirmCommandResult(...args);}
   catch(error){report({event:'http-command-error',stage:'confirm',code:error.code,cause:error.cause?.code});throw error;}}};
 handler=createAuthenticationHttp({serviceId:business.identity.service_id,databaseInstanceId:business.identity.database_instance_id,
  serviceBootId:receipt.member_boot_id,sessions,origin,onFailure:value=>report({event:'http-handler-failure',...value})});
 if(input.gui)commandGui=loadGuiAssets(input.gui.directory,business.identity,origin);
 if(input.automation_peer?.publication_gui)configurePublicationGui=directory=>{commandGui=loadGuiAssets(directory,business.identity,origin);};
 if(input.gui||configurePublicationGui){
  const spki=crypto.createHash('sha256').update(new crypto.X509Certificate(material.cert).publicKey.export({type:'spki',format:'der'})).digest('base64');
  report({event:'gui-endpoint',origin,spki});
 }
 commandHttp=(method,route,value,token=commandToken)=>new Promise((resolve,reject)=>{
  const body=value===undefined?null:Buffer.from(JSON.stringify(value));
  const request=https.request(origin+route,{method,ca:material.cert,rejectUnauthorized:true,agent:commandAgent,headers:{Origin:origin,
   ...(token?{Authorization:'Bearer v1.'+token.token_id+'.'+token.secret}:{}),
   'X-LeafSeamer-Contract':contractSelection.contract_id,'X-LeafSeamer-Contract-Digest':contractSelection.contract_digest,
   ...(body?{'Content-Type':'application/json','Content-Length':body.length}:{})}},response=>{
    const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.on('error',reject);
    response.on('end',()=>{try{resolve({status:response.statusCode,body:JSON.parse(Buffer.concat(chunks))});}catch(error){reject(error);}});
   });request.on('error',reject);request.end(body);
 });
}
async function manualSourceFor(proof,device,refresh=true){
 if(refresh){
  await business.workerLaunches.runtime.refreshCurrent(key);
  await source.refreshCoreObservation();
 }
 // 每次独立挑战使用新采集的实际认证时钟；不改变既有来源或已受理命令期限。
 if(input.mode.includes('_guard_dispatch'))manager.real.refresh();
 const checks=input.mode.endsWith('_manual_challenge_checks'),requestId=crypto.randomUUID(),observation=source.observeCore(),challenge=manager.sessions.beginManualExecutionChallenge(proof,device,requestId);
 if(checks&&canonicalize(manager.sessions.beginManualExecutionChallenge(proof,device,requestId))!==canonicalize(challenge))throw new Error('manual_challenge_replay');
 if(checks)await delay(10);
 const response={request_id:crypto.randomUUID(),challenge_ref:{id:challenge.id,revision:challenge.revision,digest:challenge.digest},nonce:challenge.nonce};
 if(checks&&!firstManualChallenge){
  try{manager.sessions.completeManualExecutionChallenge(proof,{...response,nonce:'A'.repeat(43)});report({event:'manual-challenge-wrong-nonce',code:'unexpected_success'});}catch(error){report({event:'manual-challenge-wrong-nonce',code:error.code});}
  try{manager.sessions.selectManualExecutionSource(proof,device);report({event:'manual-challenge-bypass',code:'unexpected_success'});}catch(error){report({event:'manual-challenge-bypass',code:error.code});}
 }
 if(checks)await delay(10);
 const value=manager.sessions.completeManualExecutionChallenge(proof,response);
 if(checks)await delay(10);
 if(checks&&canonicalize(value)!==canonicalize(manager.sessions.completeManualExecutionChallenge(proof,response)))throw new Error('manual_challenge_source_replay');
 if(checks)await delay(10);
 manualCoreObservations.set(value.ref.id,observation);
 report({event:'manual-challenge',challenge,source_ref:value.ref});
 if(!firstManualChallenge){
  firstManualChallenge={input:proof,response};
  if(checks)try{manager.sessions.completeManualExecutionChallenge(proof,{...response,request_id:crypto.randomUUID()});report({event:'manual-challenge-conflict',code:'unexpected_success'});}catch(error){report({event:'manual-challenge-conflict',code:error.code});}
 }
 return value;
}
async function checkCommand(stage,changes={}){
 try{await manager.sessions.submitCommand(commandToken,{...commandRequest,...changes,idempotency_key:crypto.randomUUID()});report({event:'command-source',stage,code:'unexpected_success'});}
 catch(error){report({event:'command-source',stage,code:error.code,message:error.message});}
}
async function releaseAfterCommands(device){
 const token=manager.token(['control.read','control.release','request.create']),{contractSelection:selection}=await import('../../dist/sdk/index.mjs');
 manager.real.refresh();const context=manager.sessions.createRequestContext(token,{audience:business.identity.service_id,operations:['releaseControl'],selection,ttl_ms:60000,max_unique_requests:8});
 const before=manager.sessions.getControl(token,device),request={context_id:context.context_id,idempotency_key:crypto.randomUUID(),expected_control:{epoch:before.control_epoch,version:before.effective_version},reason:'完成命令后的控制释放'};
 let accepted;try{accepted=await manager.sessions.changeControl(token,'releaseControl',{device_id:device},request);}catch(error){
  if(!input.mode.endsWith('_control_queued_cut_omit'))throw error;
  const after=manager.sessions.getControl(token,device);report({event:'command-control-rollback',code:error.code,before,after});
  if(error.code!=='control_command_cut_storage'||canonicalize(before)!==canonicalize(after))throw error;
  return;
 }
 if(input.mode.endsWith('_control_queued_cut_omit'))throw new Error('control_cut_omission_accepted');let operation;
 const until=performance.now()+8000;
 do{operation=manager.sessions.getControlOperation(token,accepted.receipt.initial_result_ref.id);if(operation.state!=='pending')break;if(performance.now()>=until)throw new Error('command_control_wait');await delay(20);}while(true);
 const replay=await manager.sessions.changeControl(token,'releaseControl',{device_id:device},request);
 report({event:'command-control-released',before,accepted,operation,replay,control:manager.sessions.getControl(token,device)});
 if(operation.state!=='effective')throw Object.assign(new Error('command_control_not_effective'),{code:'command_control_not_effective'});
}
async function openSuccessorGate(device,{checkObsSample=false}={}){
 const missing=await commandHttp('GET','/api/v1/commands/00000000-0000-4000-8000-000000000001');if(missing.status!==404)throw new Error('successor_http_connection');
 let baseline=checkObsSample?null:await moduleClient.captureBaseline(device);manager.real.refresh();
 const manual=await manualSourceFor(commandToken,device),challenge=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
 const evaluated=manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:challenge.id,revision:'1',digest:challenge.digest},nonce:challenge.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret});
 const context=manager.sessions.currentManualAuthorizationContext({device_id:device,manual_source_ref:manual.ref,evaluator_source_ref:evaluated.ref});
 const recovery=manager.sessions.requestDeviceAuthorizationRecovery(commandToken,{request_id:crypto.randomUUID(),device_id:device,
  manual_source_ref:manual.ref,evaluator_source_ref:evaluated.ref,expected_state_ref:context.state_ref,expected_context_digest:context.context_digest});
 const selected=manager.sessions.consumeDeviceAuthorizationRecovery(commandToken,recovery.receipt.id);
 const firstEvidence=manager.sessions.selectDeviceAuthorizationEvidence({request_id:crypto.randomUUID(),device_id:device,manual_source_ref:manual.ref,evaluator_source_ref:evaluated.ref,
  expected_state_ref:selected.ref,expected_evidence_ref:null});
 await business.workerLaunches.runtime.refreshCurrent(key);await source.refreshCoreObservation();
 manager.real.refresh();const pendingManual=manualSourceFor(commandToken,device,false),next=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
 const nextEvaluator=manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:next.id,revision:'1',digest:next.digest},nonce:next.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret}),nextManual=await pendingManual;
 const evidence=manager.sessions.selectDeviceAuthorizationEvidence({request_id:crypto.randomUUID(),device_id:device,manual_source_ref:nextManual.ref,evaluator_source_ref:nextEvaluator.ref,
  expected_state_ref:selected.ref,expected_evidence_ref:firstEvidence.ref});
 report({event:'successor-stage',stage:'authorization-selected',remaining_ms:Number((BigInt(evidence.value.requirement.expires_tick_ns)-clock.tick())/1000000n)});
 const select=()=>manager.sessions.selectInitialDeviceResources({request_id:crypto.randomUUID(),device_id:device,expected_evidence_ref:evidence.ref});
 if(checkObsSample){
  try{select();throw new Error('obs_cut_stale_sample_accepted');}
  catch(error){if(error.code!=='initial_resource_observed_write')throw error;report({event:'obs-cut-stale-reopen',code:error.code});}
  baseline=await moduleClient.captureBaseline(device);
 }
 const resource=select();
 const opening=manager.sessions.prepareInitialDeviceOpen({request_id:crypto.randomUUID(),device_id:device,expected_resource_ref:resource.ref});
 report({event:'successor-resource',baseline,resource,opening,remaining_ms:Number((BigInt(opening.value.plan.expires_tick_ns)-clock.tick())/1000000n)});
 const opened=await executionClient.initialOpen(opening.ref,{ready:true});report({event:'successor-stage',stage:'opened',remaining_ms:Number((BigInt(opening.value.plan.expires_tick_ns)-clock.tick())/1000000n)});
 return {baseline,resource,opening,opened};
}
async function runSuccessor(device,parameters={value:23},contextId=commandRequest.context_id){
 const {opening,opened}=await openSuccessorGate(device);
 const request={...commandRequest,parameters,context_id:contextId,idempotency_key:crypto.randomUUID(),dispatch:{mode:'immediate',max_queue_ms:10000}};
 const accepted=await commandHttp('POST','/api/v1/commands',request);
 if(accepted.status!==202)throw Object.assign(new Error('successor_http_admission'),{code:'successor_http_admission',cause:accepted.body});
 report({event:'successor-stage',stage:'accepted',remaining_ms:Number((BigInt(opening.value.plan.expires_tick_ns)-clock.tick())/1000000n)});
  for(const [stage,method]of [['encoded','whenCommandEncoded'],['finalized','whenCommandFinalized'],['guarded','whenCommandGuarded'],['dispatched','whenCommandDispatched']]){
   business.workerLaunches[method](accepted.body.command_ref.object_id).then(result=>{
    const disposition=stage==='guarded'?result?.ack?.value?.disposition:undefined;
    report({event:'successor-stage',stage,disposition,remaining_ms:Number((BigInt(opening.value.plan.expires_tick_ns)-clock.tick())/1000000n)});
   },()=>{});
  }
 const id=accepted.body.command_ref.object_id,cleaned=await business.workerLaunches.whenCommandCleaned(id),closed=await business.workerLaunches.whenCommandSettled(id);
 const current=await commandHttp('GET','/api/v1/commands/'+id),replayed=await commandHttp('POST','/api/v1/commands',request);
 report({event:'successor-command',opened,accepted,current,replayed,closed,cleaned,state:executionClient.state});
}
async function completeObsCut(request,ordinal,browserAdmission=null){
 const route='/api/v1/commands',admitted=browserAdmission??await commandHttp('POST',route,request);
 report({event:'obs-cut-command-admission',admitted,ordinal});
 if(admitted.status!==202)throw new Error('obs_cut_command_http');
 const id=admitted.body.command_ref.object_id;
 for(const [stage,method] of [['encoding','whenCommandEncoded'],['final-admission','whenCommandFinalized'],['guard','whenCommandGuarded'],['dispatch','whenCommandDispatched'],['settlement','whenCommandSettled'],['cleanup','whenCommandCleaned']]){
  try{await business.workerLaunches[method](id);}catch(error){report({event:'obs-cut-command-failed',ordinal,stage,code:error.code,cause:error.cause?.code});throw error;}
 }
 manager.real.refresh();
 const finished=await commandHttp('GET',route+'/'+id),evidence=await commandHttp('GET',route+'/'+id+'/evidence?state_revision=5&limit=5'),
  replayed=await commandHttp('POST',route,request),control=manager.sessions.getControl(commandToken,request.device_id);
 report({event:'obs-cut-command-result',ordinal,finished,evidence,replayed,control});
}
async function observeInterruptedObsCut(request){
 const route='/api/v1/commands',admitted=await commandHttp('POST',route,request);
 if(admitted.status!==202)throw new Error('obs_cut_interruption_admission');
 const id=admitted.body.command_ref.object_id,until=performance.now()+10000;
 const wait=input.obs_interruption==='report'?'whenCommandDispatched':'whenCommandSettled';
 try{await business.workerLaunches[wait](id);}
 catch(error){report({event:'obs-cut-interruption-error',code:error.code});}
 let finished;
 do{
  manager.real.refresh();
  finished=await commandHttp('GET',route+'/'+id);
  if(finished.body?.record?.state?.phase==='finished')break;
  if(performance.now()>=until){
   report({event:'obs-cut-interruption-timeout',finished,execution:executionClient.state});
   throw new Error('obs_cut_interruption_timeout');
  }
  await delay(30);
 }while(true);
 const replayed=await commandHttp('POST',route,request),control=manager.sessions.getControl(commandToken,request.device_id);
 const blocked=await commandHttp('POST',route,{...request,idempotency_key:crypto.randomUUID()});
 report({event:'obs-cut-interrupted',admitted,finished,replayed,blocked,control});
}
async function obsBrowserMarker(file){
 const until=performance.now()+15000;
 while(!fs.existsSync(file)){
  if(performance.now()>=until)throw Object.assign(new Error('fixture_obs_browser_timeout'),{code:'fixture_obs_browser_timeout'});
  await delay(20);
 }
 return fs.readFileSync(file,'utf8');
}
async function openOrdinaryGate(device,automatic,token=commandToken){
 await executionClient.initialFence(device);
 const evaluate=()=>{
  const challenge=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
  return manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:challenge.id,revision:challenge.revision,digest:challenge.digest},
   nonce:challenge.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret});
 };
 const manual=automatic?null:await manualSourceFor(commandToken,device,false);
 const evaluated=evaluate(),inputs={device_id:device,manual_source_ref:manual?.ref??null,evaluator_source_ref:evaluated.ref};
 const context=automatic?manager.sessions.currentAutomaticAuthorizationContext(inputs):manager.sessions.currentManualAuthorizationContext(inputs);
 const recovery=manager.sessions.requestDeviceAuthorizationRecovery(token,{...inputs,request_id:crypto.randomUUID(),
  expected_state_ref:context.state_ref,expected_context_digest:context.context_digest});
 const selected=manager.sessions.consumeDeviceAuthorizationRecovery(token,recovery.receipt.id);
 const evidence=manager.sessions.selectDeviceAuthorizationEvidence({...inputs,request_id:crypto.randomUUID(),expected_state_ref:selected.ref,expected_evidence_ref:null});
 await business.workerLaunches.runtime.refreshCurrent(key);
 await source.refreshCoreObservation();
 manager.real.refresh();
 const freshManual=automatic?null:await manualSourceFor(commandToken,device,false);
 const renewed=manager.sessions.selectDeviceAuthorizationEvidence({...inputs,manual_source_ref:freshManual?.ref??null,evaluator_source_ref:evaluate().ref,
  request_id:crypto.randomUUID(),expected_state_ref:selected.ref,expected_evidence_ref:evidence.ref});
 const resources=manager.sessions.selectInitialDeviceResources({request_id:crypto.randomUUID(),device_id:device,expected_evidence_ref:renewed.ref});
 const opening=manager.sessions.prepareInitialDeviceOpen({request_id:crypto.randomUUID(),device_id:device,expected_resource_ref:resources.ref});
 const opened=await executionClient.initialOpen(opening.ref,{ready:true});
 const control=manager.sessions.getControl(token,device);
 const current=executionClient.currentReady(opened.ready.ref);
 return {control,selected,recovery,renewed,resources,opening,ready:opened.ready,current};
}
async function runOrdinaryGate(device,automatic){
 const {control,selected,recovery,renewed,opening,ready,current}=await openOrdinaryGate(device,automatic);
 if(!automatic){
  report({event:'manual-gate-before-migration',control,selected,recovery,ready,current});
  executionClient.close();
  return;
 }
 report({event:'automatic-ready',control,selected,renewed,opening,ready,current});
 try{
  await manager.sessions.submitCommand(commandToken,{...commandRequest,idempotency_key:crypto.randomUUID(),
   expected_control:{epoch:control.control_epoch,version:control.effective_version}},{withStatus:true});
  throw Error('manual_command_on_automatic_device');
 }catch(error){if(error.code!=='command_control_owner')throw error;report({event:'automatic-manual-rejected',code:error.code});}
 manager.sessions.revokeDeviceEvaluatorPolicy(manager.auth,{request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref});
 const until=performance.now()+5000;
 let protectedControl;
 do{
  protectedControl=manager.sessions.getControl(commandToken,device);
  if(protectedControl.gate_state==='protected')break;
  if(performance.now()>=until)throw Error('automatic_gate_protection_timeout');
  await delay(20);
 }while(true);
 let rejection;
 try{executionClient.currentReady(ready.ref);}catch(error){rejection=error.code;}
 if(!rejection)throw Error('revoked_evaluator_kept_ready');
 report({event:'automatic-protected',control:protectedControl,rejection,state:executionClient.state});
}
async function openAutomationTarget(device){
 manager.real.refresh();const token=manager.token(['control.read','device.recover','device.command']);
 const value=await openOrdinaryGate(device,true,token);
 const result={ready_ref:value.ready.ref,control:value.control};
 report({event:'automation-target-ready',...result,
  remaining_ms:Number((BigInt(value.opening.value.plan.expires_tick_ns)-clock.tick())/1000000n)});return result;
}
async function verifyCapturedEvents(device){
const qualified=moduleClient.qualifiedEventCapture(device);
const firstEvent=await moduleClient.readEvents(device,1),repeated=await moduleClient.readEvents(device,1),r=firstEvent.body.result;
const firstPublished=moduleClient.publishedEvents(device);
let wrong;try{await moduleClient.acknowledgeEvents(device,{through_sequence:r.batch.through_sequence,batch_digest:'sha256:'+'0'.repeat(64)});wrong='unexpected_success';}catch(error){wrong=error.code;}
const receipt={through_sequence:r.batch.through_sequence,batch_digest:r.batch_digest};await moduleClient.acknowledgeEvents(device,receipt);await moduleClient.acknowledgeEvents(device,receipt);
let secondEvent;
async function publishSecond(){
 if(!secondEvent){
  secondEvent=await moduleClient.readEvents(device);const {batch,batch_digest}=secondEvent.body.result;
  await moduleClient.acknowledgeEvents(device,{through_sequence:batch.through_sequence,batch_digest});
 }
 return moduleClient.publishedEvents(device);
}
const incremental=input.automation_peer?.incremental_source_event===true;
async function publishArmedEvent(){
 if(!secondEvent)throw Error('automation_trigger_baseline_missing');
 report({event:'successor-stage',stage:'trigger-source-start'});
 manager.real.refresh();
 commandToken=manager.token(['control.read','device.recover','device.command','command.read','request.create']);
 const context=manager.sessions.createRequestContext(commandToken,{audience:business.identity.service_id,operations:['submitCommand'],
  selection:contractSelection,ttl_ms:30000,max_unique_requests:1});
  try{await runSuccessor(device,{value:31},context.context_id);}
  catch(error){await performanceCapture.stop().catch(()=>{});throw error;}
 // 目标开闸由同一RunGrant的首动作资格查验触发，避免在事件交付前消耗其独立窗口。
 const frame=await moduleClient.readEvents(device);
 const {batch,batch_digest}=frame.body.result;
 if(batch.events.length!==1||batch.events[0].payload.value!==31)throw Error('automation_trigger_capture');
 await moduleClient.acknowledgeEvents(device,{through_sequence:batch.through_sequence,batch_digest});
 const sourceEvent=moduleClient.publishedEvents(device,'2').events[0];
 if(!sourceEvent?.origin.source_time_ref)throw Error('automation_trigger_source_time');
 return {sourceEvent};
}
if(!incremental)await publishSecond();
if(input.automation_peer){
 bindingPeer=await automationPeer({business,manager,config:input.automation_peer,device,
  refresh:()=>input.automation_peer.verify_armed_target_dispatch?source.assertCurrent():business.workerLaunches.runtime.refreshCurrent(key),report,
  readReferenceBundle:referencePublication?.readBundle,
  publishBufferedEvent:incremental?publishSecond:null,configurePublicationGui,
  openArmTarget:input.automation_peer.arm_target?()=>openAutomationTarget(input.automation_peer.arm_target):null,
  readExecutionState:()=>executionClient.state,
  publishArmedEvent:input.automation_peer.verify_armed_target_dispatch?publishArmedEvent:null});
 report({event:'event-source-published',published:moduleClient.publishedEvents(device)});
 scheduling?.reset();
 await bindingPeer.phase('events');
 if(input.automation_peer.verify_armed_target_ready){await bindingPeer.close();bindingPeer=null;return;}
}
await publishSecond();
const empty=await moduleClient.readEvents(device);await moduleClient.acknowledgeEvents(device,{through_sequence:empty.body.result.batch.through_sequence,batch_digest:empty.body.result.batch_digest});
const published=moduleClient.publishedEvents(device),suffix=moduleClient.publishedEvents(device,'1');
const stopped=await moduleClient.stopEvents(device);let afterStop;try{moduleClient.qualifiedEventCapture(device);afterStop='unexpected_success';}catch(error){afterStop=error.code;}
if(bindingPeer)await bindingPeer.phase('events-stopped');
report({event:'module-events-captured',first:firstEvent,repeated,second:secondEvent,empty,stopped,wrong,qualified,afterStop,firstPublished,published,suffix});
 await moduleClient.stopReadOnly(device);await moduleClient.connectReadOnly(device);await moduleClient.captureBaseline(device);
const started=await moduleClient.startEvents(device),newEmpty=await moduleClient.readEvents(device),newPublished=moduleClient.publishedEvents(device),newStopped=await moduleClient.stopEvents(device);
report({event:'module-events-new-session',started,empty:newEmpty,stopped:newStopped,published:newPublished});
}
const boot=createCoreBootstrapChannel(process.stdin,process.stdout,{timeoutMs:10000});
const assignment=await boot.assignment(),receipt=await boot.proveAndReceive(assignment);boot.release();
const policy=JSON.parse(options['--bootstrap-policy']),input=JSON.parse(fs.readFileSync(options['--fixture']));
const scheduling=input.automation_peer?.verify_armed_target_dispatch?monitorEventLoopDelay({resolution:20}):null;
scheduling?.enable();
const omitRetirementRequest=input.mode.endsWith('_reference_restart_missing');
const automaticReady=input.mode.endsWith('_ready_automatic');
const manualGateMigration=input.mode.endsWith('_ready_manual_migration');
const obsCommand=input.mode==='supervisor_create_module_obs_cut_command';
const obsOpen=input.mode==='supervisor_create_module_obs_cut_open'||obsCommand;
const controlFlow=obsOpen||input.mode==='supervisor_create_module_writable'||input.mode.includes('_control_fence_')||(input.mode.includes('_manual_authority_')||input.mode.includes('_manual_challenge_')||input.mode.includes('_evidence_'))||(input.mode.includes('_evaluator_')||(input.mode.includes('_recovery_')||input.mode.includes('_consumption_')||input.mode.includes('_evidence_')));
const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],policy,
 timeProviderIntent:options['--time-provider-intent']??null,binding:{descriptor:assignment.clock_domain_descriptor,receipt}});
source.subscribeLost(error=>report({event:'core-source-lost',code:error.code,stack:error.stack,...error.timing,
 ...(scheduling&&{event_loop_delay:{samples:scheduling.count,max_ms:scheduling.max/1e6,p99_ms:scheduling.percentile(99)/1e6}})}));
async function waitPastSource(deadline){while(clock.tick()<=BigInt(deadline))await delay(Math.max(1,Number((BigInt(deadline)-clock.tick())/1000000n)+25));}
const clock=openNativeClock(),hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
let referenceLink=null,referencePublication=null,referenceWithdrawn=false;
async function collectCommandReference(binding){
 const udp=dgram.createSocket('udp4');
 try{
  udp.bind(0,'127.0.0.1');await once(udp,'listening');
  const network={authentication:'trusted_network',endpoint:'127.0.0.1:'+udp.address().port};
  const fixed=(id,digest=hash(id))=>({id,digest,revision:'1'}),slot='source.command-time';
  const valid=String(clock.tick()+90000000000n),boundary=((1n<<32n)-2208988800n)*1000000000n;
  const key=crypto.createSecretKey(crypto.randomBytes(32));
  const readAuthentication=()=>manager.real.referenceTimeSample();
  const assertCurrent=()=>source.assertCurrent();
  referenceLink=await openTimeProviderLink(binding,{assertCurrent,readAuthentication});
  udp.on('message',(request,peer)=>{
   const reply=Buffer.alloc(48);reply[0]=36;reply[1]=1;reply[19]=1;
   request.copy(reply,24,40,48);reply.writeUInt32BE(0xffffffff,32);reply.writeUInt32BE(0xffffffff,36);reply[47]=1;
   udp.send(reply,peer.port,peer.address);
  });
  const configuration_ref=fixed('configuration.command-time');
  const bundleAuthority=input.source_reference_capture?referenceBundleAuthority({serviceId:policy.service_id,configuration:configuration_ref,
   timeBounds:{lower_ns:String(boundary-1000000000n),upper_ns:String(boundary+1000000000n)},maxAnchorAge:'90000000000',
   maxExchangeAge:'90000000000',maxUpstreamAge:'91000000000'}):null;
  const reserved_bytes=bundleAuthority?16384:8192;
  const facts={source_slot:slot,source_digest:bundleAuthority?.sourceDoc.source_digest??hash(slot),approval_ref:bundleAuthority?.references.approval_ref??fixed('approval.command-time'),configuration_ref,
   endpoint_ref:fixed('endpoint.loopback',hash(network)),minimum_poll_interval_ns:'16000000000',poll_lease_ns:'2000000000',reserved_bytes};
  const polls=business.openTimeProviderPolls({limits:{max_outstanding:1,max_reserved_bytes:reserved_bytes},readSource:()=>({...facts,valid_before_tick_ns:valid}),
   readAuthentication,assertCurrent,observeRetirement:source.observeTimeProviderRetirement,assertRetirement:source.assertTimeProviderRetirement});
  const publication=business.openReferenceTimeAnchor({sourceSlot:slot,readContext:polls.referenceContext,
   readApproval:()=>referenceWithdrawn?null:{format:'leafseamer-reference-approval/1',authentication:'trusted_network',source_digest:facts.source_digest,
    approval_ref:facts.approval_ref,configuration_ref:facts.configuration_ref,profile_ref:bundleAuthority?.references.profile_ref??fixed('profile.command-time'),
    policy_ref:bundleAuthority?.references.policy_ref??fixed('policy.command-time'),
    time_scale:'UTC',leap_mode:'normal_only',smear:false,elapsed_error_ppm:0,span_quantization_ns:'1000',max_span_ns:'2000000000',
    max_anchor_age_ns:'90000000000',max_exchange_age_ns:'90000000000',max_upstream_age_ns:'91000000000',max_half_width_ns:'1000000000',valid_before_tick_ns:valid},
   readEvidence:request=>({format:'leafseamer-reference-evidence/1',exchange_digest:request.exchange_digest,
    ...(bundleAuthority?bundleAuthority.proofs(request):{authentication_ref:fixed('authentication.command-time'),error_ref:fixed('error.command-time'),era_ref:fixed('era.command-time')}),
    independent_utc_lower_ns:String(boundary-1000000000n),independent_utc_upper_ns:String(boundary+1000000000n),t2_error_ns:'1000',t3_error_ns:'1000',
    upstream_age_at_m1_ns:'1000',valid_before_tick_ns:valid}),...(bundleAuthority&&{readBundleOriginals:bundleAuthority.readBundleOriginals})});
  referencePublication=publication;
  const archive=business.openTimeProviderCapture({currentKey:scope=>({...scope,key,id:'fixture.command-time',writable:true}),
   readKey:scope=>({...scope,key,id:'fixture.command-time'})},publication);
  const original=polls.reserve(slot,'poll.command-time'),pollRef={id:original.reservation.poll_id,digest:original.digest};
  const before=readAuthentication();
  await referenceLink.collect(()=>{
   const reservation=original.reservation,attempt=polls.markAttempt(pollRef),authorize=()=>polls.authorizeAttempt(attempt);
   return {reservation,attempt,authorize,network,archive:candidate=>archive.store({reservation,attempt,authorize,candidate,network}),
    release:(receipt,acknowledgement)=>archive.release({reservation,receipt,acknowledgement,assertCurrent})};
  });
  if(bundleAuthority){
   const current=readAuthentication(),{tick_ns,runtime_domain_ref}=current,provider=publication.receiverReference;
   const reference=provider.readFirst({tick_ns,runtime_domain_ref});
   if(!reference)throw new Error('fixture_receiver_reference_missing');
   const check={first_tick_ns:tick_ns,tick_ns,reference},altered=structuredClone(reference);
   altered.state.status='unqualified';
   report({event:'receiver-reference-native-receipt',boot:reference.service_boot_id,bundle_digest:reference.bundle.bundle_digest,
    current:provider.isCurrent(check),before_publication:provider.readFirst({tick_ns:before.tick_ns,runtime_domain_ref})===null,
    wrong_domain:provider.readFirst({tick_ns,runtime_domain_ref:{...runtime_domain_ref,descriptor_digest:hash('other domain')}})===null,
    wrong_boot:!provider.isCurrent({...check,reference:{...reference,service_boot_id:crypto.randomUUID()}}),
    altered:!provider.isCurrent({...check,reference:altered}),expired:!provider.isCurrent({...check,tick_ns:reference.valid_before_tick_ns})});
  }
  report({event:'command-reference-anchor',current:publication.current()});
 }finally{udp.close();}
}
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
 business=openStorage(options['--data-dir']);
 const needsReference=input.reference_acceptance||input.source_reference_capture;
 const timeBinding=business.bindCoreRuntime(await verifyCoreAdmission(assignment,receipt,policy),policy,needsReference?source:null);
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
 const workerSource=omitRetirementRequest?{...source,async retireWorker(){throw new Error('fixture_retirement_request_lost');}}:source;
 business.workerLaunches.runtime.bindSource(workerSource);business.extensionInstallations.bindRuntimeSource(source);business.workerLaunches.authorization.bindSource(workerSource);
 manager=await authenticated({after(){}},{store:business},{native:{source:clock,descriptor:assignment.clock_domain_descriptor},sampleWindowPolicy:'authentication-clock-sample/2'});
 if(needsReference)await collectCommandReference(timeBinding);
 if(input.command_tls)await startCommandHttp(input.command_tls);
 if(input.mode.endsWith('_capabilities')||input.mode.startsWith('supervisor_create_module_obs')){
  const before=manager.sessions.localPermissions(manager.auth);
  manager.sessions.replaceLocalPermissions(manager.auth,{request_id:crypto.randomUUID(),principal_id:manager.logged.session.principal_id,expected_revision:before.revision,permissions:[...new Set([...before.permissions,'device.read'])]});
  commandToken=manager.token(['device.read']);
 }
 if(obsOpen||input.mode==='supervisor_create_module_writable'||(input.mode.includes('_evaluator_')||(input.mode.includes('_recovery_')||input.mode.includes('_consumption_')||input.mode.includes('_evidence_')))){
  const objectRef=value=>({id:value.id,revision:value.revision,digest:value.digest}),now=manager.real.current();
  const principal=manager.sessions.createServicePrincipal(manager.auth,{request_id:crypto.randomUUID(),display_name:'模拟器评估器身份',purpose:'controller_evaluator'});
  const approved=manager.sessions.approveServicePrincipal(manager.auth,{request_id:crypto.randomUUID(),principal_id:principal.id,expected_revision:principal.revision,
   audiences:[business.identity.service_id],permissions:['identity.read'],device_ids:intent.object_scope.device_ids,
   not_before_ns:now.lower_ns,expires_ns:String(BigInt(now.upper_ns)+3600000000000n)});
  const staged=manager.sessions.createServiceCredential(manager.auth,{request_id:crypto.randomUUID(),principal_id:principal.id,expected_revision:approved.principal.revision,
   approval_ref:objectRef(approved.approval),expires_ns:String(BigInt(now.upper_ns)+1800000000000n)});
  const proof=manager.sessions.proveServiceCredential({credential_id:staged.credential.id,secret:staged.secret,proof_request_id:crypto.randomUUID()});
  const proven=manager.sessions.getServiceCredential(manager.auth,staged.credential.id);
  const active=manager.sessions.activateServiceCredential(manager.auth,{request_id:crypto.randomUUID(),credential_id:proven.id,expected_revision:proven.revision,
   approval_ref:objectRef(approved.approval),proof_ref:objectRef(proof)});
  report({event:'service-identity-active',principal:approved.principal,credential:active,proof_ref:objectRef(proof)});
  const receiverPolicy=manager.sessions.approveLocalServicePolicy(manager.auth,{request_id:crypto.randomUUID(),principal_id:principal.id,
   subject_ref:objectRef(approved.principal),approval_ref:objectRef(approved.approval),audience:business.identity.service_id,
   permissions:['identity.read'],device_ids:intent.object_scope.device_ids,not_before_ns:now.lower_ns,expires_ns:approved.approval.expires_ns});
  const serviceToken=manager.sessions.issueServiceToken({credential_id:active.id,secret:staged.secret,request_id:crypto.randomUUID(),
   audience:business.identity.service_id,permissions:['identity.read'],device_ids:intent.object_scope.device_ids});
  const serviceTokenInput={token_id:serviceToken.binding.id,secret:serviceToken.secret};
  const serviceIdentity=manager.sessions.readServiceIdentity(serviceTokenInput),serviceAuthorization=manager.sessions.verifyServiceToken(serviceTokenInput);
  report({event:'service-token-verified',policy:receiverPolicy,binding:serviceToken.binding,principal:serviceIdentity,authorization:serviceAuthorization});
  const evaluatorPolicy=manager.sessions.approveDeviceEvaluatorPolicy(manager.auth,{request_id:crypto.randomUUID(),principal_id:principal.id,
   subject_ref:objectRef(approved.principal),approval_ref:objectRef(approved.approval),device_ids:intent.object_scope.device_ids,expires_ns:approved.approval.expires_ns});
  evaluator={policy_ref:objectRef(evaluatorPolicy),credential_id:active.id,secret:staged.secret,credential:active,principal:approved.principal,token:serviceTokenInput};
  report({event:'evaluator-policy',policy:evaluatorPolicy});
 }
 if(controlFlow){
  const armTarget=input.automation_peer?.arm_target;
  const permissions=['control.read','control.acquire','device.command','device.recover','command.read','command.evidence.read','command.cancel','request.create',...(automaticReady||armTarget||input.mode.endsWith('_successor_control')||input.mode.includes('_control_queued')||input.mode.endsWith('_control_unresolved')?['control.release']:[])];
  if(obsOpen)permissions.push('device.read');
  const before=manager.sessions.localPermissions(manager.auth);manager.sessions.replaceLocalPermissions(manager.auth,{request_id:crypto.randomUUID(),principal_id:manager.logged.session.principal_id,expected_revision:before.revision,permissions:[...new Set([...before.permissions,...permissions,...(input.gui?['device.read']:[])])]});
  commandToken=manager.token(permissions);const device=intent.object_scope.device_ids[0],{contractSelection:selection}=await import('../../dist/sdk/index.mjs');
  const context=manager.sessions.createRequestContext(commandToken,{audience:business.identity.service_id,
   operations:automaticReady||armTarget?['acquireControl','releaseControl','submitCommand']:['acquireControl','submitCommand'],selection,ttl_ms:60000,max_unique_requests:8});
  async function change(selected,method,key){
   const original=manager.sessions.getControl(commandToken,selected);
   const accepted=await manager.sessions.changeControl(commandToken,method,{device_id:selected},{context_id:context.context_id,idempotency_key:key,
    expected_control:{epoch:original.control_epoch,version:original.effective_version},reason:'模拟器人员控制'});
   const until=performance.now()+5000;let operation;
   do{operation=manager.sessions.getControlOperation(commandToken,accepted.receipt.initial_result_ref.id);if(operation.state!=='pending')break;if(performance.now()>=until)throw new Error('command_control_wait');await delay(20);}while(true);
   if(operation.state!=='effective')throw new Error('command_control_not_effective');return operation;
  }
  const operation=await change(device,'acquireControl','manual.command.owner');
  const control=manager.sessions.getControl(commandToken,device);report({event:'command-control',control,operation});
  if(automaticReady){
   const released=await change(device,'releaseControl','automation.target.release');
   report({event:'automatic-released',released,control:manager.sessions.getControl(commandToken,device)});
  }
  if(armTarget){
   await change(armTarget,'acquireControl','automation.target.acquire');
   const released=await change(armTarget,'releaseControl','automation.target.release');
   report({event:'automation-target-control',result:released,control:manager.sessions.getControl(commandToken,armTarget)});
  }
  commandRequest={device_id:device,action_id:'leafseamer.simulator.value.set',capability_version:'1.0.0',parameters:{value:7},context_id:context.context_id,
   expected_control:{epoch:control.control_epoch,version:control.effective_version},origin:'manual',automation_binding:null,required_completion:'sent',preconditions:[],dispatch:{mode:'immediate',max_queue_ms:1000},evidence_timeout_ms:1000};
 }
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
 // 服务端在启动准备完成后显式交接物化通道，不消耗连接握手窗口。
 const coordinatorDeadline=performance.now()+10000;
 while(!fs.existsSync(options['--fixture']+'.coordinator-ready')){if(performance.now()>=coordinatorDeadline)throw new Error('fixture_coordinator_ready_timeout');await delay(20);}
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
    moduleWork: if(input.mode.startsWith('supervisor_create_module')){
      const eventCaptureMode=input.mode.endsWith('_capture_events');
      moduleClient=await business.workerLaunches.openModule(key,{events:eventCaptureMode});const device=intent.object_scope.device_ids[0];
      if(input.mode==='supervisor_create_module'||input.mode.includes('_binding_')){
        const execution=business.workerLaunches.openExecutionJournal(key);
        report({event:'execution-session',binding:execution.binding,controller_boot_id:receipt.member_boot_id});
      }
      const connected=await moduleClient.connectReadOnly(device),first=await moduleClient.captureBaseline(device),second=await moduleClient.captureBaseline(device);
      const accepted=moduleClient.currentBaseline(device);
      if(input.mode.startsWith('supervisor_create_module_obs')){
        const route='/api/v1/devices/'+device+'/scene-catalog';
        manager.real.refresh();
        report({event:'obs-scene-catalog-http',current:await commandHttp('GET',route),
          noPermission:await commandHttp('GET',route,undefined,manager.token()),
          noToken:await commandHttp('GET',route,undefined,null)});
        const token=manager.token(['device.read','extension.manage']);
        const request={request_id:'obs.confirm',expected_catalog_digest:hash(accepted.scene_catalog)};
        const confirm=(fields=request,credential=token,csrf=manager.auth.csrf)=>manager.sessions.confirmSceneCatalog(credential,csrf,device,fields);
        const rejected=(action)=>{
          try{action();return 'unexpected_success';}catch(error){return error.code;}
        };
        const denied=rejected(()=>confirm(request,commandToken)),csrf=rejected(()=>confirm(request,token,'A'.repeat(43))),
          stale=rejected(()=>confirm({...request,expected_catalog_digest:hash('old catalogue')}));
        const ready=confirm(),replayed=confirm(),conflict=rejected(()=>confirm({...request,request_id:'obs.confirm.other'}));
        report({event:'obs-scene-confirmed',ready,replayed,denied,csrf,stale,conflict,
          actor:{principal_id:manager.logged.session.principal_id,session_id:manager.logged.session.session_id},
          current:await commandHttp('GET',route)});
        const {collection_ref,collection_generation,catalog_revision,binding_revision}=ready;
        const target=ready.entries.find(entry=>entry.obs_scene_uuid!==second.body.value.program_scene_uuid);
        const scene_ref={collection_ref,collection_generation,catalog_revision,binding_revision,scene_id:target.scene_id};
        const packet=business.workerLaunches.prepareObsCutPacket(device,{scene_ref});
        report({event:'obs-cut-packet',target:target.obs_scene_uuid,packet_hex:packet.toString('hex'),
          stale:rejected(()=>business.workerLaunches.prepareObsCutPacket(device,{scene_ref:{...scene_ref,binding_revision:'1'}}))});
        if(input.mode==='supervisor_create_module_obs_cut'||obsOpen){
          executionClient=await business.workerLaunches.openExecution(key);
          const first=await moduleClient.configureExecution(device),repeated=await moduleClient.configureExecution(device);
          manager.real.refresh();
          report({event:'obs-cut-execution-bound',first,repeated,state:executionClient.state,features:executionClient.negotiation.selected_features,
            capabilities:await commandHttp('GET','/api/v1/devices/'+device+'/capabilities')});
          if(obsOpen){
            if(obsCommand)await commandHttp('GET','/api/v1/commands/00000000-0000-4000-8000-000000000001');
            if(input.gui?.obs)await obsBrowserMarker(input.gui.obs.ready);
            await business.workerLaunches.runtime.refreshCurrent(key);
            await source.refreshCoreObservation();
            manager.real.refresh();
            const opened=await openOrdinaryGate(device,false);
            report({event:'obs-cut-opened',...opened,state:executionClient.state});
            if(obsCommand){
              const route='/api/v1/commands';
              const request={...commandRequest,action_id:'obs.program_scene.set',parameters:{scene_ref},required_completion:'effect_verified',
                idempotency_key:crypto.randomUUID(),dispatch:{mode:'immediate',max_queue_ms:10000}};
              const stale=await commandHttp('POST',route,{...request,parameters:{scene_ref:{...scene_ref,binding_revision:'1'}}});
              report({event:'obs-cut-stale-reference',stale});
              if(input.gui?.obs){
                fs.writeFileSync(input.gui.obs.opened,'ready');
                const {body,response}=JSON.parse(await obsBrowserMarker(input.gui.obs.submitted));
                if(canonicalize(body.parameters)!==canonicalize(request.parameters))throw new Error('fixture_obs_browser_target');
                if(input.gui.obs.recovery){
                  manager.real.refresh();
                  const replayed=await commandHttp('POST',route,body);
                  report({event:'obs-cut-browser-rejected',response,replayed});
                }else await completeObsCut(body,1,response);
                fs.writeFileSync(input.gui.obs.settled,'settled');
                await obsBrowserMarker(input.gui.obs.checked);
              }else if(input.obs_interruption)await observeInterruptedObsCut(request);
              else await completeObsCut(request,1);
              if(!input.obs_interruption&&!input.gui?.obs?.recovery){
                const original=ready.entries.find(entry=>entry.obs_scene_uuid===second.body.value.program_scene_uuid);
                const next={...request,idempotency_key:crypto.randomUUID(),parameters:{scene_ref:{...scene_ref,scene_id:original.scene_id}}};
                const blocked=await commandHttp('POST',route,next);
                report({event:'obs-cut-protected',blocked,state:executionClient.state});
                const successor=await openSuccessorGate(device,{checkObsSample:true});
                report({event:'obs-cut-reopened',...successor,state:executionClient.state});
                await completeObsCut(next,2);
                const sample=await moduleClient.captureBaseline(device);
                report({event:'obs-cut-final-sample',sample:sample.body.value});
              }
            }
          }
        }
        report({event:'obs-module-samples',connected,first,second,accepted});
        const until=performance.now()+20000;
        while(!fs.existsSync(options['--fixture']+'.obs-stopped')){
          if(performance.now()>=until)throw new Error('fixture_obs_stop_timeout');
          await delay(20);
        }
        try{await moduleClient.captureBaseline(device);}
        catch(error){
          manager.real.refresh();
          let control;
          if(obsOpen){
            const deadline=performance.now()+3000;
            do{
              control=manager.sessions.getControl(commandToken,device);
              if(control.gate_state==='protected'||performance.now()>=deadline)break;
              await delay(20);
            }while(true);
          }
          report({event:'obs-scene-catalog-withdrawn',response:await commandHttp('GET',route),
            confirmation:rejected(confirm),...(obsOpen&&{control})});
          throw error;
        }
        throw new Error('fixture_obs_stale_sample');
      }
      const armTarget=input.automation_peer?.arm_target;
      if(armTarget){await moduleClient.connectReadOnly(armTarget);await moduleClient.captureBaseline(armTarget);}
      if(eventCaptureMode){
       const started=await moduleClient.startEvents(device),empty=await moduleClient.readEvents(device);
       await moduleClient.acknowledgeEvents(device,{through_sequence:empty.body.result.batch.through_sequence,batch_digest:empty.body.result.batch_digest});
       report({event:'module-events-started',started,empty});
      }
      if(input.mode.endsWith('_capabilities')){
       manager.real.refresh();report({event:'capabilities-connected',response:await commandHttp('GET','/api/v1/devices/'+device+'/capabilities')});
       const bindings=business.workerLaunches.deviceAutomation(device);automationRegistration=bindings.registration_ref;report({event:'automation-bindings-connected',bindings});
       if(input.automation_peer){bindingPeer=await automationPeer({business,manager,config:input.automation_peer,device,refresh:()=>business.workerLaunches.runtime.refreshCurrent(key),report});await bindingPeer.phase('connected');}
       if(input.gui){
        report({event:'gui-capabilities-ready'});const until=performance.now()+60000;let refreshed=0;
        while(true){
         if(performance.now()>=until)throw new Error('gui_capabilities_timeout');
         if(performance.now()-refreshed>500){await business.workerLaunches.runtime.refreshCurrent(key);refreshed=performance.now();}
         if(fs.existsSync(input.gui.capability_request)){
          const request=JSON.parse(fs.readFileSync(input.gui.capability_request,'utf8'));fs.unlinkSync(input.gui.capability_request);
          if(request.operation==='finish')break;
          if(request.operation==='disconnect')await moduleClient.stopReadOnly(device);
          else if(request.operation==='reconnect'){await moduleClient.connectReadOnly(device);await moduleClient.captureBaseline(device);}
          else throw new Error('gui_capabilities_operation');
          fs.writeFileSync(input.gui.capability_result,JSON.stringify(request));
         }
         await delay(20);
        }
       }
      }
      if(controlFlow||input.mode.includes('_handshake_')){
        const execution=executionClient=await business.workerLaunches.openExecution(key);
        report({event:'execution-session',binding:execution.binding,controller_boot_id:receipt.member_boot_id});
        report({event:'execution-negotiated',negotiation:execution.negotiation,state:execution.state});
      }
      if(controlFlow||input.mode.includes('_binding_'))report({event:'execution-bound',first:moduleClient.bindExecution(device),repeated:moduleClient.bindExecution(device)});
      const protectionPlan=input.run_fence?{origin_scope:input.run_fence.origin_scope,run_id:input.run_fence.run_id,deny_through_generation:'2',
        device_ids:input.run_fence.after_retirement?[device]:[device,crypto.randomUUID()]}:null;
      const beforeConfiguration=protectionPlan?await business.workerLaunches.applyRunProtection(protectionPlan):null;
      if(input.mode==='supervisor_create_module_writable'||input.mode.includes('_open_dispatch'))report({event:'execution-configured',first:await moduleClient.configureExecution(device),repeated:await moduleClient.configureExecution(device)});
      if(armTarget){
        await moduleClient.configureExecution(armTarget);
      }
      if(protectionPlan&&!input.run_fence.after_retirement){
        const scheduled=await business.workerLaunches.applyRunProtection(protectionPlan);
        const request={...input.run_fence,device_id:device},first=await executionClient.applyRunFence(request);
        report({event:'run-fence',beforeConfiguration,scheduled,first,repeated:await executionClient.applyRunFence(request),state:executionClient.state});
      }
      let manualSource=null,recoveryRequest=null,recoveryAccepted=null,consumedRecovery=null,competingRecovery=null;
      if(automaticReady||manualGateMigration){await runOrdinaryGate(device,automaticReady);break moduleWork;}
      if(controlFlow){
        report({event:'initial-control-fence',first:await executionClient.initialFence(device),repeated:await executionClient.initialFence(device)});
        if(!input.automation_peer?.verify_armed_target_dispatch){
         if(commandHttp){const missing=await commandHttp('GET','/api/v1/commands/00000000-0000-4000-8000-000000000001');if(missing.status!==404)throw new Error('command_http_connection');}
         try{await manualSourceFor({...commandToken,secret:'A'.repeat(43)},device);report({event:'manual-source-bad-secret',code:'unexpected_success'});}
         catch(error){report({event:'manual-source-bad-secret',code:error.code});}
         const coreObservation=source.observeCore();source.assertCoreObservation(coreObservation);
         try{source.assertCoreObservation(structuredClone(coreObservation));report({event:'core-observation-copy',code:'unexpected_success'});}
         catch(error){report({event:'core-observation-copy',code:error.code});}
        }
        manualSource=await manualSourceFor(commandToken,device);
        report({event:'manual-source',source:manualSource,current:manager.sessions.currentManualExecutionSource(manualSource.ref)});
        await delay(25); // 独立调用间让实际监督观察刷新任务运行，保留原证据期限。
        if(input.mode.includes('_evidence_')){
          const challenge=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
          evaluatorSource=manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:challenge.id,revision:'1',digest:challenge.digest},nonce:challenge.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret});
          authorizationContext=manager.sessions.currentManualAuthorizationContext({device_id:device,manual_source_ref:manualSource.ref,evaluator_source_ref:evaluatorSource.ref});
          await delay(10);
          recoveryRequest={request_id:crypto.randomUUID(),device_id:device,manual_source_ref:manualSource.ref,evaluator_source_ref:evaluatorSource.ref,
            expected_state_ref:authorizationContext.state_ref,expected_context_digest:authorizationContext.context_digest};
          recoveryAccepted=manager.sessions.requestDeviceAuthorizationRecovery(commandToken,recoveryRequest);
          await delay(10);
          consumedRecovery=manager.sessions.consumeDeviceAuthorizationRecovery(commandToken,recoveryAccepted.receipt.id);
          await delay(10);
          const evidenceRequest={request_id:crypto.randomUUID(),device_id:device,manual_source_ref:manualSource.ref,evaluator_source_ref:evaluatorSource.ref,
            expected_state_ref:consumedRecovery.ref,expected_evidence_ref:null};
          if(input.mode.includes('_resource_open_')){
            const freshManual=await manualSourceFor(commandToken,device,false);
            const challenge=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
            const freshEvaluator=manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:challenge.id,revision:'1',digest:challenge.digest},
              nonce:challenge.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret});
            authorizationEvidence=manager.sessions.selectDeviceAuthorizationEvidence({...evidenceRequest,manual_source_ref:freshManual.ref,evaluator_source_ref:freshEvaluator.ref});
            // 触发组合场景使用首次选择的就绪证据。证据续换由独立场景覆盖。
            if(input.mode.includes('_dispatch_ready')&&!input.automation_peer?.verify_armed_target_dispatch){
              // 首次Evidence先在恢复窗口内采用，再等待实际新观察并续约。
              await business.workerLaunches.runtime.refreshCurrent(key);
              await source.refreshCoreObservation();
              if(input.mode.includes('_guard_dispatch'))manager.real.refresh();
              const manualPending=manualSourceFor(commandToken,device,false),next=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
              const nextEvaluator=manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:next.id,revision:'1',digest:next.digest},nonce:next.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret});
              const nextManual=await manualPending;
              authorizationEvidence=manager.sessions.selectDeviceAuthorizationEvidence({...evidenceRequest,request_id:crypto.randomUUID(),expected_evidence_ref:authorizationEvidence.ref,
                manual_source_ref:nextManual.ref,evaluator_source_ref:nextEvaluator.ref});
            }
          }else authorizationEvidence=manager.sessions.selectDeviceAuthorizationEvidence(evidenceRequest);
          await delay(10);
          if(input.mode.includes('_resource_'))report({event:'authorization-evidence',value:authorizationEvidence});
          else report({event:'authorization-evidence',value:authorizationEvidence,current:manager.sessions.currentDeviceAuthorizationEvidence(device),replayed:manager.sessions.selectDeviceAuthorizationEvidence(evidenceRequest)});
          if(input.mode.includes('_resource_')){
            initialResourceRequest={request_id:crypto.randomUUID(),device_id:device,expected_evidence_ref:authorizationEvidence.ref};
            initialResource=manager.sessions.selectInitialDeviceResources(initialResourceRequest);
            await delay(10);
            report({event:'initial-resource',value:initialResource,...(input.mode.includes('_open_')?{}:{current:manager.sessions.currentInitialDeviceResources(initialResource.ref)})});
            if(input.mode.includes('_open_')){
              await delay(10);
              initialOpeningRequest={request_id:crypto.randomUUID(),device_id:device,expected_resource_ref:initialResource.ref};
              initialOpening=manager.sessions.prepareInitialDeviceOpen(initialOpeningRequest);
              if(input.mode.includes('_open_dispatch')){
                report({event:'initial-open',value:initialOpening});
                if(input.mode.includes('_dispatch_ready'))report({event:'ready-window',stage:'before-open',remaining_ms:Number((BigInt(initialOpening.value.plan.expires_tick_ns)-clock.tick())/1000000n)});
                if(input.mode.endsWith('_expired')&&!input.mode.includes('_dispatch_ready')){await waitPastSource(initialOpening.value.plan.expires_tick_ns);report({event:'open-expiry-boundary',tick:String(clock.tick()),expires:initialOpening.value.plan.expires_tick_ns});}
                const result=await executionClient.initialOpen(initialOpening.ref,{ready:input.mode.includes('_dispatch_ready')&&!input.mode.endsWith('_expired')});report({event:'open-confirmed',result,state:executionClient.state});
                if(input.mode.includes('_dispatch_ready')){
                  report({event:'ready-window',stage:'after-open',remaining_ms:Number((BigInt(initialOpening.value.plan.expires_tick_ns)-clock.tick())/1000000n)});
                  if(input.mode.endsWith('_expired'))await waitPastSource(initialOpening.value.plan.expires_tick_ns);
                  const ready=result.ready??executionClient.initialReady(initialOpening.ref.id);
                  report({event:'initial-ready',value:ready,
                    control:manager.sessions.getControl(commandToken,device)});
                  if(!input.mode.endsWith('_stale')){
                    const request={...commandRequest,...((input.mode.endsWith('_closure_late')||input.mode.endsWith('_cleanup_late')||input.mode.endsWith('_control_unresolved'))?{evidence_timeout_ms:1}:{}),idempotency_key:crypto.randomUUID(),dispatch:{mode:'immediate',max_queue_ms:input.mode.endsWith('_queue_deadline')?300:10000}};
                    let accepted,replayed,current,http_statuses,guardProof=null,preparedProof=null;
                    if(input.mode.includes('_control_queued')){
                      accepted=await manager.sessions.submitCommand(commandToken,request,{withStatus:true});
                      await releaseAfterCommands(device);
                      report({event:'control-queued-command',accepted,current:manager.sessions.getCommand(commandToken,accepted.adjudication.command_ref.object_id)});
                      if(input.mode.endsWith('_control_queued_cut_omit'))executionClient.close();
                      break moduleWork;
                    }
                    if(commandHttp){
                      const first=await commandHttp('POST','/api/v1/commands',request);
                      if(first.status!==202)throw Object.assign(new Error('command_http_admission'),{code:'command_http_admission',cause:first.body});
                      if(input.mode.includes('_cleanup_successor_control'))for(const [stage,method]of [['encoded','whenCommandEncoded'],['finalized','whenCommandFinalized']])
                        business.workerLaunches[method](first.body.command_ref.object_id).then(()=>report({event:'ready-window',stage,remaining_ms:Number((BigInt(initialOpening.value.plan.expires_tick_ns)-clock.tick())/1000000n)}),()=>{});
                      if(input.mode.includes('_t2_guard'))business.workerLaunches.whenCommandGuarded(first.body.command_ref.object_id).catch(error=>report({event:'guard-task-failed',code:error.code,message:error.message}));
                      // Guard正例先等待已受理的真实执行任务，再进行历史HTTP查询；避免查询负载消耗原短窗口。
                      if(input.mode.includes('_t2_guard')&&(!input.mode.endsWith('_omit')||input.mode.includes('_guard_dispatch'))){
                        const commandId=first.body.command_ref.object_id,guarded=await business.workerLaunches.whenCommandGuarded(commandId);
                        preparedProof=guarded.qualification;
                        if(input.mode.includes('_guard_dispatch')){report({event:'ready-window',stage:'after-guard',remaining_ms:Number((BigInt(initialOpening.value.plan.expires_tick_ns)-clock.tick())/1000000n)});const dispatched=await business.workerLaunches.whenCommandDispatched(commandId);
                          const closed=input.mode.includes('_dispatch_closure')?await business.workerLaunches.whenCommandSettled(commandId):null;
                          if(input.mode.includes('_closure_cleanup')){const cleaned=await business.workerLaunches.whenCommandCleaned(commandId),replayed=await executionClient.cleanupCommand(commandId);
                            report({event:'command-cleaned',value:cleaned,replay_ref:replayed.ref,state:executionClient.state});}
                          const repeated=await executionClient.dispatchCommand(commandId);
                          report({event:'command-dispatched',value:dispatched,replay_ref:repeated.ref,replay_qualification:repeated.qualification});
                          if(closed){const again=await executionClient.closeCommand(commandId);report({event:'command-closed',value:closed,replay_ref:again.ref,state:executionClient.state});}}
                        const replay=input.mode.endsWith('_guard_changed')?null:await executionClient.installCommandGuard(commandId);
                        guardProof={event:'command-guard-installed',disposition:guarded.ack.value.disposition,body:guarded.ack.reply.frame.body,original_ref:guarded.ref,replay_ref:replay?.ref??null,replay_qualification:replay?.qualification??null};
                        if(input.mode.endsWith('_guard_changed')){await moduleClient.captureBaseline(device);
                          try{executionClient.currentPreparedCommand(commandId);report({event:'command-prepared-rejected',code:'unexpected_success'});}
                          catch(error){report({event:'command-prepared-rejected',code:error.code});}}
                      }

                      const again=await commandHttp('POST','/api/v1/commands',{...request,correlation_id:crypto.randomUUID()});
                      let read=await commandHttp('GET','/api/v1/commands/'+first.body.command_ref.object_id);
                      http_statuses=[first.status,again.status,read.status];
                      // 首次采样与响应末核间可推进修订；只遵从显式read_current重读一次，不重提交动作。
                      if(read.status===503&&read.body.code==='unavailable'&&read.body.retry_action==='read_current'){
                        read=await commandHttp('GET','/api/v1/commands/'+first.body.command_ref.object_id);http_statuses.push(read.status);
                      }
                      if(read.status!==200)throw Object.assign(new Error('command_http_read'),{code:'command_http_read',cause:read.body});accepted={adjudication:first.body,replay:false};replayed={adjudication:again.body,replay:true};current=read.body;
                    }else{
                      accepted=await manager.sessions.submitCommand(commandToken,request,{withStatus:true});
                      replayed=await manager.sessions.submitCommand(commandToken,{...request,correlation_id:crypto.randomUUID()},{withStatus:true});
                      current=manager.sessions.getCommand(commandToken,accepted.adjudication.command_ref.object_id);
                    }
                    report({event:'command-accepted',request,accepted,replayed,current,http_statuses});
                    if(input.mode.includes('_ready_encoding')){
                      const encoded=await business.workerLaunches.whenCommandEncoded(accepted.adjudication.command_ref.object_id);
                      const finalizing=input.mode.includes('_encoding_t2');
                      const replay=finalizing?await business.workerLaunches.whenCommandEncoded(accepted.adjudication.command_ref.object_id):await executionClient.encodeCommand(accepted.adjudication.command_ref.object_id);
                      report({event:'command-encoded',disposition:encoded.response.value.disposition,evidence:encoded.response.value.evidence,packet:encoded.response.reply.frame.body.packet,
                        bytes_hex:encoded.response.bytes.toString('hex'),original_ref:encoded.ref,replay_ref:replay.ref});
                      if(input.mode.endsWith('_changed_input')){
                        await moduleClient.captureBaseline(device);
                        try{executionClient.commandFinalizationInputs(encoded.value.prepare_id);report({event:'command-finalization-rejected',code:'unexpected_success'});}
                        catch(error){report({event:'command-finalization-rejected',code:error.code});}
                      }else if(!finalizing)report({event:'command-finalization-inputs',value:executionClient.commandFinalizationInputs(encoded.value.prepare_id)});
                      if(finalizing){
                        const committed=await business.workerLaunches.whenCommandFinalized(accepted.adjudication.command_ref.object_id);
                        report({event:'command-final-admission',record:committed.saved.record,value:committed.saved.lifecycle.final_admission.value,
                          observation:committed.observation,replay:committed.replay});
                        if(!input.reference_schema&&!input.mode.endsWith('_current_schema')&&!input.mode.includes('_cleanup_successor')&&!input.mode.endsWith('_control_unresolved'))report({event:'command-prepared-current',value:preparedProof??executionClient.currentPreparedCommand(committed.saved.source.command_id)});
                        if(input.mode.includes('_t2_guard')){
                          if(guardProof)report(guardProof);
                          else await business.workerLaunches.whenCommandGuarded(committed.saved.source.command_id);
                        }
                      }
                    }
                    if(input.mode.endsWith('_execution_closed'))executionClient.close();
                    await waitPastSource(initialOpening.value.plan.expires_tick_ns);
                    const code=async action=>{try{await action();return 'unexpected_success';}catch(error){return error.code;}};
                    const readOnly=manager.token(['control.read']);
                    if(input.reference_acceptance){
                      referenceWithdrawn=true;
                      const current=referencePublication.current();
                      await referencePublication.reconcileProtection();
                      report({event:'command-reference-invalidated',current,protection:referencePublication.protectionStatus()});
                    }
                    const terminalHttp=commandHttp?await commandHttp('GET','/api/v1/commands/'+accepted.adjudication.command_ref.object_id):null;
                    if(terminalHttp&&terminalHttp.status!==200)throw Object.assign(new Error('command_http_terminal'),{code:'command_http_terminal',cause:terminalHttp.body});
                    if(input.reference_schema||input.mode.endsWith('_dispatch_closure')||input.mode.endsWith('_closure_cleanup')||input.mode.endsWith('_current_schema')){
                      const commandId=accepted.adjudication.command_ref.object_id,first=await commandHttp('GET','/api/v1/commands/'+commandId+'/evidence?state_revision=5&limit=1'),
                        second=await commandHttp('GET','/api/v1/commands/'+commandId+'/evidence?state_revision=5&limit=1&cursor='+encodeURIComponent(first.body.next_cursor)),
                        original=await commandHttp('GET','/api/v1/commands/'+commandId+'/evidence/'+first.body.items?.[0]?.source_ref.id+'/revisions/1'),
                        prior=await commandHttp('GET','/api/v1/commands/'+commandId+'/evidence?state_revision=4&limit=1'),
                        denied=await code(()=>manager.sessions.getCommandEvidence(manager.token(['command.read']),commandId,{state_revision:'5',limit:1}));
                      report({event:'command-evidence',first,second,original,prior,denied});
                    }

                    report({event:'command-history',http_status:terminalHttp?.status,current:terminalHttp?.body??manager.sessions.getCommand(commandToken,accepted.adjudication.command_ref.object_id),
                      replayed:await manager.sessions.submitCommand(commandToken,request,{withStatus:true}),
                      conflict:await code(()=>manager.sessions.submitCommand(commandToken,{...request,parameters:{value:123}})),
                      denied:await code(()=>manager.sessions.getCommand(readOnly,accepted.adjudication.command_ref.object_id)),
                      missing:await code(()=>manager.sessions.getCommand(commandToken,crypto.randomUUID()))});
                  }
                  if(input.mode.endsWith('_stale')){await moduleClient.captureBaseline(device);await checkCommand('ready-stale');executionClient.currentReady(ready.ref);report({event:'ready-stale',code:'unexpected_success'});}
                  else{await checkCommand('ready-expired');report({event:'ready-expired',state:executionClient.state,control:manager.sessions.getControl(commandToken,device)});}
                  if(input.mode.includes('_cleanup_successor'))await runSuccessor(device);
                  if(input.automation_peer?.target_gate_only)await openAutomationTarget(input.automation_peer.arm_target);
                  else if(eventCaptureMode)await verifyCapturedEvents(device);
                  if(input.mode.endsWith('_successor_control')||input.mode.endsWith('_control_unresolved'))await releaseAfterCommands(device);
                  if(protectionPlan&&input.run_fence.after_retirement)report({event:'run-protection-retirement',plan:protectionPlan,
                    beforeConfiguration,result:await business.workerLaunches.applyRunProtection(protectionPlan)});
                  break moduleWork;
                }
                if(input.mode.endsWith('_stale')){await moduleClient.captureBaseline(device);await executionClient.initialOpen(initialOpening.ref);report({event:'open-stale',code:'unexpected_success'});}
                break moduleWork;
              }
              await delay(10);
              report({event:'initial-open',value:initialOpening,current:manager.sessions.currentInitialDeviceOpen(initialOpening.ref)});
            }
            await moduleClient.captureBaseline(device);
            if(initialOpening){
              // 该调用沿真实plan->resource链检查基线失效，避免在同一短窗口重复整个来源校验。
              try{manager.sessions.currentInitialDeviceOpen(initialOpening.ref);report({event:'initial-open-new-sample',code:'unexpected_success'});}catch(error){report({event:'initial-open-new-sample',code:error.code});}
            }else try{manager.sessions.currentInitialDeviceResources(initialResource.ref);report({event:'initial-resource-new-sample',code:'unexpected_success'});}catch(error){report({event:'initial-resource-new-sample',code:error.code});}
            await business.workerLaunches.runtime.refreshCurrent(key);
          }else{
          const priorObservation=manualCoreObservations.get(manualSource.ref.id),until=performance.now()+1000;
          while(source.observeCore()===priorObservation){if(performance.now()>=until)throw new Error('fixture_core_refresh_timeout');await delay(10);}
          const freshManual=await manualSourceFor(commandToken,device,false),next=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
          const freshEvaluator=manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:next.id,revision:'1',digest:next.digest},nonce:next.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret});
          const renewalRequest={...evidenceRequest,request_id:crypto.randomUUID(),manual_source_ref:freshManual.ref,evaluator_source_ref:freshEvaluator.ref,expected_evidence_ref:authorizationEvidence.ref};
          const renewed=manager.sessions.selectDeviceAuthorizationEvidence(renewalRequest);
          await delay(10);
          report({event:'evidence-renewed',value:renewed,current:manager.sessions.currentDeviceAuthorizationEvidence(device)});
          try{manager.sessions.selectDeviceAuthorizationEvidence({...renewalRequest,request_id:crypto.randomUUID(),expected_evidence_ref:null});report({event:'evidence-clear-bypass',code:'unexpected_success'});}catch(error){report({event:'evidence-clear-bypass',code:error.code});}
          try{manager.sessions.selectDeviceAuthorizationEvidence({...evidenceRequest,expected_evidence_ref:authorizationEvidence.ref});report({event:'evidence-request-conflict',code:'unexpected_success'});}catch(error){report({event:'evidence-request-conflict',code:error.code});}
          authorizationEvidence=renewed;
          const recoveryEnd=BigInt(recoveryAccepted.authorization.expires_tick_ns),evidenceEnd=BigInt(renewed.value.requirement.expires_tick_ns);
          if(evidenceEnd<=recoveryEnd)throw new Error('fixture_evidence_not_refreshed');
          const remaining=recoveryEnd-clock.tick();if(remaining>0n)await delay(Number(remaining/1000000n)+2);
          const afterRecovery=await manualSourceFor(commandToken,device,false);
          report({event:'evidence-after-recovery-window',source:afterRecovery,state:manager.sessions.currentDeviceAuthorizationEvidence(device).value.state_ref,
            now_tick:String(clock.tick()),recovery_before:String(recoveryEnd),evidence_before:String(evidenceEnd)});
          }
        }else if(evaluator){
          const challenge=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
          const response={request_id:crypto.randomUUID(),challenge_ref:{id:challenge.id,revision:challenge.revision,digest:challenge.digest},nonce:challenge.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret};
          for(const [event,changes] of [['evaluator-wrong-secret',{secret:'A'.repeat(43)}],['evaluator-wrong-nonce',{nonce:'A'.repeat(43)}]]){
            try{manager.sessions.completeDeviceEvaluatorChallenge({...response,...changes});report({event,code:'unexpected_success'});}catch(error){report({event,code:error.code});}
          }
          evaluatorSource=manager.sessions.completeDeviceEvaluatorChallenge(response);
          report({event:'evaluator-source',source:evaluatorSource,replayed:manager.sessions.completeDeviceEvaluatorChallenge(response),current:manager.sessions.currentDeviceEvaluatorSource(evaluatorSource.ref)});
          try{manager.sessions.completeDeviceEvaluatorChallenge({...response,request_id:crypto.randomUUID()});report({event:'evaluator-conflict',code:'unexpected_success'});}catch(error){report({event:'evaluator-conflict',code:error.code});}
          await delay(25);
          const request={device_id:device,manual_source_ref:manualSource.ref,evaluator_source_ref:evaluatorSource.ref};
          authorizationContext=manager.sessions.currentManualAuthorizationContext(request);
          report({event:'authorization-context',value:authorizationContext});
          for(const [event,changes] of [['authorization-context-device',{device_id:crypto.randomUUID()}],['authorization-context-injected',{context_digest:hash('untrusted')}],['authorization-context-missing',{manual_source_ref:null}]]){
            try{manager.sessions.currentManualAuthorizationContext({...request,...changes});report({event,code:'unexpected_success'});}catch(error){report({event,code:error.code});}
          }
          // 新一组取证使用下一次真实监督回复，不延长上一组原件的期限。
          const previousObservation=source.observeCore(),refreshDeadline=performance.now()+1500;
          while(source.observeCore()===previousObservation){if(performance.now()>=refreshDeadline)throw new Error('fixture_core_refresh_timeout');await delay(10);}
          const refreshedManual=await manualSourceFor(commandToken,device),refreshedChallenge=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
          const refreshedEvaluator=manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:refreshedChallenge.id,revision:refreshedChallenge.revision,digest:refreshedChallenge.digest},nonce:refreshedChallenge.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret});
          report({event:'authorization-context-refreshed',value:manager.sessions.currentManualAuthorizationContext({device_id:device,manual_source_ref:refreshedManual.ref,evaluator_source_ref:refreshedEvaluator.ref})});
          recoveryRequest={request_id:crypto.randomUUID(),device_id:device,manual_source_ref:refreshedManual.ref,evaluator_source_ref:refreshedEvaluator.ref,
            expected_state_ref:authorizationContext.state_ref,expected_context_digest:authorizationContext.context_digest};
          try{manager.sessions.requestDeviceAuthorizationRecovery(manager.token(['device.command']),recoveryRequest);report({event:'recovery-no-permission',code:'unexpected_success'});}catch(error){report({event:'recovery-no-permission',code:error.code});}
          try{manager.sessions.requestDeviceAuthorizationRecovery(commandToken,{...recoveryRequest,expected_context_digest:hash('changed')});report({event:'recovery-wrong-context',code:'unexpected_success'});}catch(error){report({event:'recovery-wrong-context',code:error.code});}
          recoveryAccepted=manager.sessions.requestDeviceAuthorizationRecovery(commandToken,recoveryRequest);
          report({event:'recovery-accepted',value:recoveryAccepted,replayed:manager.sessions.requestDeviceAuthorizationRecovery(commandToken,recoveryRequest),current:manager.sessions.currentDeviceAuthorizationRecovery(commandToken,recoveryAccepted.receipt.id)});
          try{manager.sessions.requestDeviceAuthorizationRecovery(commandToken,{...recoveryRequest,expected_context_digest:hash('changed')});report({event:'recovery-conflict',code:'unexpected_success'});}catch(error){report({event:'recovery-conflict',code:error.code});}
          await delay(100);
          competingRecovery=manager.sessions.requestDeviceAuthorizationRecovery(commandToken,{...recoveryRequest,request_id:crypto.randomUUID()});
          consumedRecovery=manager.sessions.consumeDeviceAuthorizationRecovery(commandToken,recoveryAccepted.receipt.id);
          report({event:'recovery-consumed',value:consumedRecovery,replayed:manager.sessions.consumeDeviceAuthorizationRecovery(commandToken,recoveryAccepted.receipt.id)});
          try{manager.sessions.consumeDeviceAuthorizationRecovery(commandToken,competingRecovery.receipt.id);report({event:'recovery-old-state',code:'unexpected_success'});}catch(error){report({event:'recovery-old-state',code:error.code});}
          await delay(10);
          const afterConsumption=await manualSourceFor(commandToken,device,false);
          report({event:'authorization-context-selected',value:manager.sessions.currentManualAuthorizationContext({device_id:device,manual_source_ref:afterConsumption.ref,evaluator_source_ref:refreshedEvaluator.ref})});

        }
        await waitPastSource([manualSource.value.expires_tick_ns,coreObservation.expires_tick_ns,evaluatorSource?.value.expires_tick_ns??'0'].map(BigInt).reduce((a,b)=>a>b?a:b));
        if(initialResource){
          try{manager.sessions.currentInitialDeviceResources(initialResource.ref);report({event:'initial-resource-expired',code:'unexpected_success'});}catch(error){report({event:'initial-resource-expired',code:error.code});}
          report({event:'initial-resource-history',value:manager.sessions.lookupInitialDeviceResources(initialResource.ref),replayed:manager.sessions.selectInitialDeviceResources(initialResourceRequest)});
          try{manager.sessions.selectInitialDeviceResources({...initialResourceRequest,expected_evidence_ref:null});report({event:'initial-resource-conflict',code:'unexpected_success'});}catch(error){report({event:'initial-resource-conflict',code:error.code});}
          await delay(10);
        }
        if(initialOpening){
          try{manager.sessions.currentInitialDeviceOpen(initialOpening.ref);report({event:'initial-open-expired',code:'unexpected_success'});}catch(error){report({event:'initial-open-expired',code:error.code});}
          report({event:'initial-open-history',value:manager.sessions.lookupInitialDeviceOpen(initialOpening.ref),replayed:manager.sessions.prepareInitialDeviceOpen(initialOpeningRequest)});
          try{manager.sessions.prepareInitialDeviceOpen({...initialOpeningRequest,expected_resource_ref:null});report({event:'initial-open-conflict',code:'unexpected_success'});}catch(error){report({event:'initial-open-conflict',code:error.code});}
          try{manager.sessions.prepareInitialDeviceOpen({...initialOpeningRequest,request_id:crypto.randomUUID()});report({event:'initial-open-second',code:'unexpected_success'});}catch(error){report({event:'initial-open-second',code:error.code});}
          await delay(10);
        }
        if(firstManualChallenge)try{manager.sessions.completeManualExecutionChallenge(firstManualChallenge.input,firstManualChallenge.response);report({event:'manual-challenge-expired',code:'unexpected_success'});}catch(error){report({event:'manual-challenge-expired',code:error.code});}
        if(authorizationEvidence){
          try{manager.sessions.currentDeviceAuthorizationEvidence(device);report({event:'evidence-expired',code:'unexpected_success'});}catch(error){report({event:'evidence-expired',code:error.code});}
          report({event:'evidence-history',value:manager.sessions.lookupDeviceAuthorizationEvidence(authorizationEvidence.ref)});
          await delay(10);
        }
        if(recoveryAccepted){
          try{manager.sessions.currentDeviceAuthorizationRecovery(commandToken,recoveryAccepted.receipt.id);report({event:'recovery-expired',code:'unexpected_success'});}catch(error){report({event:'recovery-expired',code:error.code});}
          report({event:'recovery-history',value:manager.sessions.lookupDeviceAuthorizationRecovery(commandToken,recoveryAccepted.receipt.id),replayed:manager.sessions.requestDeviceAuthorizationRecovery(commandToken,recoveryRequest)});
          report({event:'recovery-consumed-history',value:manager.sessions.consumeDeviceAuthorizationRecovery(commandToken,recoveryAccepted.receipt.id)});
          if(competingRecovery)try{manager.sessions.consumeDeviceAuthorizationRecovery(commandToken,competingRecovery.receipt.id);report({event:'recovery-expired-consumption',code:'unexpected_success'});}catch(error){report({event:'recovery-expired-consumption',code:error.code});}
          await delay(10);
        }
        if(evaluatorSource)try{manager.sessions.currentDeviceEvaluatorSource(evaluatorSource.ref);report({event:'evaluator-expired',code:'unexpected_success'});}catch(error){report({event:'evaluator-expired',code:error.code});}
        try{source.assertCoreObservation(coreObservation);report({event:'core-observation-expired',code:'unexpected_success'});}
        catch(error){report({event:'core-observation-expired',code:error.code});}
        try{manager.sessions.currentManualExecutionSource(manualSource.ref);report({event:'manual-source-expired',code:'unexpected_success'});}
        catch(error){report({event:'manual-source-expired',code:error.code});}
        await delay(10);await checkCommand('connected');await delay(10);await checkCommand('wrong-capability',{capability_version:'9.0.0'});
        await delay(10);
        await checkCommand('old-control',{expected_control:{...commandRequest.expected_control,version:'0'}});
      }
      const disconnected=await moduleClient.stopReadOnly(device);
      if(input.mode.endsWith('_capabilities')){
       manager.real.refresh();report({event:'capabilities-disconnected',response:await commandHttp('GET','/api/v1/devices/'+device+'/capabilities')});
       try{business.workerLaunches.deviceAutomation(device,automationRegistration);report({event:'automation-bindings-disconnected',code:'unexpected_success'});}catch(error){report({event:'automation-bindings-disconnected',code:error.code});}
       if(bindingPeer)await bindingPeer.phase('disconnected');
      }
      if(controlFlow){
        await checkCommand('disconnected');
        try{manager.sessions.currentManualExecutionSource(manualSource.ref);report({event:'manual-source-disconnected',code:'unexpected_success'});}
        catch(error){report({event:'manual-source-disconnected',code:error.code});}
        try{moduleClient.bindExecution(device);report({event:'execution-disconnected',code:'unexpected_success'});}catch(error){report({event:'execution-disconnected',code:error.code});}
      }
      try{moduleClient.currentBaseline(device);report({event:'catalog-disconnected',code:'unexpected_success'});}catch(error){report({event:'catalog-disconnected',code:error.code});}
      try{await moduleClient.captureBaseline(device);report({event:'module-disconnected-read',code:'unexpected_success'});}
      catch(error){report({event:'module-disconnected-read',code:error.code});}
      await delay(10);
      const reconnected=await moduleClient.connectReadOnly(device),third=await moduleClient.captureBaseline(device);
      if(input.mode.endsWith('_capabilities')){
       manager.real.refresh();report({event:'capabilities-reconnected',response:await commandHttp('GET','/api/v1/devices/'+device+'/capabilities')});
       try{business.workerLaunches.deviceAutomation(device,automationRegistration);report({event:'automation-bindings-old-registration',code:'unexpected_success'});}catch(error){report({event:'automation-bindings-old-registration',code:error.code});}
       report({event:'automation-bindings-reconnected',bindings:business.workerLaunches.deviceAutomation(device)});
       if(bindingPeer)await bindingPeer.phase('reconnected');
      }
      const fresh=moduleClient.currentBaseline(device);report({event:'module-samples',connected,first,second,disconnected,reconnected,third,accepted,fresh});
      if(controlFlow){
        await checkCommand('before-rebind');report({event:'execution-rebound',binding:moduleClient.bindExecution(device)});
        if(input.mode==='supervisor_create_module_writable')report({event:'execution-reconfigured',binding:await moduleClient.configureExecution(device)});
        report({event:'initial-control-refence',receipt:await executionClient.initialFence(device)});await checkCommand('rebound');
        const logged=await manager.sessions.login({login:'role.test',password:'Synthetic-role-password-123'}),auth={credential_id:logged.credential_id,secret:logged.secret,csrf:logged.csrf};
        const readOnly=manager.sessions.issueToken(auth,{request_id:crypto.randomUUID(),audience:business.identity.service_id,requested_scopes:['control.read']});
        try{await manualSourceFor({token_id:readOnly.token.token_id,secret:readOnly.secret},device);report({event:'manual-source-read-only',code:'unexpected_success'});}
        catch(error){report({event:'manual-source-read-only',code:error.code});}
        const issued=manager.sessions.issueToken(auth,{request_id:crypto.randomUUID(),audience:business.identity.service_id,requested_scopes:['device.command']});
        const freshSource=await manualSourceFor({token_id:issued.token.token_id,secret:issued.secret},device);
        report({event:'manual-source-rebound',source:freshSource,current:manager.sessions.currentManualExecutionSource(freshSource.ref)});
        if(authorizationEvidence){
          try{manager.sessions.currentDeviceAuthorizationEvidence(device);report({event:'evidence-protected',code:'unexpected_success'});}catch(error){report({event:'evidence-protected',code:error.code});}
          report({event:'evidence-protected-history',value:manager.sessions.lookupDeviceAuthorizationEvidence(authorizationEvidence.ref)});
        }
        if(initialResource){
          try{manager.sessions.currentInitialDeviceResources(initialResource.ref);report({event:'initial-resource-reconnected',code:'unexpected_success'});}catch(error){report({event:'initial-resource-reconnected',code:error.code});}
          report({event:'initial-resource-reconnected-history',value:manager.sessions.lookupInitialDeviceResources(initialResource.ref)});
        }
        if(initialOpening){
          try{manager.sessions.currentInitialDeviceOpen(initialOpening.ref);report({event:'initial-open-reconnected',code:'unexpected_success'});}catch(error){report({event:'initial-open-reconnected',code:error.code});}
          report({event:'initial-open-reconnected-history',value:manager.sessions.lookupInitialDeviceOpen(initialOpening.ref)});
        }
        if(evaluator){
          const challenge=manager.sessions.beginDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),policy_ref:evaluator.policy_ref,device_id:device});
          const current=manager.sessions.completeDeviceEvaluatorChallenge({request_id:crypto.randomUUID(),challenge_ref:{id:challenge.id,revision:challenge.revision,digest:challenge.digest},
            nonce:challenge.nonce,credential_id:evaluator.credential_id,secret:evaluator.secret});
          report({event:'evaluator-refreshed',source:current});
          const recoveryInputs={device_id:device,manual_source_ref:freshSource.ref,evaluator_source_ref:current.ref};
          report({event:'authorization-context-rebound',value:manager.sessions.currentManualAuthorizationContext(recoveryInputs)});
          report({event:'recovery-old-history',value:manager.sessions.consumeDeviceAuthorizationRecovery(commandToken,recoveryAccepted.receipt.id)});
          const revoked=manager.sessions.revokeServicePrincipal(manager.auth,{request_id:crypto.randomUUID(),principal_id:evaluator.principal.id,expected_revision:evaluator.principal.revision});
          report({event:'service-principal-revoked',operation:revoked});
          try{manager.sessions.verifyServiceToken(evaluator.token);report({event:'service-principal-token-revoked',code:'unexpected_success'});}catch(error){report({event:'service-principal-token-revoked',code:error.code});}
          try{manager.sessions.currentDeviceEvaluatorSource(current.ref);report({event:'evaluator-revoked',code:'unexpected_success'});}catch(error){report({event:'evaluator-revoked',code:error.code});}
          try{manager.sessions.currentManualAuthorizationContext(recoveryInputs);report({event:'authorization-context-revoked',code:'unexpected_success'});}catch(error){report({event:'authorization-context-revoked',code:error.code});}
        }
        manager.sessions.logout(auth);
        try{manager.sessions.currentManualExecutionSource(freshSource.ref);report({event:'manual-source-logged-out',code:'unexpected_success'});}
        catch(error){report({event:'manual-source-logged-out',code:error.code});}
      }
    }
    if(input.mode==='supervisor_create_module_control'){
      const permissions=['control.read','control.acquire','control.release','control.transfer','control.accept','control.emergency'];
      const before=manager.sessions.localPermissions(manager.auth);manager.sessions.replaceLocalPermissions(manager.auth,{request_id:crypto.randomUUID(),principal_id:manager.logged.session.principal_id,expected_revision:before.revision,permissions:[...before.permissions,...permissions]});
      const token=manager.token([...permissions,'request.create']),device=intent.object_scope.device_ids[0];
      const {contractSelection:selection}=await import('../../dist/sdk/index.mjs');
      const context=manager.sessions.createRequestContext(token,{audience:business.identity.service_id,operations:['acquireControl','releaseControl'],selection,ttl_ms:60000,max_unique_requests:8});
      const act=async(method,key)=>{
        const before=manager.sessions.getControl(token,device),request={context_id:context.context_id,idempotency_key:key,expected_control:{epoch:before.control_epoch,version:before.effective_version},reason:'人工控制'};
        const accepted=await manager.sessions.changeControl(token,method,{device_id:device},request);report({event:'control-accepted',method,accepted});
        const until=performance.now()+8000;let operation;
        do{operation=manager.sessions.getControlOperation(token,accepted.receipt.initial_result_ref.id);if(operation.state!=='pending')break;if(performance.now()>=until)throw new Error('control_wait');await delay(20);}while(true);
        report({event:'control-result',method,operation,control:manager.sessions.getControl(token,device)});
        const replay=await manager.sessions.changeControl(token,method,{device_id:device},request);report({event:'control-replay',method,replay});
      };
      await act('acquireControl','control.acquire');await act('releaseControl','control.release');
    }
    let observed;if(current.state==='admitted_closed'&&input.mode!=='supervisor_create_module_control'&&
      !(input.mode.includes('_dispatch_ready')&&executionClient.state.phase==='closed')){observed=await source.observeWorker(intent);source.assertWorkerObservation(observed);report({event:'observed',receipt:observed.receipt});
      try{source.assertWorkerObservation(structuredClone(observed));report({event:'copied-observation',code:'unexpected_success'});}catch(error){report({event:'copied-observation',code:error.code});}}
    try{if(business)await business.workerLaunches.authorization.create(key,{load_id:held.load_id,...proof});else await source.createWorker({key,authorization:authorization(),load_id:held.load_id,...proof});report({event:'duplicate',code:'unexpected_success'});}
    catch(error){report({event:'duplicate',code:error.code});}
    if(business){manager.sessions.revokeExtensionApproval(manager.token(),{request_id:'runtime.deny',approval_ref:input.runtime.approved.approval_ref,reason:'人员撤销'});await business.workerLaunches.authorization.synchronize();}
    else if(input.mode!=='supervisor_create_deny_pending')await source.putFence(fence('2','deny'));report({event:'denied',record:await source.queryLaunch(key)});
    if(moduleClient){try{moduleClient.currentBaseline(intent.object_scope.device_ids[0]);report({event:'catalog-revoked',code:'unexpected_success'});}catch(error){report({event:'catalog-revoked',code:error.code});}
      if(controlFlow){
        try{moduleClient.bindExecution(intent.object_scope.device_ids[0]);report({event:'execution-revoked',code:'unexpected_success'});}catch(error){report({event:'execution-revoked',code:error.code});}
      }
      try{await moduleClient.captureBaseline(intent.object_scope.device_ids[0]);report({event:'module-revoked',code:'unexpected_success'});}
      catch(error){report({event:'module-revoked',code:error.code});}}

    if(observed){try{source.assertWorkerObservation(observed);report({event:'withdrawn-observation',code:'unexpected_success'});}catch(error){report({event:'withdrawn-observation',code:error.code});}}
    if(business){try{business.workerLaunches.runtime.current(key);}catch{}report({event:'runtime-withdrawn',binding:business.workerLaunches.runtime.query(key)});}
    if(business&&input.mode.endsWith('_capabilities')){try{business.workerLaunches.deviceAutomation(intent.object_scope.device_ids[0]);report({event:'automation-bindings-withdrawn',code:'unexpected_success'});}catch(error){report({event:'automation-bindings-withdrawn',code:error.code});}}
    if(bindingPeer)await bindingPeer.phase('withdrawn',{running:false});
    if(!omitRetirementRequest){
      const retirementDeadline=performance.now()+5000;
      for(;;){try{report({event:'retired',result:await source.retireWorker(intent,'revoked')});break;}
        catch(error){if(error.code!=='supervisor_indeterminate'||performance.now()>=retirementDeadline)throw error;await delay(25);}}
    }
    if(input.reference_acceptance){
      if(!input.mode.includes('_reference_restart'))await referencePublication.reconcileProtection();
      report({event:'command-reference-exit-retired',protection:referencePublication.protectionStatus()});
    }
  }
  }
  if(input.mode==='supervisor_deny')await source.putFence(fence('2','deny'));
  try{const released=await held.release();report({event:'released',status:released.status});}
  catch(error){
    if(!omitRetirementRequest || error.code!=='supervisor_indeterminate')throw error;
    report({event:'release-unproven',code:error.code});
  }
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
}catch(error){report({event:'unavailable',code:error.code,message:error.message,cause:error.cause?.code,stack:error.stack,errors:error.errors?.map(e=>e.code),
 ...(input.mode.includes('_dispatch_ready')?{execution_state:executionClient?.state}:{})});
 if(input.mode.startsWith('supervisor_create_module')){
  const until=performance.now()+5000;
  for(;;){try{report({event:'module-failed-retired',result:await source.retireWorker(intent,'revoked')});break;}
   catch(error){if(error.code!=='supervisor_indeterminate'||performance.now()>=until)throw error;await delay(25);}}
 }
}
if(input.gui){guiTimer=setInterval(()=>{
 if(!fs.existsSync(input.gui.revoke_request))return;clearInterval(guiTimer);
 try{const current=manager.sessions.localPermissions(manager.auth);
  const changed=manager.sessions.replaceLocalPermissions(manager.auth,{request_id:crypto.randomUUID(),principal_id:manager.logged.session.principal_id,
   expected_revision:current.revision,permissions:current.permissions.filter(permission=>permission!=='command.evidence.read')});
  fs.writeFileSync(input.gui.revoke_result,JSON.stringify({state:'revoked',result:changed}));report({event:'gui-evidence-revoked'});
 }catch(error){fs.writeFileSync(input.gui.revoke_result,JSON.stringify({state:'failed',code:error.code}));}
},50);guiTimer.unref();}
await bindingPeer?.close();
report({event:'done',record:await source.queryLaunch(key)});
await performanceCapture.stop();
scheduling?.disable();
process.stdin.setEncoding('utf8').on('data',data=>{if(data==='stop\n'){clearInterval(guiTimer);commandAgent?.destroy();commandServer?.close();manager?.real.stop();intakeClient?.close();business?.close();referenceLink?.close();source.close();process.stdin.destroy();}});process.stdin.resume();
