// 仅集成测试的可信装配；RPC文件位于用例私有临时目录，不打包为产品入口。
import fs from 'node:fs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {setTimeout as delay} from 'node:timers/promises';
import {startPeerPairingTransport} from '../../dist/peer-pairing-transport.mjs';
import {createIntrospectionEndpoint} from '../../dist/introspection-http.mjs';
import {createSubscriptionEndpoint} from '../../dist/service-subscription-http.mjs';
import {startRunProtectionDelivery} from '../../dist/run-approval-protection-completion.mjs';
export async function automationPeer({business,manager,config,device,refresh,report,publishBufferedEvent=null,configurePublicationGui=null,readReferenceBundle=null,
 openArmTarget=null,publishArmedEvent=null,readExecutionState=null}){
 const identity={service_id:business.identity.service_id,database_instance_id:business.identity.database_instance_id,service_kind:'controller',
  issuer_id:manager.logged.session.issuer_id,issuer_epoch:manager.logged.session.issuer_epoch,credential_id:crypto.randomUUID()};
 let failureCount=0;const trace=(name,fn)=>(...args)=>{const failed=error=>{if(failureCount++<32)report({event:'peer-transport-failure',method:name,code:error.code,stack:error.stack});throw error;};try{const value=fn(...args);return value?.then?value.catch(failed):value;}catch(error){return failed(error);}};
 const subscriptionEndpoint=manager.sessions.serviceSubscriptions?createSubscriptionEndpoint({store:manager.sessions.serviceSubscriptions,
  readReferenceBundle,serviceBootId:business.serviceBootId}):null;
 const subscriptions=subscriptionEndpoint?{...subscriptionEndpoint,sweep:trace('sweep',()=>subscriptionEndpoint.sweep()),handle:trace('handle',async args=>{const reply=await subscriptionEndpoint.handle(args);return {...reply,beforeSend:trace('beforeSend',()=>reply.beforeSend())};}),channel:{...subscriptionEndpoint.channel,open(...args){const app=subscriptionEndpoint.channel.open(...args);return Object.fromEntries(Object.entries(app).map(([name,fn])=>[name,trace('channel.'+name,fn)]));}}}:null;
 const endorsements=manager.sessions.runApprovalEndorsements,policies=manager.sessions.runEndorsementPolicies,preparations=manager.sessions.runPreparations;
 const commands=preparations?.automationCommands;
 let armedEventRequested=false,triggerPlanGrant=null,targetOpening=null;
 async function prepareEligibility(binding,socket,request,options){
  if(options?.recovery)return preparations.prepareEligibility(binding,socket,request,options);
  if(config.scheduled_admission&&request.schedule_device_ids){
   targetOpening??=openArmTarget();
   await targetOpening;
  }
  if(!armedEventRequested)return preparations.prepareEligibility(binding,socket,request);
  const grant=canonicalize(request);
  // 首次查验用于封存触发计划，后一次才是同一计划首动作的资格查验。
  if(grant===triggerPlanGrant&&!targetOpening){
   targetOpening=openArmTarget();
   targetOpening.catch(()=>{});
  }
  const eligible=await preparations.prepareEligibility(binding,socket,request);
  triggerPlanGrant??=grant;
  return eligible;
 }
 const api=manager.sessions.peerPairings,transport=await startPeerPairingTransport({pairings:{...api,currentPending:trace('currentPending',id=>api.currentPending(id))},clock:{pairingSample:trace('pairingSample',()=>manager.real.pairingSample())},identity,...config.material,ca:config.ca,
  deviceBindings:(id,expected)=>business.workerLaunches.deviceAutomation(id,expected),
  deviceEvents:(id,expected,after,limit)=>business.workerLaunches.deviceEvents(id,expected,after,limit),
  subscriptions,
  automationApproval:endorsements?trace('automationApproval',manager.sessions.currentAutomationServiceApproval):null,
  runEndorsement:endorsements?trace('runEndorsement',endorsements.readForPeer):null,
  runControlObservation:endorsements?trace('runControlObservation',endorsements.readControlsForPeer):null,
  runPreparations:preparations?{prepare:trace('prepareRun',preparations.prepare),lookup:trace('lookupRunPreparation',preparations.lookup),
   prepareEligibility:trace('prepareRunEligibility',prepareEligibility)}:null,
  automationCommands:commands&&(publishArmedEvent||config.scheduled_admission)?{...commands,submit:trace('submitAutomationCommand',async(...args)=>{
   if(!targetOpening)throw Error('automation_target_opening_missing');
   await targetOpening;
   const response=await commands.submit(...args),reference=response.adjudication.command_ref;
   if(response.created&&reference){
    report({event:'automation-target-accepted',reference});
    if(config.scheduled_admission&&!config.scheduled_dispatch)return response;
    for(const [stage,method] of [['encoded','whenCommandEncoded'],['finalized','whenCommandFinalized'],['guarded','whenCommandGuarded'],['dispatched','whenCommandDispatched']]){
     business.workerLaunches[method](reference.object_id).then(result=>{
      report({event:'automation-target-stage',stage,present:result!=null,disposition:result?.response?.value?.disposition??result?.ack?.value?.disposition});
     },error=>report({event:'automation-target-stage-failed',stage,code:error.code??error.name,cause:error.cause?.code,constraint:error.code==='SQLITE_CONSTRAINT_TRIGGER'?error.message:undefined}));
    }
    business.workerLaunches.whenCommandSettled(reference.object_id).then(result=>report(result?{event:'automation-target-settled',reference}:
     {event:'automation-target-failed',reference,code:'execution_settlement_ineligible'}),
     error=>report({event:'automation-target-failed',reference,code:error.code,cause:error.cause?.code,close_reason:readExecutionState?.()?.close_reason}));
   }
   return response;
  })}:commands??null,
  runApprovalProtection:endorsements?.receiveProtection?trace('runApprovalProtection',endorsements.receiveProtection):null,
  introspection:createIntrospectionEndpoint({sessions:manager.sessions,serviceId:identity.service_id,serviceBootId:business.serviceBootId})});
 policies?.bindProposalReader(transport.readRunApprovalProposal);
 endorsements?.bindApprovalReader(transport.readRunApproval);
 endorsements?.bindInitiatorReader((bindingId,ref)=>ref.kind==='recovery_operation'?
  transport.readRunRecoveryInitiator(bindingId,ref):transport.readRunInitiator(bindingId,ref));
 preparations?.bindPlanReader(trace('readPreparationPlan',(bindingId,ref)=>ref.kind==='recovery_plan'?
  transport.prepareRunRecoveryPlan(bindingId,ref):transport.prepareRunArmPlan(bindingId,ref)));
 if(preparations?.automationCommands)preparations.bindActionReader(trace('readActionBinding',transport.prepareRunActionBinding));
 let closing=false;
 const protectionDelivery=startRunProtectionDelivery({endorsements,workerLaunches:business.workerLaunches,
  assertCurrent(){if(closing)throw new Error('controller_closing');}});
 async function execute(command,value){
  if(command==='bind'){transport.bindPeers(value);return true;}
  if(command==='stage')return api.stage(manager.auth,value);
  if(command==='get')return api.get(manager.auth,value);
  if(command==='exportFirstPairing')return api.exportFirstPairingAuthorization(manager.auth,value);
  if(command==='configurePublicationGui'&&configurePublicationGui){configurePublicationGui(value);return true;}
  if(command==='prove')return transport.prove(value);
  if(command==='activate')return api.activate(manager.auth,value);
  if(command==='registerEventScope')return business.workerLaunches.eventScopes.register(value);
  if(command==='currentEventScope')return business.workerLaunches.eventScopes.current(value);
  if(command==='sourceSnapshotCut')return business.workerLaunches.eventScopes.snapshotCut(value);
  if(command==='publishBufferedEvent'&&publishBufferedEvent)return publishBufferedEvent();
  if(command==='openArmTarget'&&openArmTarget)return openArmTarget();
  if(command==='publishArmedEvent'&&publishArmedEvent){armedEventRequested=true;return publishArmedEvent();}
  if(command==='revokeEventScope')return business.workerLaunches.eventScopes.revoke(value);
  if(command==='createConsumer')return manager.sessions.createServicePrincipal(manager.auth,{request_id:crypto.randomUUID(),display_name:'集成消费者',purpose:'event_consumer'});
  if(command==='approveConsumer')return manager.sessions.approveSubscriptionServicePrincipal(manager.auth,value);
  if(command==='approveConsumerPolicy')return manager.sessions.approveLocalSubscriptionPolicy(manager.auth,value);
  if(command==='revokeConsumerPolicy')return manager.sessions.revokeLocalServicePolicy(manager.auth,value);
  if(command==='currentConsumer')return manager.sessions.currentServiceConsumer(value);
  if(command==='revokeConsumer')return manager.sessions.revokeServicePrincipal(manager.auth,value);
  if(command==='createAutomationPrincipal')return manager.sessions.createServicePrincipal(manager.auth,{request_id:crypto.randomUUID(),display_name:'集成自动化',purpose:'automation'});
  if(command==='approveAutomationPrincipal')return manager.sessions.approveAutomationServicePrincipal(manager.auth,value);
  if(command==='replaceEndorsementPolicy')return policies.replace(manager.auth,value);
  if(command==='endorseRun'){
   const token=manager.token(['request.create','grant.manage','grant.read']);
   const context=manager.sessions.createEndorsementContext(token,{ttl_ms:30000,max_unique_requests:1});
   return endorsements.endorse(token,{...value,context_id:context.context_id,idempotency_key:crypto.randomUUID()});
  }
  if(command==='checkRunApproval')return (await endorsements.prepareRunApproval(value.binding_id,value.approval_ref)).eligibility;
  if(command==='readRunInitiator')return transport.readRunInitiator(value.binding_id,value.operation_ref);
  if(command==='issueIdentity'){
   const record=api.get(manager.auth,value),now=manager.real.current(),permissions=['auth.manage','auth.read','request.create','request.read','definition.read','definition.edit'];
   if(config.incremental_source_event){
    permissions.push('definition.publish','run.approve','run.arm','run.manage','run.read');
    if(config.scheduled_admission)permissions.push('schedule.read','schedule.publish','schedule.activate');
    if(config.recovery_reconciliation)permissions.push('run.approval.revoke','run.resume');
    const current=manager.sessions.localPermissions(manager.auth),principal_id=manager.logged.session.principal_id;
    if(!current.permissions.includes('grant.manage'))manager.sessions.replaceLocalPermissions(manager.auth,{request_id:crypto.randomUUID(),principal_id,
     expected_revision:current.revision,permissions:[...current.permissions,'grant.manage','grant.read']});
   }
   manager.sessions.remotePermissions.replace(manager.auth,{request_id:crypto.randomUUID(),principal_id:manager.logged.session.principal_id,audience:record.peer_service_id,
    pairing_ref:{id:record.binding_id,revision:record.revision,digest:record.digest},expected_revision:null,permissions,
    not_before_ns:String(BigInt(now.lower_ns)>BigInt(record.not_before_ns)?BigInt(now.lower_ns):BigInt(record.not_before_ns)),
    expires_ns:String(BigInt(now.upper_ns)+60000000000n<BigInt(record.expires_ns)?BigInt(now.upper_ns)+60000000000n:BigInt(record.expires_ns))});
   const result=await manager.sessions.issueToken(manager.auth,{request_id:crypto.randomUUID(),audience:record.peer_service_id,requested_scopes:permissions});
   return {token:'v1.'+result.token.token_id+'.'+result.secret,principal_id:manager.logged.session.principal_id};
  }
  if(command==='finish')return true;
  throw new Error('automation_peer_command');
 }
 return {async close(){closing=true;await protectionDelivery?.close();await transport.close();},async phase(name,{running=true}={}){
  report({event:'binding-peer-phase',phase:name,pid:process.pid,identity,origin:transport.origin,configuration:transport.configuration,principal_id:manager.logged.session.principal_id,device_id:device});
  const deadline=performance.now()+(config.native_receiver_age?100000:60000);let refreshed=0;
  for(;;){
   if(performance.now()>=deadline)throw new Error('automation_peer_phase_timeout');
   if(running&&performance.now()-refreshed>400){await refresh();refreshed=performance.now();}
   if(fs.existsSync(config.request)){
    const request=JSON.parse(fs.readFileSync(config.request,'utf8'));fs.unlinkSync(config.request);let reply;
   try{reply={id:request.id,ok:true,value:await execute(request.command,request.value)};}catch(error){
    if(publishArmedEvent)report({event:'native-automation-rpc-failed',command:request.command,code:error.code,stack:error.stack});
    reply={id:request.id,ok:false,error:{code:error.code,message:error.message,...(publishArmedEvent&&{stack:error.stack})}};
   }
    fs.writeFileSync(config.response,JSON.stringify(reply));if(request.command==='finish')return;
   }
   await delay(15);
  }
 }};
}
