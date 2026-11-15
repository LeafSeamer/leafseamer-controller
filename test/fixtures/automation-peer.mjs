// 仅集成测试的可信装配；RPC文件位于用例私有临时目录，不打包为产品入口。
import fs from 'node:fs';
import crypto from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {startPeerPairingTransport} from '../../dist/peer-pairing-transport.mjs';
import {createIntrospectionEndpoint} from '../../dist/introspection-http.mjs';
import {createSubscriptionEndpoint} from '../../dist/service-subscription-http.mjs';
export async function automationPeer({business,manager,config,device,refresh,report}){
 const identity={service_id:business.identity.service_id,database_instance_id:business.identity.database_instance_id,service_kind:'controller',
  issuer_id:manager.logged.session.issuer_id,issuer_epoch:manager.logged.session.issuer_epoch,credential_id:crypto.randomUUID()};
 let failureCount=0;const trace=(name,fn)=>(...args)=>{const failed=error=>{if(failureCount++<32)report({event:'peer-transport-failure',method:name,code:error.code,stack:error.stack});throw error;};try{const value=fn(...args);return value?.then?value.catch(failed):value;}catch(error){return failed(error);}};
 const subscriptionEndpoint=manager.sessions.serviceSubscriptions?createSubscriptionEndpoint({store:manager.sessions.serviceSubscriptions}):null;
 const subscriptions=subscriptionEndpoint?{...subscriptionEndpoint,sweep:trace('sweep',()=>subscriptionEndpoint.sweep()),handle:trace('handle',async args=>{const reply=await subscriptionEndpoint.handle(args);return {...reply,beforeSend:trace('beforeSend',()=>reply.beforeSend())};}),channel:{...subscriptionEndpoint.channel,open(...args){const app=subscriptionEndpoint.channel.open(...args);return Object.fromEntries(Object.entries(app).map(([name,fn])=>[name,trace('channel.'+name,fn)]));}}}:null;
 const api=manager.sessions.peerPairings,transport=await startPeerPairingTransport({pairings:{...api,currentPending:trace('currentPending',id=>api.currentPending(id))},clock:{pairingSample:trace('pairingSample',()=>manager.real.pairingSample())},identity,...config.material,ca:config.ca,
  deviceBindings:(id,expected)=>business.workerLaunches.deviceAutomation(id,expected),
  deviceEvents:(id,expected,after,limit)=>business.workerLaunches.deviceEvents(id,expected,after,limit),
  subscriptions,
  introspection:createIntrospectionEndpoint({sessions:manager.sessions,serviceId:identity.service_id,serviceBootId:business.serviceBootId})});
 async function execute(command,value){
  if(command==='bind'){transport.bindPeers(value);return true;}
  if(command==='stage')return api.stage(manager.auth,value);
  if(command==='get')return api.get(manager.auth,value);
  if(command==='prove')return transport.prove(value);
  if(command==='activate')return api.activate(manager.auth,value);
  if(command==='registerEventScope')return business.workerLaunches.eventScopes.register(value);
  if(command==='currentEventScope')return business.workerLaunches.eventScopes.current(value);
  if(command==='sourceSnapshotCut')return business.workerLaunches.eventScopes.snapshotCut(value);
  if(command==='revokeEventScope')return business.workerLaunches.eventScopes.revoke(value);
  if(command==='createConsumer')return manager.sessions.createServicePrincipal(manager.auth,{request_id:crypto.randomUUID(),display_name:'集成消费者',purpose:'event_consumer'});
  if(command==='approveConsumer')return manager.sessions.approveSubscriptionServicePrincipal(manager.auth,value);
  if(command==='approveConsumerPolicy')return manager.sessions.approveLocalSubscriptionPolicy(manager.auth,value);
  if(command==='revokeConsumerPolicy')return manager.sessions.revokeLocalServicePolicy(manager.auth,value);
  if(command==='currentConsumer')return manager.sessions.currentServiceConsumer(value);
  if(command==='revokeConsumer')return manager.sessions.revokeServicePrincipal(manager.auth,value);
  if(command==='issueIdentity'){
   const record=api.get(manager.auth,value),now=manager.real.current(),permissions=['auth.manage','auth.read','request.create','request.read','definition.read','definition.edit'];
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
 return {close:()=>transport.close(),async phase(name,{running=true}={}){
  report({event:'binding-peer-phase',phase:name,pid:process.pid,identity,origin:transport.origin,configuration:transport.configuration,principal_id:manager.logged.session.principal_id,device_id:device});
  const deadline=performance.now()+60000;let refreshed=0;
  for(;;){
   if(performance.now()>=deadline)throw new Error('automation_peer_phase_timeout');
   if(running&&performance.now()-refreshed>400){await refresh();refreshed=performance.now();}
   if(fs.existsSync(config.request)){
    const request=JSON.parse(fs.readFileSync(config.request,'utf8'));fs.unlinkSync(config.request);let reply;
    try{reply={id:request.id,ok:true,value:await execute(request.command,request.value)};}catch(error){reply={id:request.id,ok:false,error:{code:error.code,message:error.message}};}
    fs.writeFileSync(config.response,JSON.stringify(reply));if(request.command==='finish')return;
   }
   await delay(15);
  }
 }};
}
