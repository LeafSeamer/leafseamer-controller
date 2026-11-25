import assert from 'node:assert/strict';
import https from 'node:https';
import {once} from 'node:events';
import {createAuthenticationHttp} from '../../dist/auth-http.mjs';
import {createIntrospectionEndpoint} from '../../dist/introspection-http.mjs';
import {createLocalPairingManagement} from '../../dist/local-pairing-management.mjs';
import {inspectLinuxClockEvidence,readLinuxClockEvidenceProfile} from '../../dist/linux-clock-evidence.mjs';
import {startPeerPairingTransport} from '../../dist/peer-pairing-transport.mjs';
import {readProtectedIngressProfile} from '../../dist/protected-ingress-profile.mjs';
import {createSubscriptionEndpoint} from '../../dist/service-subscription-http.mjs';
import {openLinuxReferenceProvider} from '../../dist/linux-reference-provider.mjs';
import {readInstalledLinuxReferenceCapture} from '../../dist/linux-reference-capture.mjs';
import {openTimeProviderLink} from '../../dist/time-provider-link.mjs';
import {openReferenceCaptureRuntime} from '../../dist/reference-capture-runtime.mjs';
import {readTrustedPairingProfile} from '../../dist/trusted-pairing-profile.mjs';

function argument(flag){
  const index=process.argv.indexOf(flag);
  assert.ok(index>=3&&typeof process.argv[index+1]==='string',flag);
  return process.argv[index+1];
}

export function simulatorPairingInputs(store,runtime,source){
  const {policy,signal}=runtime;
  const clockProfile=readLinuxClockEvidenceProfile(argument('--clock-evidence-profile'),policy,'controller');
  assert.equal(clockProfile.authentication,true);
  const provider=inspectLinuxClockEvidence(clockProfile,store.authenticationClock.scope,runtime,source);
  const profile=readTrustedPairingProfile(argument('--pairing-profile'),'127.0.0.1',8444,{linux:true});
  assert.deepEqual(profile.policy,policy);
  return {profile,evidence:{provider,signal}};
}

export async function admitSimulatorReference(t,{store,runtime,clock}){
  const artifactDigest=argument('--reference-provider');
  const authorization=readInstalledLinuxReferenceCapture({identity:store.identity,providerDigest:artifactDigest,
    approvalDigest:argument('--reference-capture')});
  const provider=await openLinuxReferenceProvider({core:runtime.binding,artifactDigest,
    timeoutMs:runtime.policy.bootstrap_timeout_ms,assertLive:runtime.assertLive});
  t.after(()=>provider.socket.destroy());
  return {provider,async start(authentication,binding){
    const assertCurrent=()=>{runtime.assertLive();provider.assertCurrent();};
    const link=await openTimeProviderLink(binding,{connection:provider.socket,assertCurrent,readAuthentication(){
      try{return authentication.referenceTimeSample();}catch{return null;}
    }});
    t.after(()=>link.close());
    const {publication,scheduler}=openReferenceCaptureRuntime({storage:store,authorization,authentication,link,assertCurrent,
      observeRetirement:original=>provider.observeRetirement?.(original,clock.tick)??null,
      assertRetirement:provider.assertRetirement});
    assert.ok(publication&&scheduler);
    t.after(async()=>{
      const stopped=scheduler.close();
      link.quiesce();
      try{publication.invalidate('shutdown');}finally{await stopped;}
    });
    scheduler.start();
    return publication;
  }};
}

export async function startSimulatorPairing(t,{store,sessions,real,profile,assertCurrent,reference=null,openTarget=null}){
  let targetOpening;
  const commands=openTarget?sessions.runPreparations.automationCommands:null;
  assert.ok(!openTarget||commands);
  const {service_id,database_instance_id}=store.identity,{issuer_id,issuer_epoch}=store.enrollment.summary();
  const {peers,...settings}=profile.pairing;
  const identity={service_id,database_instance_id,service_kind:'controller',issuer_id,issuer_epoch,credential_id:settings.credential_id};
  const authenticationScope={serviceId:service_id,databaseInstanceId:database_instance_id,serviceBootId:store.serviceBootId,sessions};
  const introspection=createIntrospectionEndpoint(authenticationScope);
  const transport=await startPeerPairingTransport({...settings,identity,pairings:sessions.peerPairings,
    clock:{pairingSample(){assertCurrent();return real.pairingSample();}},
    subscriptions:createSubscriptionEndpoint({store:sessions.serviceSubscriptions,serviceBootId:store.serviceBootId,readReferenceBundle:reference?.readBundle}),
    deviceBindings(...args){assertCurrent();return store.workerLaunches.deviceAutomation(...args);},
    deviceEvents(...args){assertCurrent();return store.workerLaunches.deviceEvents(...args);},
    automationApproval(...args){assertCurrent();return sessions.currentAutomationServiceApproval(...args);},
    runEndorsement(...args){assertCurrent();return sessions.runApprovalEndorsements.readForPeer(...args);},
    runControlObservation(...args){assertCurrent();return sessions.runApprovalEndorsements.readControlsForPeer(...args);},
    runPreparations:{
      async prepare(...args){
        assertCurrent();
        try{
          const prepared=await sessions.runPreparations.prepare(...args);
          assertCurrent();
          return prepared;
        }catch(error){
          process.stdout.write(JSON.stringify({event:'simulator_preparation_failed',code:error.code??error.name})+'\n');
          throw error;
        }
      },
      lookup(...args){assertCurrent();return sessions.runPreparations.lookup(...args);},
      async prepareEligibility(...args){
        assertCurrent();
        try{
          if(openTarget&&args[2].schedule_device_ids){
            targetOpening??=openTarget();
            await targetOpening;
          }
          const support=await sessions.runPreparations.prepareEligibility(...args);
          return {body:support.body,beforeSend(){assertCurrent();return support.beforeSend();}};
        }catch(error){
          process.stdout.write(JSON.stringify({event:'simulator_eligibility_failed',code:error.code??error.name})+'\n');
          throw error;
        }
      }
    },
    automationCommands:commands?{
      async submit(...args){
        assertCurrent();
        assert.ok(targetOpening);
        await targetOpening;
        const result=await commands.submit(...args);
        assertCurrent();
        if(result.created&&result.adjudication.command_ref){
          const id=result.adjudication.command_ref.object_id;
          for(const [stage,method] of [['guard','whenCommandGuarded'],['settlement','whenCommandSettled']]){
            Promise.resolve().then(()=>store.workerLaunches[method](id)).catch(error=>{
              process.stdout.write(JSON.stringify({event:'simulator_scheduled_command_failed',stage,
                code:error.code??error.message,cause:error.cause?.code??null})+'\n');
            });
          }
        }
        return result;
      },
      lookup(...args){assertCurrent();return commands.lookup(...args);},
      result(...args){assertCurrent();return commands.result(...args);},
      reject(...args){assertCurrent();return commands.reject(...args);}
    }:null,
    async introspection(request){
      assertCurrent();
      const reply=await introspection(request);
      return {...reply,beforeSend(){assertCurrent();reply.beforeSend();}};
    }});
  t.after(()=>transport.close());
  transport.bindPeers(peers);
  sessions.runEndorsementPolicies.bindProposalReader(transport.readRunApprovalProposal);
  sessions.runApprovalEndorsements.bindApprovalReader(transport.readRunApproval);
  sessions.runApprovalEndorsements.bindInitiatorReader(transport.readRunInitiator);
  sessions.runPreparations.bindPlanReader(transport.prepareRunArmPlan);
  if(commands)sessions.runPreparations.bindActionReader(transport.prepareRunActionBinding);
  const {host,port,tls}=readProtectedIngressProfile(argument('--ingress-profile'));
  const ingress=createAuthenticationHttp({...authenticationScope,origin:tls.origin});
  const listener=https.createServer({cert:tls.cert,key:tls.key,minVersion:'TLSv1.2'},(req,res)=>{
    try{assertCurrent();}catch{res.writeHead(503).end();return;}
    if(!ingress.handle(req,res))res.writeHead(404).end();
  });
  listener.listen(port,host);await once(listener,'listening');
  t.after(()=>new Promise(resolve=>{listener.close(resolve);listener.closeAllConnections();}));
  return createLocalPairingManagement({sessions,serviceId:service_id,transport:()=>transport,assertCurrent});
}
