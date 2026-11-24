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

export async function startSimulatorPairing(t,{store,sessions,real,profile,assertCurrent}){
  const {service_id,database_instance_id}=store.identity,{issuer_id,issuer_epoch}=store.enrollment.summary();
  const {peers,...settings}=profile.pairing;
  const identity={service_id,database_instance_id,service_kind:'controller',issuer_id,issuer_epoch,credential_id:settings.credential_id};
  const authenticationScope={serviceId:service_id,databaseInstanceId:database_instance_id,serviceBootId:store.serviceBootId,sessions};
  const introspection=createIntrospectionEndpoint(authenticationScope);
  const transport=await startPeerPairingTransport({...settings,identity,pairings:sessions.peerPairings,
    clock:{pairingSample(){assertCurrent();return real.pairingSample();}},
    subscriptions:createSubscriptionEndpoint({store:sessions.serviceSubscriptions,serviceBootId:store.serviceBootId}),
    deviceEvents(...args){assertCurrent();return store.workerLaunches.deviceEvents(...args);},
    async introspection(request){
      assertCurrent();
      const reply=await introspection(request);
      return {...reply,beforeSend(){assertCurrent();reply.beforeSend();}};
    }});
  t.after(()=>transport.close());
  transport.bindPeers(peers);
  const {host,port,tls}=readProtectedIngressProfile(argument('--ingress-profile'));
  const ingress=createAuthenticationHttp({...authenticationScope,origin:tls.origin});
  const listener=https.createServer({cert:tls.cert,key:tls.key,minVersion:'TLSv1.2'},(req,res)=>{
    try{assertCurrent();}catch{res.writeHead(503).end();return;}
    if(!ingress.handle(req,res))res.writeHead(404).end();
  });
  listener.listen(port,host);await once(listener,'listening');
  t.after(()=>new Promise(resolve=>{listener.close(resolve);listener.closeAllConnections();}));
  return createLocalPairingManagement({sessions,transport:()=>transport,assertCurrent});
}
