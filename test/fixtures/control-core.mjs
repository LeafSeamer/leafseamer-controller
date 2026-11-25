import net from 'node:net';
import dgram from 'node:dgram';
import {once} from 'node:events';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import canonicalize from 'canonicalize';
import crypto from 'node:crypto';
import {connectCoreSupervisor} from '../../dist/supervisor-control.mjs';
import {openNativeClock} from '../../dist/native-clock.mjs';
import {createCoreBootstrapChannel, verifyCoreAdmission} from '../../dist/core-bootstrap.mjs';
import {openTimeProviderLink} from '../../dist/time-provider-link.mjs';
import {openStorage} from '../../dist/storage.mjs';
import {startAuthenticationClock} from '../../dist/auth-clock.mjs';
import {startController} from '../../dist/server.mjs';
import {referenceBundleAuthority} from './reference-bundle-authority.mjs';
import {fixture as authenticationFixture} from '../auth-clock-fixture.mjs';
import {decodeWorkerControl as decodeSupervisorControl, workerControlVersion as supervisorControlVersion} from '../../dist/sdk/worker-runtime.mjs';
const args = process.argv.slice(3), options = Object.fromEntries(Array.from({length: args.length / 2}, (_, i) => [args[i * 2], args[i * 2 + 1]]));
const bootstrap = createCoreBootstrapChannel(process.stdin, process.stdout, {timeoutMs: 10000});
const assignment = await bootstrap.assignment(), receipt = await bootstrap.proveAndReceive(assignment); bootstrap.release();
const policy = JSON.parse(options['--bootstrap-policy']), mode = options['--mode'];
const controlMode=['time-provider-control','time-provider-control-resume','time-provider-control-write-fault'].includes(mode);
const scheduleMode=['time-provider-schedule','time-provider-schedule-restart','time-provider-schedule-close'].includes(mode);
const invalidationSource=mode==='time-provider-invalidation-source';
const invalidationMode=invalidationSource||['time-provider-invalidation','time-provider-invalidation-write-fault'].includes(mode);
const anchorMode=scheduleMode||invalidationMode||['time-provider-anchor','time-provider-anchor-reopen','time-provider-anchor-write-fault'].includes(mode);
process.stderr.write(JSON.stringify({event: 'bootstrapped', pid: process.pid}) + '\n');
if(controlMode||anchorMode||['time-provider-capture','time-provider-capture-restart','time-provider-capture-rollback','time-provider-capture-repeat',
 'time-provider-capture-resume','time-provider-ack-fault'].includes(mode)){
 const binding=await verifyCoreAdmission(assignment,receipt,policy),native=openNativeClock();
 const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],policy,
  timeProviderIntent:options['--time-provider-intent'],binding});
 const udp=dgram.createSocket('udp4');
 udp.bind(Number(options['--fixture-port']??0),'127.0.0.1');
 await once(udp,'listening');
 const network={authentication:'trusted_network',endpoint:'127.0.0.1:'+udp.address().port};
 const digest=body=>'sha256:'+crypto.createHash('sha256').update(body).digest('hex');
 const ref=(id,value='sha256:'+'1'.repeat(64))=>({id,revision:'1',digest:value});
 const key=crypto.createSecretKey(crypto.createHash('sha256').update('isolated archive fixture').digest());
 const wrongKey=crypto.createSecretKey(crypto.createHash('sha256').update('different isolated archive fixture').digest());
 let wrongRead=false, wrongWrite=false;
 let revoke=false, revokedReads=0, mismatchedEndpoint=false, received=0, attemptedBeforeUDP=false;
 const packet=Promise.withResolvers();
 const eraBoundary=((1n<<32n)-2208988800n)*1000000000n;
 const approvalDeadline=String(native.tick()+90000000000n);
 const withBundle=mode==='time-provider-anchor'||invalidationSource;
 let omitEvidence=mode==='time-provider-anchor', approvalWithdrawn=false;
 const bundleAuthority=withBundle?referenceBundleAuthority({serviceId:policy.service_id,configuration:ref('configuration.loopback'),
  timeBounds:{lower_ns:String(eraBoundary-1000000000n),upper_ns:String(eraBoundary+1000000000n)},
  ...(invalidationSource&&{maxAnchorAge:'45000000000',maxExchangeAge:'45000000000',maxUpstreamAge:'50000000000'})}):null;
 const referenceAuthority={sourceSlot:'source.capture',
  readApproval({authorization}){
   if(approvalWithdrawn)return null;
   const {source_digest,configuration_ref,approval_ref}=authorization;
   return {format:'leafseamer-reference-approval/1',source_digest,configuration_ref,approval_ref,authentication:'trusted_network',
    profile_ref:withBundle?bundleAuthority.references.profile_ref:ref('profile.reference'),policy_ref:withBundle?bundleAuthority.references.policy_ref:ref('policy.reference'),time_scale:'UTC',leap_mode:'normal_only',smear:false,
    elapsed_error_ppm:0,span_quantization_ns:'1000',max_span_ns:'2000000000',max_anchor_age_ns:invalidationMode?'45000000000':'5000000000',
    max_exchange_age_ns:invalidationMode?'45000000000':'5000000000',max_upstream_age_ns:invalidationMode?'50000000000':'10000000000',
    max_half_width_ns:'1000000000',valid_before_tick_ns:approvalDeadline};
  },
  readEvidence(input){
   if(omitEvidence)return null;
   const {exchange_digest}=input;
   const proofs=withBundle?bundleAuthority.proofs(input):{authentication_ref:ref('evidence.reference-authentication'),
    error_ref:ref('evidence.reference-error'),era_ref:ref('evidence.reference-era')};
   return {format:'leafseamer-reference-evidence/1',exchange_digest,...proofs,
    independent_utc_lower_ns:String(eraBoundary-1000000000n),independent_utc_upper_ns:String(eraBoundary+1000000000n),
    t2_error_ns:'1000',t3_error_ns:'1000',upstream_age_at_m1_ns:'1000',valid_before_tick_ns:approvalDeadline};
  },...(withBundle&&{readBundleOriginals:bundleAuthority.readBundleOriginals})};
 const app=await startController({dataDir:options['--data-dir'],coreBootstrap:async()=>({binding,policy,supervision:source}),
  authenticationProvider:({scope,source})=>authenticationFixture(scope,{source,descriptor:binding.descriptor},
   {sampleWindowPolicy:'authentication-clock-sample/2'}).provider,
  referenceTimeAuthorization:{limits:{max_outstanding:controlMode||mode==='time-provider-capture-repeat'||mode==='time-provider-capture-resume'?1:4,
   max_reserved_bytes:mode==='time-provider-capture-resume'?65536:32768},
   readSource(slot){
    const lost=slot==='source.revoked'&&revoke&&++revokedReads>=4;
    const stable=slot==='source.rate-alias'?'source.rate':slot==='source.capture-alias'?'source.capture':slot;
    return {source_slot:slot,source_digest:withBundle?bundleAuthority.sourceDoc.source_digest:digest(stable),approval_ref:withBundle?bundleAuthority.references.approval_ref:ref(lost?'approval.withdrawn':'approval.current'),
     configuration_ref:ref('configuration.loopback'),endpoint_ref:ref('endpoint.loopback',digest(canonicalize(network))),
     minimum_poll_interval_ns:'16000000000',
     reserved_bytes:withBundle?16384:8192,poll_lease_ns:slot==='source.expiring'?'200000000':'2000000000',
     valid_before_tick_ns:String(native.tick()+3000000000n)};
   },
   readEndpoint(){return mismatchedEndpoint?{...network,endpoint:'127.0.0.1:9'}:network;},
   ...(anchorMode&&{referenceAuthority}),
   ...(scheduleMode&&{schedule:{sourceSlots:['source.capture']}}),
   captureProtection:{
    currentKey(scope){return {...scope,id:'capture.fixture',key:wrongWrite?wrongKey:key,writable:true};},
    readKey(scope,id){return {...scope,id,key:wrongRead?wrongKey:key,writable:false};}
   }
  }});
 const polls=app.referenceTimePolls;
 udp.on('message',(request,peer)=>{
  ++received;
  packet.resolve();
  if(mode==='time-provider-schedule-close')return;
  if(mode==='time-provider-invalidation'&&received===2){approvalWithdrawn=true;polls.currentReference();}
  attemptedBeforeUDP=Boolean(polls.lookup(mode==='time-provider-capture-rollback'?'poll.storage':
   mode==='time-provider-capture-resume'?'poll.resumed':'poll.capture')?.attempt);
  const reply=Buffer.alloc(48);
  reply[0]=4<<3|4;reply[1]=1;reply[19]=1;reply[35]=2;reply[43]=3;
  if(controlMode){
   reply[1]=0;reply[2]=4;
   reply.write(mode==='time-provider-control'&&received===2?'DENY':'RATE',12,'ascii');
  }
  if(anchorMode){
   reply.writeUInt32BE(0xffffffff,32);reply.writeUInt32BE(0xffffffff,36);
   reply.writeUInt32BE(0,40);reply.writeUInt32BE(1,44);
  }
  if(mode==='time-provider-schedule-restart'){
   reply[1]=0;reply.write('DENY',12,'ascii');
  }
  request.copy(reply,24,40,48);
  udp.send(reply,peer.port,peer.address);
 });
 const reserve=slot=>{const row=polls.reserve('source.'+slot,'poll.'+slot);return {id:row.reservation.poll_id,digest:row.digest};};
 const rejected=promise=>promise.then(()=>null,error=>error.message);
 if(scheduleMode){
  const {port}=udp.address();
  const target=mode==='time-provider-schedule-restart'?'blocked':'waiting';
  await packet.promise;
  if(mode==='time-provider-schedule-close'){
   process.stderr.write(JSON.stringify({event:'reference-schedule-pending',received,status:polls.scheduleStatus()})+'\n');
  }else{
   const waitUntil=performance.now()+7000;
   while(polls.scheduleStatus()[0].state!==target && performance.now()<waitUntil){
    await new Promise(resolve=>setTimeout(resolve,25));
   }
   process.stderr.write(JSON.stringify({event:'reference-schedule-result',received,status:polls.scheduleStatus(),
    reference:polls.currentReference(),port})+'\n');
  }
 }else if(invalidationMode){
  const first=await polls.collect(reserve('capture'));
  const available=polls.currentReference();
  const bundle=invalidationSource?polls.readReferenceBundle(available.bundle_ref):null;
  const beforeSource=invalidationSource?polls.referenceProtectionFenceSource():null;
  let inflight=null, late=null;
  if(mode==='time-provider-invalidation'){
   const wait=BigInt(first.receipt.m4_tick_ns)+16000000000n-native.tick();
   await new Promise(resolve=>setTimeout(resolve,Math.max(0,Number(wait/1000000n)+80)));
   const row=polls.reserve('source.capture','poll.pending-invalidation');
   inflight={id:row.reservation.poll_id,digest:row.digest};
   late=await polls.collect(inflight);
  }else{
   approvalWithdrawn=true;
   const watchDeadline=performance.now()+3000;
   while(polls.referenceProtectionStatus().state!=='unavailable'&&performance.now()<watchDeadline) {
    await new Promise(resolve=>setTimeout(resolve,25));
   }
  }
  const status=polls.referenceProtectionStatus();
  approvalWithdrawn=false;
  const afterRestore=polls.currentReference(), repeated=polls.referenceProtectionStatus();
  const denied=await rejected(Promise.resolve().then(()=>polls.reserve('source.capture-alias','poll.after-invalidation')));
  process.stderr.write(JSON.stringify({event:'reference-invalidation',available,status,repeated,afterRestore,denied,received,inflight,
   attempt:inflight?polls.lookup(inflight.id).attempt?.attempt_id:null,late,
   ...(invalidationSource&&{beforeSource,bundle,source:polls.referenceProtectionFenceSource()})})+'\n');
 }else if(mode==='time-provider-anchor-write-fault'){
  const original=reserve('capture');
  const failure=await rejected(polls.collect(original));
  process.stderr.write(JSON.stringify({event:'reference-anchor-write-fault',failure,received,current:polls.currentReference(),
   archive:polls.lookupCapture(original),attempt:Boolean(polls.lookup(original.id).attempt)})+'\n');
 }else if(mode==='time-provider-anchor-reopen'){
  const old=polls.lookup('poll.anchor');
  const archived=polls.lookupCapture({id:'poll.anchor',digest:old.digest});
  const projection=polls.projectReferenceCapture({domain:binding.receipt.domain_ref,
   before_tick_ns:archived.m1_tick_ns,after_tick_ns:archived.m4_tick_ns});
  process.stderr.write(JSON.stringify({event:'reference-anchor-reopened',received,current:polls.currentReference(),archived,projection})+'\n');
 }else if(mode==='time-provider-anchor'){
  const first=await polls.collect(reserve('capture'));
  const unqualified=polls.currentReference();
  const wait=BigInt(first.receipt.m4_tick_ns)+16000000000n-native.tick();
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,Number(wait/1000000n)+50)));
  omitEvidence=false;
  const next=polls.reserve('source.capture','poll.anchor');
  const accepted=await polls.collect({id:'poll.anchor',digest:next.digest});
  const current=polls.currentReference();
  const bundle=polls.readReferenceBundle(current.bundle_ref);
  await new Promise(resolve=>setTimeout(resolve,5));
  const capture={domain:current.runtime_domain_ref,before_tick_ns:current.tick_ns,after_tick_ns:polls.currentReference().tick_ns};
  const future=polls.projectReferenceCapture({...capture,after_tick_ns:'18446744073709551615'});
  const projection=polls.projectReferenceCapture(capture);
  const beforeAnchor=polls.projectReferenceCapture({...capture,before_tick_ns:accepted.receipt.m1_tick_ns});
  const wrongDomain=polls.projectReferenceCapture({...capture,domain:{...capture.domain,descriptor_digest:digest('wrong domain')}});
  const reversed=polls.projectReferenceCapture({...capture,before_tick_ns:capture.after_tick_ns,after_tick_ns:capture.before_tick_ns});
  approvalWithdrawn=true;
  const withdrawn=polls.currentReference();
  const historicBundle=polls.readReferenceBundle(current.bundle_ref);
  const wrongBundle=polls.readReferenceBundle({...current.bundle_ref,digest:digest('different bundle')});
  const withdrawnProjection=polls.projectReferenceCapture(capture);
  approvalWithdrawn=false;
  const afterRestore=polls.currentReference();
  process.stderr.write(JSON.stringify({event:'reference-anchor',first,accepted,current,unqualified,withdrawn,afterRestore,received,
   capture,projection,bundle,historicBundle,wrongBundle,rejectedProjections:[future,beforeAnchor,wrongDomain,reversed,withdrawnProjection],
   port:udp.address().port,eraBoundary:String(eraBoundary)})+'\n');
 }else if(mode==='time-provider-control-write-fault'){
  const ref=reserve('rate');
  const failed=await rejected(polls.collect(ref));
  const replay=await rejected(polls.collect(ref));
  const retry=await rejected(Promise.resolve().then(()=>polls.reserve('source.rate','poll.retry')));
  const capacity=await rejected(Promise.resolve().then(()=>polls.reserve('source.new','poll.new')));
  process.stderr.write(JSON.stringify({event:'time-provider-control-write-fault',failed,replay,retry,capacity,received})+'\n');
 }else if(mode==='time-provider-control'){
  const rate=await polls.collect(reserve('rate'));
  const early=await rejected(Promise.resolve().then(()=>polls.reserve('source.rate-alias','poll.early')));
  const stopped=await polls.collect(reserve('stopped'));
  const denied=await rejected(Promise.resolve().then(()=>polls.reserve('source.stopped','poll.denied')));
  process.stderr.write(JSON.stringify({event:'time-provider-control-stored',rate,early,stopped,denied,received,port:udp.address().port})+'\n');
 }else if(mode==='time-provider-control-resume'){
  const schedule=()=>polls.reserve('source.rate','poll.rate-next');
  const proof=await polls.recover('source.rate');
  const stopped=await polls.recover('source.stopped');
  const early=await rejected(Promise.resolve().then(schedule));
  const denied=await rejected(Promise.resolve().then(()=>polls.reserve('source.stopped','poll.denied')));
  const wait=BigInt(proof.wait_until_tick_ns)-native.tick();
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,Number(wait/1000000n)+25)));
  const allowed=schedule();
  const next=await polls.collect({id:'poll.rate-next',digest:allowed.digest});
  process.stderr.write(JSON.stringify({event:'time-provider-control-resumed',proof,stopped,early,denied,received,next,allowed})+'\n');
 }else if(mode==='time-provider-capture-restart'){
  const ref={id:'poll.capture',digest:polls.lookup('poll.capture').digest};
  const recovered=polls.readCapture(ref);
  wrongRead=true;
  const wrong=await rejected(Promise.resolve().then(()=>polls.readCapture(ref)));
  const replay=await rejected(polls.collect(ref));
  const reopen=await rejected(Promise.resolve().then(()=>polls.reserve('source.capture','poll.reopened')));
  process.stderr.write(JSON.stringify({event:'time-provider-archive-reopened',receipt:recovered.receipt,
   restoredDigest:digest(canonicalize(recovered.candidate)),wrong,replay,reopen,received})+'\n');
 }else if(mode==='time-provider-capture-resume'){
  const schedule=()=>polls.reserve('source.capture','poll.resumed');
  const unrecovered=await rejected(Promise.resolve().then(schedule));
  const proof=await polls.recover('source.capture');
  const repeated=await polls.recover('source.capture');
  const early=await rejected(Promise.resolve().then(schedule));
  const uncertain=await polls.recover('source.revoked');
  const backoff=await rejected(Promise.resolve().then(()=>polls.reserve('source.revoked','poll.unknown')));
  await polls.recover('source.changed');
  await polls.recover('source.expiring');
  const wait=BigInt(proof.wait_until_tick_ns)-native.tick();
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,Number(wait/1000000n)+25)));
  const replay=await rejected(polls.collect({id:'poll.capture',digest:polls.lookup('poll.capture').digest}));
  const archive=await polls.collect({id:'poll.resumed',digest:schedule().digest});
  process.stderr.write(JSON.stringify({event:'time-provider-archive-resumed',proof,repeated,uncertain,unrecovered,early,backoff,replay,
   archive,received,attemptedBeforeUDP,port:udp.address().port})+'\n');
 }else if(mode==='time-provider-ack-fault'){
  await rejected(polls.collect(reserve('capture')));
 }else if(mode==='time-provider-capture-repeat'){
  const first=await polls.collect(reserve('capture'));
  const schedule=()=>polls.reserve('source.capture','poll.next');
  const early=await rejected(Promise.resolve().then(schedule));
  const wait=BigInt(first.receipt.m4_tick_ns)+16000000000n-native.tick();
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,Number(wait/1000000n)+25)));
  const second=await polls.collect({id:'poll.next',digest:schedule().digest});
  process.stderr.write(JSON.stringify({event:'time-provider-archive-repeat',first,second,early,received})+'\n');
 }else if(mode==='time-provider-capture-rollback'){
  const ref=reserve('storage');
  const failure=await rejected(polls.collect(ref));
  const replay=await rejected(polls.collect(ref));
  const occupied=await rejected(Promise.resolve().then(()=>polls.reserve('source.storage','poll.retry')));
  const replacement=reserve('replacement');wrongWrite=true;
  const keyFailure=await rejected(polls.collect(replacement));
  process.stderr.write(JSON.stringify({event:'time-provider-archive-rollback',failure,replay,occupied,received,
   attemptedBeforeUDP,capture:polls.lookupCapture(ref),keyFailure,replacementAttempt:polls.lookup(replacement.id).attempt})+'\n');
 }else{
 const first=reserve('capture'), active=polls.collect(first);
 const busy=await rejected(polls.collect(first)), archive=await active;
 const candidate=polls.readCapture(first);
 const replay=await rejected(polls.collect(first));
 const revoked=reserve('revoked');revoke=true;
 const refused=await polls.collect(revoked);revoke=false;
 const changed=reserve('changed');mismatchedEndpoint=true;
 const endpoint=await rejected(polls.collect(changed));mismatchedEndpoint=false;
 const expiring=reserve('expiring');
 await new Promise(resolve=>setTimeout(resolve,250));
 const expired=await rejected(polls.collect(expiring));
 const confirmed=polls.lookup(first.id).attempt;
 process.stderr.write(JSON.stringify({event:'time-provider-capture',candidate,archive,refused,received,attemptedBeforeUDP,busy,replay,endpoint,expired,
  revokedReads,revokedAttempt:Boolean(polls.lookup(revoked.id).attempt),changedAttempt:polls.lookup(changed.id).attempt,
  expiredAttempt:polls.lookup(expiring.id).attempt,confirmed,port:udp.address().port})+'\n');
 }
 if(!scheduleMode)udp.close();
 process.stdin.setEncoding('utf8').on('data',data=>{if(data==='stop\n'){void app.close().finally(()=>{
  if(scheduleMode){
   process.stderr.write(JSON.stringify({event:'reference-schedule-closed',received,status:polls.scheduleStatus()})+'\n');
   udp.close();
  }
  process.stdin.destroy();
 });}});
 process.stdin.resume();
}else if(mode==='time-provider-polls'||mode==='time-provider-polls-restart'){
 const binding=await verifyCoreAdmission(assignment,receipt,policy);
 const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],policy,
  timeProviderIntent:options['--time-provider-intent'],binding});
 const evidenceRef=id=>({id,revision:'1',digest:'sha256:'+'a'.repeat(64)});
 const native=openNativeClock();
 let approval='approved.local';
 let failAfterCommit=false, uncertainReads=0;
 const app=await startController({dataDir:options['--data-dir'],coreBootstrap:async()=>({binding,policy,supervision:source}),
  authenticationProvider:({scope,source})=>authenticationFixture(scope,{source,descriptor:binding.descriptor},
   {sampleWindowPolicy:'authentication-clock-sample/2'}).provider,
  referenceTimeAuthorization:{limits:{max_outstanding:4,max_reserved_bytes:256},
   readSource(slot){
    if(slot==='source.uncertain'&&failAfterCommit&&++uncertainReads===3) throw new Error('test_source_unavailable');
    const sourceDigest='sha256:'+crypto.createHash('sha256').update(slot==='source.alias'?'source.first':slot).digest('hex');
    return {source_slot:slot,source_digest:sourceDigest,approval_ref:evidenceRef(approval),configuration_ref:evidenceRef('test.configuration'),
     endpoint_ref:evidenceRef('test.endpoint'),poll_lease_ns:slot==='source.expiring'?'250000000':'2000000000',
     reserved_bytes:64,valid_before_tick_ns:String(native.tick()+3000000000n)};
   }}});
 const polls=app.referenceTimePolls;
 const rejected=operation=>{try{operation();return null;}catch(error){return error.message;}};
 const ref=row=>({id:row.reservation.poll_id,digest:row.digest});
 const errors={};
 if(mode==='time-provider-polls'){
  const first=polls.reserve('source.first','poll.first');
  if(canonicalize(first)!==canonicalize(polls.reserve('source.first','poll.first'))) throw new Error('unexpected_reservation_replay');
  approval='withdrawn.local';
  errors.changed=rejected(()=>polls.markAttempt(ref(first)));
  approval='approved.local';
  polls.markAttempt(ref(first));
  errors.duplicate=rejected(()=>polls.markAttempt(ref(first)));
  errors.sameSource=rejected(()=>polls.reserve('source.first','poll.second'));
  errors.alias=rejected(()=>polls.reserve('source.alias','poll.alias'));
  const rollback=polls.reserve('source.rollback','poll.rollback');
  errors.rollback=rejected(()=>polls.markAttempt(ref(rollback)));
  const expiring=polls.reserve('source.expiring','poll.expiring');
  const remaining=BigInt(expiring.reservation.expires_tick_ns)-native.tick();
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,Number(remaining/1000000n)+15)));
  errors.expired=rejected(()=>polls.markAttempt(ref(expiring)));
  const uncertain=polls.reserve('source.uncertain','poll.uncertain');
  failAfterCommit=true;
  errors.afterCommit=rejected(()=>polls.markAttempt(ref(uncertain)));
  failAfterCommit=false;
  errors.uncertainReplay=rejected(()=>polls.markAttempt(ref(uncertain)));
  errors.capacity=rejected(()=>polls.reserve('source.over','poll.over'));
 }else{
  const old=polls.lookup('poll.first');
  errors.oldAttempt=rejected(()=>polls.markAttempt(ref(old)));
  errors.oldReserve=rejected(()=>polls.reserve('source.first','poll.first'));
  errors.sameSource=rejected(()=>polls.reserve('source.first','poll.second'));
 }
 process.stderr.write(JSON.stringify({event:'time-provider-poll-records',errors,row:polls.lookup('poll.first'),bootId:app.serviceBootId,
  rolledBack:polls.lookup('poll.rollback').attempt===null})+'\n');
 process.stdin.setEncoding('utf8').on('data',data=>{if(data==='stop\n'){void app.close().finally(()=>process.stdin.destroy());}});
 process.stdin.resume();
}else if(mode==='time-provider-authentication'){
 const binding=await verifyCoreAdmission(assignment,receipt,policy);
 const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],policy,
  timeProviderIntent:options['--time-provider-intent'],binding});
 const storage=openStorage(options['--data-dir']), saved=storage.bindCoreRuntime(binding,policy,source);
 const native=openNativeClock(), f=authenticationFixture(storage.authenticationClock.scope,{source:native,descriptor:binding.descriptor});
 const clock=startAuthenticationClock(native,storage.authenticationClock,f.provider,{schedule:false});
 let released;
 const link=await openTimeProviderLink(saved,{
  assertCurrent:()=>source.assertCurrent(),
  readAuthentication(){released=clock.referenceTimeSample();return released;}
 });
 process.stderr.write(JSON.stringify({event:'time-provider-authenticated',sample:released})+'\n');
 process.stdin.setEncoding('utf8').on('data',data=>{
  if(data==='stop\n'){clock.stop();link.close();storage.close();source.close();process.stdin.destroy();}
 });
 process.stdin.resume();
}else if(mode==='time-provider-observation'||mode==='time-provider-link-bad-binding'){
 const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],policy,
  timeProviderIntent:options['--time-provider-intent'],binding:{descriptor:assignment.clock_domain_descriptor,receipt}});
 const observed=await source.observeTimeProvider();
 source.assertTimeProviderObservation(observed);
 if(mode==='time-provider-link-bad-binding'){
  const digest=body=>'sha256:'+crypto.createHash('sha256').update(body).digest('hex');
  const {intent,descriptor,receipt:providerReceipt,process_observation}=observed;
  const binding={format:'leafseamer-time-provider-runtime-binding/1',service_id:policy.service_id,
   database_instance_id:policy.database_instance_id,service_boot_id:crypto.randomUUID(),core_receipt_id:receipt.receipt_id,
   launch_intent:intent,clock_domain_descriptor:descriptor,admission_receipt:providerReceipt,
   process_observation:{...process_observation,provider_pid:process.pid},gate_state:'closed'};
  const text=canonicalize({...binding,runtime_binding_id:'time-runtime.'+digest(canonicalize(binding)).slice(7)});
  const link=await openTimeProviderLink({text,digest:digest(text),memberBoot:providerReceipt.member_boot_id}).catch(()=>null);
  process.stderr.write(JSON.stringify({event:link?'bad-binding-accepted':'bad-binding-refused'})+'\n');
  link?.close();
  source.close();
  process.stdin.destroy();
 }else{
 const errors={};
 const record=async(name,operation)=>{try{await operation();errors[name]='unexpected_success';}catch(error){errors[name]=error.code;}};
 await record('copy',()=>source.assertTimeProviderObservation(structuredClone(observed)));
 await record('digest',()=>source.queryLaunch({launch_id:observed.intent.launch_id,launch_intent_digest:'sha256:'+'0'.repeat(64)}));
 const current=await source.observeTimeProvider();
 source.assertTimeProviderObservation(current);
 await record('superseded',()=>source.assertTimeProviderObservation(observed));
 const {descriptor,receipt:providerReceipt}=current;
 process.stderr.write(JSON.stringify({event:'time-provider-observed',errors,role:providerReceipt.role,
  providerPid:current.process_observation.provider_pid,providerBoot:providerReceipt.member_boot_id,
  processBound:current.process_observation.observation_id===providerReceipt.os_observation_ref,
  sameDomain:canonicalize(providerReceipt.domain_ref)===canonicalize(receipt.domain_ref),
  sameDescriptor:canonicalize(descriptor)===canonicalize(assignment.clock_domain_descriptor),
  observedBeforeDeadline:BigInt(current.received_tick_ns)<BigInt(current.confirmation_deadline_ns)})+'\n');
 process.stdin.setEncoding('utf8').on('data',data=>{if(data==='stop\n'){source.close();process.stdin.destroy();}});
 process.stdin.resume();
 }
}else if(mode==='core-refresh'){
 const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],policy,
  binding:{descriptor:assignment.clock_domain_descriptor,receipt}});
 const clock=openNativeClock(),original=source.observeCore(),expires=original.expires_tick_ns,requested=clock.tick();
 const observations=await Promise.all(Array.from({length:6},()=>source.refreshCoreObservation()));
 const fresh=observations.every(value=>BigInt(value.issued_tick_ns)>=requested&&value!==original&&value===source.observeCore());
 await new Promise(resolve=>setTimeout(resolve,Number((BigInt(expires)-clock.tick())/1000000n)+50));
 let oldError=null;try{source.assertCoreObservation(original);}catch(error){oldError=error.code;}
 source.assertCurrent();source.assertCoreObservation(source.observeCore());source.close();
 let closedError=null;try{await source.refreshCoreObservation();}catch(error){closedError=error.code;}
 process.stderr.write(JSON.stringify({event:'core-refresh-done',fresh,unchanged:original.expires_tick_ns===expires,oldError,closedError})+'\n');
 process.stdin.setEncoding('utf8').on('data',data=>{if(data==='stop\n')process.stdin.destroy();});process.stdin.resume();
}else if (mode === 'worker-register' || mode === 'worker-create' || mode === 'worker-retire') {
  const source = await connectCoreSupervisor({pipe: options['--supervisor-pipe'], channelId: options['--supervisor-channel'], policy,
    binding: {descriptor: assignment.clock_domain_descriptor, receipt}});
  const clock = openNativeClock(), hash = value => 'sha256:' + crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
  const ref = kind => ({kind, authority_service_id: policy.service_id, database_instance_id: policy.database_instance_id, object_id: kind, revision: '1', digest: hash(kind)});
  const intent = {launch_id: 'worker.launch', service_id: policy.service_id, supervisor_instance_id: source.scope.supervisor_instance_id,
    runtime_generation: assignment.clock_domain_descriptor.runtime_generation, member_id: 'worker.member', role: 'worker', artifact_manifest_ref: policy.artifact_manifest_ref,
    containment_ref: {group_id: 'worker.group', generation: 'worker.generation', backend: 'windows_job'}, object_scope: {kind: 'devices', device_ids: ['device.a']}, policy_revision: policy.policy_revision,
    extension_binding: {installation_ref: ref('installation'), approval_ref: ref('approval'), review_ref: ref('review'), role_resolution_ref: ref('role_resolution'),
      configuration_ref: ref('configuration'), intake_ref: ref('intake'), platform_profile_ref: {...ref('platform_profile'), object_id:policy.platform_profile_ref.profile_id, revision:policy.platform_profile_ref.revision}, host_installation_id: 'host', host_trust_epoch: '1',
      manifest_digest: hash('manifest'), artifact_set_digest: hash('artifacts'), entry_id: 'simulator', permissions_digest: hash('permissions')}};
  const key = {launch_id: intent.launch_id, launch_intent_digest: hash(intent)};
  const seal=grant=>{const {authorization_ref,...body}=grant;return {...body,authorization_ref:{...authorization_ref,digest:hash(body)}};};
  const authorization = (revision = '1', target = intent) => {
    const now = clock.tick();
    return seal({authorization_ref: ref('launch_authorization'), launch_id: target.launch_id, launch_intent_digest: hash(target), installation_ref: target.extension_binding.installation_ref,
      approval_ref: target.extension_binding.approval_ref, role_resolution_ref: target.extension_binding.role_resolution_ref, permissions_digest: target.extension_binding.permissions_digest,
      supervisor_instance_id: source.scope.supervisor_instance_id, fence_revision: revision, lifetime: {clock: source.scope.domain_ref, issued_tick: String(now), deadline_tick: String(now + 2000000000n)}});
  };
  const fence = (revision, items) => { const body = {scope: source.scope, revision, items}; return {...body, digest: hash(body)}; };
  const allow = {...key, disposition: 'allow'}, deny = {...key, disposition: 'deny'};
  await source.putFence(fence('1', [allow]));
  const errors = {};
  const create = async (name, grant = authorization(), requested = key) => {
    try { await source.createWorker({key: requested, authorization: name==='create_digest'?{...grant,authorization_ref:{...grant.authorization_ref,digest:hash('wrong')}}:seal(grant), load_id: 'unresolved.load', materialization_evidence_id: 'unresolved.evidence', materialization_challenge_id: 'unresolved.challenge'});
      errors[name] = 'unexpected_success'; } catch (error) { errors[name] = error.code; }
  };
  if (mode === 'worker-create') await create('create_missing');
  for (const kind of ['expired', 'future', 'domain', 'permissions', 'approval']) {
    const grant = authorization();
    if (kind === 'expired') { grant.lifetime.issued_tick = '0'; grant.lifetime.deadline_tick = '1'; }
    if (kind === 'future') { grant.lifetime.issued_tick = String(clock.tick() + 1000000000n); grant.lifetime.deadline_tick = String(BigInt(grant.lifetime.issued_tick) + 1000000000n); }
    if (kind === 'domain') grant.lifetime.clock = {...grant.lifetime.clock, descriptor_digest: hash('other')};
    if (kind === 'permissions') grant.permissions_digest = hash('other');
    if (kind === 'approval') grant.approval_ref = {...grant.approval_ref, object_id: 'other'};
    try { await source.registerWorker(intent, seal(grant)); errors[kind] = 'unexpected_success'; } catch (error) { errors[kind] = error.code; }
  }
  const grant = authorization(), first = await source.registerWorker(intent, seal(grant)), repeated = await source.registerWorker(intent, authorization());
  const queried = await source.queryLaunch(key);
  if (mode === 'worker-create') {
    await create('create_digest');
    for (const kind of ['expired', 'future', 'domain', 'permissions', 'approval', 'installation', 'role', 'authority', 'revision']) {
      const grant = authorization();
      if (kind === 'expired') { grant.lifetime.issued_tick = '0'; grant.lifetime.deadline_tick = '1'; }
      if (kind === 'future') { grant.lifetime.issued_tick = String(clock.tick() + 1000000000n); grant.lifetime.deadline_tick = String(BigInt(grant.lifetime.issued_tick) + 1000000000n); }
      if (kind === 'domain') grant.lifetime.clock = {...grant.lifetime.clock, descriptor_digest: hash('other')};
      if (kind === 'permissions') grant.permissions_digest = hash('other');
      if (kind === 'approval') grant.approval_ref = {...grant.approval_ref, object_id: 'other'};
      if (kind === 'installation') grant.installation_ref = {...grant.installation_ref, digest: hash('other')};
      if (kind === 'role') grant.role_resolution_ref = {...grant.role_resolution_ref, revision: '2'};
      if (kind === 'authority') grant.authorization_ref = {...grant.authorization_ref, database_instance_id: 'other'};
      if (kind === 'revision') grant.fence_revision = '0';
      await create('create_' + kind, grant);
    }
    const changed = {...intent, object_scope: {kind: 'devices', device_ids: ['device.b']}};
    await create('create_conflict', authorization('1', changed), {...key, launch_intent_digest: hash(changed)});
    await create('create_unresolved'); await create('create_repeated');
    source.assertCurrent();
  }
  try { await source.putFence(fence('2', [])); } catch (error) { errors.omission = error.code; }
  try { await source.registerWorker(intent, authorization()); } catch (error) { errors.unsynchronized = error.code; }
  if (mode === 'worker-create') await create('create_unsynchronized');
  await source.putFence(fence('1', [allow]));
  await source.putFence(fence('2', [deny]));
  if (mode === 'worker-create') await create('create_denied', authorization('2'));
  try { await source.registerWorker(intent, authorization('2')); } catch (error) { errors.denied = error.code; }
  const changed = {...intent, object_scope: {kind: 'devices', device_ids: ['device.b']}};
  try { await source.registerWorker(changed, authorization('2', changed)); } catch (error) { errors.changed = error.code; }
  try { await source.queryLaunch({launch_id: intent.launch_id, launch_intent_digest: hash(changed)}); } catch (error) { errors.query_conflict = error.code; }
  try { await source.putFence(fence('3', [allow])); } catch (error) { errors.reallow = error.code; }
  let retirement = null, repeatedRetirement = null, replacement = null;
  if (mode === 'worker-retire') {
    try { await source.retireWorker(changed, 'revoked'); } catch (error) { errors.retire_conflict = error.code; }
    const missing = {...intent, launch_id: 'worker.missing'};
    try { await source.retireWorker(missing, 'revoked'); } catch (error) { errors.retire_missing = error.code; }
    // 上一次reallow失败已关闭fence同步；保护退役仍可进行，不要求重新取得启动授权。
    retirement = await source.retireWorker(intent, 'revoked');
    repeatedRetirement = await source.retireWorker(intent, 'shutdown');
    try { await source.registerWorker(intent, authorization('2')); } catch (error) { errors.retire_reregister = error.code; }
    await create('retire_create', authorization('2'));
    const nextIntent = {...intent, launch_id: 'worker.next', member_id: 'worker.next.member',
      containment_ref: {...intent.containment_ref, group_id: 'worker.next.group'}};
    await source.putFence(fence('3', [{launch_id: nextIntent.launch_id, launch_intent_digest: hash(nextIntent), disposition: 'allow'}]));
    replacement = await source.registerWorker(nextIntent, authorization('3', nextIntent));
    try { await source.registerWorker(intent, authorization('3')); } catch (error) { errors.retire_reregister_synced = error.code; }
    try { await source.putFence(fence('4', [allow, {launch_id: nextIntent.launch_id, launch_intent_digest: hash(nextIntent), disposition: 'allow'}])); }
    catch (error) { errors.retire_reallow = error.code; }
  }
  const final = await source.queryLaunch(key);
  process.stderr.write(JSON.stringify({event: 'worker-result', intent, grant, first, repeated, queried, final, errors, retirement, repeatedRetirement, replacement}) + '\n');
  process.stdin.setEncoding('utf8').on('data', data => { if (data === 'stop\n') { source.close(); process.stdin.destroy(); } }); process.stdin.resume();
} else if (mode === 'fence' || mode === 'fence-failure') {
  const source = await connectCoreSupervisor({pipe: options['--supervisor-pipe'], channelId: options['--supervisor-channel'], policy,
    binding: {descriptor: assignment.clock_domain_descriptor, receipt}});
  const items = Array.from({length: 256}, (_, i) => ({launch_id: 'worker' + String(i).padStart(3, '0') + 'x'.repeat(115),
    launch_intent_digest: 'sha256:' + '2'.repeat(64), disposition: 'allow'}));
  const snapshot = (revision, list) => {
    const body = {scope: source.scope, revision, items: list};
    return {...body, digest: 'sha256:' + crypto.createHash('sha256').update(canonicalize(body)).digest('hex')};
  };
  const send = async (revision, list) => {
    const body = snapshot(revision, list);
    try { const result = await source.putFence(body); process.stderr.write(JSON.stringify({event: 'fence', body, result}) + '\n'); }
    catch (error) { process.stderr.write(JSON.stringify({event: 'fence-error', code: error.code}) + '\n'); }
  };
  await send('9007199254740993', items);
  if (mode === 'fence') {
    await send('9007199254740993', items);
    await send('9007199254740992', items);
    await send('9007199254740993', []);
    const denied = items.map(item => ({...item, disposition: 'deny'}));
    await send('9007199254740994', denied);
    await send('9007199254740995', []);
    await send('9007199254740996', items);
    await send('9007199254740996', [{...items[0], launch_intent_digest: 'sha256:' + '3'.repeat(64), disposition: 'deny'}]);
    await send('9007199254740995', []);
    process.stderr.write(JSON.stringify({event: 'fence-done', current: source.current().payload.record.gate_state}) + '\n');
  }
  process.stdin.setEncoding('utf8').on('data', data => { if (data === 'stop\n') { source.close(); process.stdin.destroy(); } });
  process.stdin.resume();
} else if (mode === 'peer') {
  const child = spawn(process.execPath, [fileURLToPath(new URL('./control-intruder.mjs', import.meta.url)), options['--supervisor-pipe']], {stdio: 'ignore', windowsHide: true});
  process.stderr.write(JSON.stringify({event: 'intruder', pid: child.pid}) + '\n');
  setInterval(() => {}, 1000);
} else {
  const socket = net.createConnection(options['--supervisor-pipe']);
  socket.on('error', () => {});
  const frame = {version: supervisorControlVersion, type: 'LAUNCH_QUERY',
    scope: {service_id: policy.service_id, database_instance_id: policy.database_instance_id, supervisor_instance_id: assignment.clock_domain_descriptor.supervisor_instance_id, domain_ref: receipt.domain_ref},
    channel_id: options['--supervisor-channel'], sequence: '1', message_id: 'first', reply_to: null,
    payload: {launch_id: receipt.launch_id, launch_intent_digest: receipt.launch_intent_digest}};
  if (mode === 'scope') frame.scope.database_instance_id = 'other';
  if (mode === 'channel') frame.channel_id = 'other';
  if (mode === 'sequence') frame.sequence = '2';
  if (mode === 'reply') frame.reply_to = 'unsolicited';
  if (mode === 'direction') frame.type = 'LAUNCH_RESULT';
  if (mode === 'conflict') frame.payload.launch_intent_digest = 'sha256:' + '0'.repeat(64);
  if (mode === 'missing') frame.payload.launch_id = 'missing';
  if (mode.startsWith('fence-bad-')) {
    frame.type = 'FENCE_PUT';
    const item = {launch_id: 'worker', launch_intent_digest: 'sha256:' + '2'.repeat(64), disposition: 'allow'};
    const body = {scope: frame.scope, revision: '1', items: [item]};
    if (mode === 'fence-bad-scope') body.scope = {...frame.scope, database_instance_id: 'another'};
    if (mode === 'fence-bad-order') body.items = [{...item, launch_id: 'z'}, {...item, launch_id: 'a'}];
    if (mode === 'fence-bad-duplicate') body.items = [item, {...item, disposition: 'deny'}];
    if (mode === 'fence-bad-core') body.items = [{...item, launch_id: receipt.launch_id}];
    if (mode === 'fence-bad-capacity') body.items = Array.from({length: 257}, (_, i) => ({...item, launch_id: 'w' + String(i).padStart(3, '0')}));
    if (mode === 'fence-bad-revision') body.revision = '01';
    if (mode === 'fence-bad-id') body.items = [{...item, launch_id: '/worker'}];
    if (mode === 'fence-bad-extra') body.items = [{...item, authorized: true}];
    frame.payload = {...body, digest: 'sha256:' + crypto.createHash('sha256').update(canonicalize(body)).digest('hex')};
    if (mode === 'fence-bad-digest') frame.payload.digest = 'sha256:' + '0'.repeat(64);
  }
  const line = canonicalize(frame) + '\n';
  socket.once('connect', () => {
    if (mode === 'disconnect') { socket.destroy(); return; }
    if (mode === 'silent') return;
    socket.write(mode === 'duplicate-key' ? line.replace('"type":', '"type":"LAUNCH_QUERY","type":') : line);
  });
  let buffer = '';
  socket.on('data', async bytes => {
    buffer += bytes; if (!buffer.endsWith('\n')) return;
    const response = await decodeSupervisorControl(Buffer.from(buffer.slice(0, -1)), mode === 'conflict' ? 'ERROR' : 'LAUNCH_RESULT'); buffer = '';
    process.stderr.write(JSON.stringify({event: 'response', sequence: response.sequence, reply_to: response.reply_to, payload: response.payload}) + '\n');
    if (mode === 'replay') socket.write(line);
  });
  process.stdin.setEncoding('utf8').on('data', data => { if (data === 'stop\n') { socket.destroy(); process.stdin.destroy(); } });
  process.stdin.resume();
}
