import http from 'node:http';
import https from 'node:https';
import {networkInterfaces} from 'node:os';
import {openStorage} from './storage.mjs';
import {openNativeClock} from './native-clock.mjs';
import {startClockMonitor} from './clock-monitor.mjs';
import {startAuthenticationClock} from './auth-clock.mjs';
import {inspectLinuxClockEvidence, waitForLinuxAuthentication} from './linux-clock-evidence.mjs';
import {createAuthenticationHttp} from './auth-http.mjs';
import {loadGuiAssets} from './gui-assets.mjs';
import {startPeerPairingTransport} from './peer-pairing-transport.mjs';
import {startOutboxDelivery} from './session-denial-delivery.mjs';
import {startRunProtectionDelivery} from './run-approval-protection-completion.mjs';
import {createSubscriptionEndpoint} from './service-subscription-http.mjs';
import {createIntrospectionEndpoint} from './introspection-http.mjs';
import {pairingFields, pairingUuid} from './peer-pairing-value.mjs';
import {openTimeProviderLink} from './time-provider-link.mjs';
import {referenceTimeScheduler} from './reference-time-scheduler.mjs';
import canonicalize from './runtime/canonicalize.mjs';
import {createHash} from 'node:crypto';

export async function startController({dataDir, host = '127.0.0.1', port = 0, tls = null, authenticationProvider = null, guiDirectory = null, guiManifestSha256 = null, coreBootstrap = null, pairing = null, referenceTimeAuthorization = null, localPairingManagement = false, standalone = false, protectedIngressIdentity = null, linuxClockEvidenceProfile = null} = {}) {
  const protectedIngress = protectedIngressIdentity !== null;
  if (protectedIngress) {
    if (process.platform !== 'linux' || !tls || authenticationProvider || guiDirectory || linuxClockEvidenceProfile || pairing ||
        referenceTimeAuthorization || localPairingManagement || standalone) throw new Error('protected_ingress_options');
    pairingFields(protectedIngressIdentity, 'database_instance_id,service_id');
    pairingUuid(protectedIngressIdentity.service_id);
    pairingUuid(protectedIngressIdentity.database_instance_id);
    if (!Object.values(networkInterfaces()).flat().some(iface => iface.address === host)) {
      throw new Error('protected_ingress_address');
    }
  }
  if ((!protectedIngress && !['127.0.0.1', '::1'].includes(host)) ||
      !Number.isInteger(port) || port < (protectedIngress ? 1 : 0) || port > 65535) throw new Error('listen_options');
  if (authenticationProvider !== null && typeof authenticationProvider !== 'function') throw new Error('authentication_provider');
  const linuxPairing = linuxClockEvidenceProfile?.authentication === true && pairing !== null && tls !== null && localPairingManagement;
  if (linuxClockEvidenceProfile !== null && (process.platform !== 'linux' || !coreBootstrap || authenticationProvider || (!linuxPairing && (tls || pairing)))) {
    throw new Error('linux_clock_evidence_binding');
  }
  if (tls !== null && (!tls || Object.keys(tls).sort().join(',') !== 'cert,key,origin' || typeof tls.origin !== 'string')) throw new Error('tls_options');
  if (guiDirectory !== null && tls === null) throw new Error('gui_requires_https');
  if (pairing !== null) pairingUuid(pairing.credential_id);
  const storage = openStorage(dataDir, protectedIngressIdentity);
  let supervision = null, timeProviderLink = null, timeProviderBinding = null, clockEvidence = null, linuxSource = null, linuxRuntime = null;
  const assertRuntimeCurrent = () => { supervision?.assertCurrent(); linuxRuntime?.assertLive(); timeProviderLink?.assertCurrent(); };
  try {
    if (coreBootstrap !== null) {
      if (typeof coreBootstrap !== 'function' || Number(storage.identity.schema_revision) < 11) throw new Error('core_runtime_migration_required');
      const result = await coreBootstrap(storage.identity), {binding, policy} = result;
      supervision = result.supervision ?? null; supervision?.assertCurrent();
      result.assertCurrent?.();
      timeProviderBinding = storage.bindCoreRuntime(binding, policy, supervision);
      if (linuxClockEvidenceProfile !== null) {
        linuxSource = openNativeClock({linuxWithoutSystemSleep: linuxClockEvidenceProfile.authentication});
        clockEvidence = inspectLinuxClockEvidence(linuxClockEvidenceProfile, storage.authenticationClock.scope, result, linuxSource);
      }
      if ((linuxPairing||protectedIngress)&&typeof result.assertLive==='function') linuxRuntime=result;
      result.assertCurrent?.();
      if(supervision)storage.workerLaunches?.runtime?.bindSource(supervision);
      if(supervision)storage.extensionInstallations?.bindRuntimeSource?.(supervision);
      if(supervision)storage.workerLaunches?.authorization?.bindSource(supervision);
      assertRuntimeCurrent();
    }
    if (localPairingManagement && ((!supervision && !linuxPairing) || !tls || !pairing || Number(storage.identity.schema_revision) < 93)) {
      throw new Error('pairing_profile_management_unavailable');
    }
    if(standalone&&(!supervision||!tls||!authenticationProvider||!guiDirectory||!guiManifestSha256||pairing||localPairingManagement||
      storage.enrollment?.summary().mode!=='standalone'))throw new Error('standalone_profile_runtime');
  } catch (error) { try { storage.close(); } finally { timeProviderLink?.close(); supervision?.close(); } throw error; }
  let clock = null, authentication = null, sessions = null;
  if (storage.clockJournal) {
    try {
      const source = linuxSource ?? openNativeClock();
      clock = startClockMonitor(source, storage.clockJournal);
      // 受信装配读取批准原件，所有入口使用同一原生时钟。
      if (storage.authenticationClock) {
        const linuxAuthentication = linuxClockEvidenceProfile?.authentication === true;
        const provider = linuxAuthentication ? clockEvidence : await authenticationProvider?.(Object.freeze({scope: storage.authenticationClock.scope, source}));
        authentication = startAuthenticationClock(source, storage.authenticationClock, provider ?? null,
          {waitForInitialEvidence: linuxAuthentication, renewableHealth: linuxAuthentication});
        if (linuxPairing) await waitForLinuxAuthentication(authentication, linuxRuntime.signal);
        if (Number(storage.identity.schema_revision) >= 5 && (!linuxAuthentication || linuxPairing)) sessions = storage.sessions(authentication);
      }
    }
    catch (error) {
      clock?.stop(); authentication?.stop(); sessions = null;
      if (pairing !== null || standalone) { try { storage.close(); } finally { supervision?.close(); } throw error; }
      try { storage.clockJournal.fault('native_clock_unavailable'); }
      catch (error) { try { storage.close(); } finally { timeProviderLink?.close(); supervision?.close(); } throw error; }
      clock = {status: () => ({state: 'faulted', qualified: false}), stop() {}};
    }
  }
  let server, referenceTimePolls = null, referenceSchedule = null, referencePublication = null, referenceWatcher = null, peerTransport = null;
  let endorsementRevocationDelivery = null, runProtectionDelivery = null, closing = false;
  const closeHttp = () => !server?.listening ? Promise.resolve() : new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve()); server.closeAllConnections();
  });
  const cleanup = async () => {
    closing = true;
    clearInterval(referenceWatcher);
    const scheduleStopped=referenceSchedule?.close();
    if(referenceSchedule) timeProviderLink.quiesce();
    let referenceFailure;
    try { referencePublication?.invalidate?.('shutdown'); }
    catch(error) { referenceFailure=error; }
    const results = await Promise.allSettled([scheduleStopped,closeHttp(), endorsementRevocationDelivery?.close(),
      runProtectionDelivery?.close(), peerTransport?.close()]);
    for (const stop of [() => clock?.stop(), () => authentication?.stop(), () => storage.close(), () => timeProviderLink?.close(), () => supervision?.close()]) {
      try { stop(); } catch (reason) { results.push({status: 'rejected', reason}); }
    }
    const failed = results.find(result => result.status === 'rejected'); if (failed) throw failed.reason;
    if(referenceFailure) throw referenceFailure;
  };
  try {
    if (timeProviderBinding) {
      timeProviderLink = await openTimeProviderLink(timeProviderBinding, {
        assertCurrent() {
          if (closing) throw new Error('controller_closing');
          supervision.assertCurrent();
        },
        readAuthentication() {
          try { return authentication?.referenceTimeSample() ?? null; }
          catch { return null; }
        }
      });
      assertRuntimeCurrent();
    }
    if (referenceTimeAuthorization !== null) {
      if (!timeProviderLink || !authentication?.status().qualified) throw new Error('time_provider_poll_authority');
      const assertPollCurrent = () => {
        if (closing) throw new Error('controller_closing');
        assertRuntimeCurrent();
      };
      const polls = storage.openTimeProviderPolls({
        limits: referenceTimeAuthorization.limits,
        readSource: referenceTimeAuthorization.readSource,
        readAuthentication: () => authentication.referenceTimeSample(),
        assertCurrent: assertPollCurrent,
        observeRetirement: supervision.observeTimeProviderRetirement,
        assertRetirement: supervision.assertTimeProviderRetirement
      });
      const {readEndpoint, captureProtection, referenceAuthority, schedule} = referenceTimeAuthorization;
      if (readEndpoint !== undefined && typeof readEndpoint !== 'function') throw new Error('time_provider_poll_endpoint_authority');
      if (referenceAuthority !== undefined && !readEndpoint) throw new Error('reference_time_authority');
      const publication = referenceAuthority===undefined ? null : storage.openReferenceTimeAnchor({...referenceAuthority,readContext:polls.referenceContext});
      referencePublication=publication;
      const archive = readEndpoint ? storage.openTimeProviderCapture(captureProtection,publication) : null;
      function collect(pollRef, scheduled = null) {
        return timeProviderLink.collect(() => {
          let stored;
          if (!scheduled) {
            stored = polls.lookup(pollRef?.id);
            if (!stored || stored.digest !== pollRef.digest || stored.reservation.service_boot_id !== storage.serviceBootId) {
              throw new Error('time_provider_poll_identity_conflict');
            }
            if (stored.attempt) throw new Error('time_provider_poll_already_attempted');
          }
          const endpoint = (scheduled?.authorization??stored.reservation.authorization).endpoint_ref;
          const encoded = canonicalize(readEndpoint(Object.freeze({...endpoint})));
          if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > 12000 ||
              'sha256:' + createHash('sha256').update(encoded).digest('hex') !== endpoint.digest) {
            throw new Error('time_provider_poll_endpoint_binding');
          }
          archive.assertWritable();
          if (scheduled) {
            stored=polls.reserve(scheduled.slot,scheduled.id,scheduled.authorization);
            pollRef={id:scheduled.id,digest:stored.digest};
          }
          const attempt = polls.markAttempt(pollRef);
          const reservation = stored.reservation, network=JSON.parse(encoded), authorize = () => polls.authorizeAttempt(attempt);
          return {reservation, attempt, network, authorize,
            ...(polls.storeControl && {storeControl:control=>polls.storeControl(attempt,control),releaseControl:polls.releaseControl}),
            archive: candidate => archive.store({reservation,attempt,candidate,authorize,network}),
            release: (receipt,acknowledgement) => archive.release({receipt,acknowledgement,reservation,assertCurrent:assertPollCurrent})};
        });
      }
      if(schedule!==undefined) {
        if(!schedule || Object.keys(schedule).join(',')!=='sourceSlots' || !archive || !polls.schedulePlan) {
          throw new Error('reference_time_schedule_authority');
        }
        referenceSchedule=referenceTimeScheduler(schedule,{plan:polls.schedulePlan,recover:polls.recover,
          collect:(slot,id,authorization)=>collect(null,{slot,id,authorization})});
      }
      referenceTimePolls = Object.freeze({lookup: polls.lookup, reserve:(slot,id)=>polls.reserve(slot,id), markAttempt: polls.markAttempt,
        ...(polls.recover && {recover: polls.recover}),
        ...(publication && {currentReference:publication.current,projectReferenceCapture:publication.projectCapture,readReferenceBundle:publication.readBundle,
          receiverReference:publication.receiverReference}),
        ...(publication?.protectionStatus && {referenceProtectionStatus:publication.protectionStatus}),
        ...(referenceSchedule && {scheduleStatus:referenceSchedule.status}),
        ...(archive && {lookupCapture: archive.lookup, readCapture: archive.read, async collect(pollRef){return collect(pollRef);}})
      });
    }
    const gui = guiDirectory === null ? null : loadGuiAssets(guiDirectory, storage.identity, tls.origin, {
      manifestSha256: guiManifestSha256, seamerIdentity: localPairingManagement ? pairing.peers?.[0]?.identity ?? null : null, standalone
    });
    async function managePairing(auth, operation, input) {
      if (closing || !peerTransport) throw new Error('pairing_runtime_unavailable');
      assertRuntimeCurrent();
      const api = sessions.peerPairings;
      let result;
      switch (operation) {
        case 'stage': result = api.stage(auth, input); break;
        case 'export': result = api.exportFirstPairingAuthorization(auth, input); break;
        case 'activate': result = api.activate(auth, input); break;
        case 'read-audience':
          pairingFields(input, 'principal_id,audience');
          result = sessions.remotePermissions.get(auth, input.principal_id, input.audience);
          break;
        case 'grant-audience':
          result = sessions.remotePermissions.replace(auth, input);
          break;
        case 'inspect':
          pairingFields(input, 'binding_id');
          result = api.get(auth, input.binding_id);
          break;
        case 'prove':
          pairingFields(input, 'binding_id');
          api.get(auth, input.binding_id);
          assertRuntimeCurrent();
          await peerTransport.prove(input.binding_id);
          if (closing) throw new Error('pairing_runtime_unavailable');
          result = api.get(auth, input.binding_id);
          break;
        default: throw new Error('pairing_operation');
      }
      assertRuntimeCurrent();
      return result;
    }
    const authenticationHttp = createAuthenticationHttp({serviceId: storage.identity.service_id, databaseInstanceId: storage.identity.database_instance_id,
      serviceBootId: storage.serviceBootId, sessions, origin: tls?.origin ?? null, localPairing: localPairingManagement ? managePairing : null});
    const options = {maxHeaderSize: 16384, requestTimeout: 5000, headersTimeout: 5000, keepAliveTimeout: 1000};
    const listener = (req, res) => {
    try { assertRuntimeCurrent(); } catch { res.writeHead(503, {'Cache-Control': 'no-store', Connection: 'close'}); res.end(); return; }
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (authenticationHttp.handle(req, res)) return;
    // 其它启动端点仍不接收正文。
    if (req.headers['transfer-encoding'] !== undefined || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) {
      res.writeHead(413, {Connection: 'close'}); res.end(); return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405, {Allow: 'GET, HEAD'}); res.end(); return; }
    if (gui?.handle(req, res)) return;
    let status, body;
    if (req.url === '/health/live') { status = 200; body = {status: 'alive'}; }
    else if (req.url === '/health/ready') {
      const authStatus = authentication?.status();
      status = 503; body = {ready: false, reason: authStatus?.qualified ? 'business_incomplete' : clock ? (clock.status().state === 'faulted' ? 'authentication_clock_unavailable' : 'authentication_clock_unqualified') : 'bootstrap_incomplete'};
      if (clockEvidence) {
        body.authentication_clock_evidence = body.reason === 'authentication_clock_unavailable' ? 'unavailable' : clockEvidence.status();
        if (linuxClockEvidenceProfile.authentication) body.authentication_clock = authStatus?.state ?? 'faulted';
        if (linuxPairing && authStatus?.state === 'faulted') body.authentication_clock_reason = authStatus.reason;
      }
    }
    else if (req.url === '/.well-known/leafseamer-contracts') { res.writeHead(503); res.end(); return; }
    else { res.writeHead(404); res.end(); return; }
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, {'Content-Type': 'application/json', 'Content-Length': String(bytes.length)});
    res.end(req.method === 'HEAD' ? undefined : bytes);
    };
    server = tls ? https.createServer({...options, key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3'}, listener) : http.createServer(options, listener);
  } catch (error) { await cleanup().catch(() => {}); throw error; }
  server.maxRequestsPerSocket = 100;
  server.on('clientError', (_error, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  try {
    assertRuntimeCurrent();
    if(standalone&&!authentication?.status().qualified)throw new Error('standalone_profile_clock_unqualified');
    if (pairing !== null && !authentication?.status().qualified) throw new Error('pairing_clock_unqualified');
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }); assertRuntimeCurrent();
    if (pairing !== null) {
      const issuer = storage.enrollment?.summary();
      if (!issuer?.initialized || !sessions?.peerPairings || !sessions?.sessionDenials || !authentication?.status().qualified) throw new Error('pairing_runtime_unavailable');
      const identity = {service_id: storage.identity.service_id, database_instance_id: storage.identity.database_instance_id, service_kind: 'controller',
        issuer_id: issuer.issuer_id, issuer_epoch: issuer.issuer_epoch, credential_id: pairing.credential_id};
      const introspection = createIntrospectionEndpoint({sessions, serviceId: storage.identity.service_id, serviceBootId: storage.serviceBootId});
      peerTransport = await startPeerPairingTransport({pairings: sessions.peerPairings,
        clock: {pairingSample() { supervision?.assertCurrent(); return authentication.pairingSample(); }}, identity,
        cert: pairing.cert, key: pairing.key, ca: pairing.ca, host: pairing.host ?? '127.0.0.1', port: pairing.port ?? 0,
        serverName: pairing.serverName ?? pairing.host ?? '127.0.0.1', network:pairing.network??false, sessionDenials: sessions.sessionDenials,
        deviceBindings(device,reference) { supervision?.assertCurrent(); return storage.workerLaunches.deviceAutomation(device,reference); },
        deviceEvents(device,reference,after,limit) { supervision?.assertCurrent(); return storage.workerLaunches.deviceEvents(device,reference,after,limit); },
        subscriptions:sessions.serviceSubscriptions?createSubscriptionEndpoint({store:sessions.serviceSubscriptions,readReferenceBundle:referencePublication?.readBundle,
          serviceBootId:storage.serviceBootId}):null,
        automationApproval(bindingId,socket,request) {
          supervision?.assertCurrent(); return sessions.currentAutomationServiceApproval(bindingId,socket,request);
        },
        runEndorsement:sessions.runApprovalEndorsements?(...args)=>{
          supervision?.assertCurrent();return sessions.runApprovalEndorsements.readForPeer(...args);
        }:null,
        runControlObservation:sessions.runApprovalEndorsements?(...args)=>{
          supervision?.assertCurrent();return sessions.runApprovalEndorsements.readControlsForPeer(...args);
        }:null,
        runPreparations:sessions.runPreparations?{
          async prepare(...args){
            supervision?.assertCurrent();const result=await sessions.runPreparations.prepare(...args);supervision?.assertCurrent();return result;
          },
          lookup(...args){supervision?.assertCurrent();return sessions.runPreparations.lookup(...args);},
          async prepareEligibility(...args){
            supervision?.assertCurrent();const observation=await sessions.runPreparations.prepareEligibility(...args);
            return {body:observation.body,beforeSend(){supervision?.assertCurrent();return observation.beforeSend();}};
          }
        }:null,
        automationCommands:sessions.runPreparations?.automationCommands?{
          async submit(...args){
            supervision?.assertCurrent();
            const result=await sessions.runPreparations.automationCommands.submit(...args);
            supervision?.assertCurrent();return result;
          },
          lookup(...args){supervision?.assertCurrent();return sessions.runPreparations.automationCommands.lookup(...args);},
          reject(...args){supervision?.assertCurrent();return sessions.runPreparations.automationCommands.reject(...args);}
        }:null,
        runApprovalProtection:sessions.runApprovalEndorsements?.receiveProtection?(...args)=>{
          supervision?.assertCurrent();return sessions.runApprovalEndorsements.receiveProtection(...args);
        }:null,
        async introspection(request) {
          supervision?.assertCurrent(); const response = await introspection(request);
          return {...response, beforeSend() { supervision?.assertCurrent(); response.beforeSend(); }};
        }});
      if (pairing.peers !== undefined) peerTransport.bindPeers(pairing.peers);
      sessions.runEndorsementPolicies?.bindProposalReader((...args)=>peerTransport.readRunApprovalProposal(...args));
      sessions.runApprovalEndorsements?.bindApprovalReader((...args)=>peerTransport.readRunApproval(...args));
      sessions.runApprovalEndorsements?.bindInitiatorReader((...args)=>peerTransport.readRunInitiator(...args));
      sessions.runPreparations?.bindPlanReader(async(...args)=>{
        const plan=await peerTransport.prepareRunArmPlan(...args);
        return {original:plan.original,assertCurrentInTransaction(){supervision?.assertCurrent();return plan.assertCurrentInTransaction();}};
      });
      sessions.runPreparations?.bindActionReader(async(...args)=>{
        supervision?.assertCurrent();
        const action=await peerTransport.prepareRunActionBinding(...args);
        supervision?.assertCurrent();
        return {original:action.original,assertCurrentInTransaction(){supervision?.assertCurrent();return action.assertCurrentInTransaction();}};
      });
      const endorsements=sessions.runApprovalEndorsements;
      if(endorsements?.deliverPendingRevocation){
        endorsements.bindRevocationTransport(async(...args)=>{
          supervision?.assertCurrent();const receipt=await peerTransport.deliverRunEndorsementRevocation(...args);supervision?.assertCurrent();return receipt;
        });
        endorsementRevocationDelivery=startOutboxDelivery({scan:endorsements.scanRevocations,async deliver(operationId){
          return (await endorsements.deliverPendingRevocation(operationId)).state;
        }});
      }
      supervision?.assertCurrent();
    }
    runProtectionDelivery=startRunProtectionDelivery({endorsements:sessions?.runApprovalEndorsements,workerLaunches:storage.workerLaunches,
      assertCurrent(){if(closing)throw new Error('controller_closing');assertRuntimeCurrent();}});
    assertRuntimeCurrent();
  } catch (error) { await cleanup().catch(() => {}); throw error; }
  let stopping;
  const application = Object.freeze({address: server.address(), identity: storage.identity, serviceBootId: storage.serviceBootId,
    authenticationStatus: () => authentication?.status() ?? null,
    ...(referenceTimePolls && {referenceTimePolls}),
    pairing: peerTransport ? Object.freeze({api: sessions.peerPairings, transport: peerTransport, remotePermissions: sessions.remotePermissions, sessionDenials: sessions.sessionDenials,
      automationApprovals:Object.freeze({
        createPrincipal(input,request) { supervision?.assertCurrent(); return sessions.createServicePrincipal(input,{...request,purpose:'automation'}); },
        approvePrincipal(input,request) { supervision?.assertCurrent(); return sessions.approveAutomationServicePrincipal(input,request); }
      }),
      runEndorsementPolicies:sessions.runEndorsementPolicies?Object.freeze({
        replace(input,request){supervision?.assertCurrent();return sessions.runEndorsementPolicies.replace(input,request);},
        async check(input,request){supervision?.assertCurrent();const result=await sessions.runEndorsementPolicies.check(input,request);supervision?.assertCurrent();return result;}
      }):null,
      runApprovalEndorsements:sessions.runApprovalEndorsements?Object.freeze({
        createContext(token,options){supervision?.assertCurrent();return sessions.createEndorsementContext(token,options);},
        async endorse(token,request){supervision?.assertCurrent();const result=await sessions.runApprovalEndorsements.endorse(token,request);supervision?.assertCurrent();return result;},
        get(token,id){supervision?.assertCurrent();return sessions.runApprovalEndorsements.get(token,id);},
        lookup(token,request){supervision?.assertCurrent();return sessions.runApprovalEndorsements.lookup(token,request);},
        async checkRunApproval(bindingId,reference){
          supervision?.assertCurrent();const checked=await sessions.runApprovalEndorsements.prepareRunApproval(bindingId,reference);supervision?.assertCurrent();return checked.eligibility;
        },async checkRunInitiator(bindingId,reference,expected){
          supervision?.assertCurrent();const checked=await sessions.runApprovalEndorsements.prepareRunInitiator(bindingId,reference,expected);supervision?.assertCurrent();return checked.eligibility;
        },...(sessions.runApprovalEndorsements.revoke&&{
          createRevocationContext(token,options){supervision?.assertCurrent();return sessions.createEndorsementRevocationContext(token,options);},
          revoke(token,id,request){supervision?.assertCurrent();return sessions.runApprovalEndorsements.revoke(token,id,request);},
          getRevocation(token,id){supervision?.assertCurrent();return sessions.runApprovalEndorsements.getRevocation(token,id);},
          lookupRevocation(token,request){supervision?.assertCurrent();return sessions.runApprovalEndorsements.lookupRevocation(token,request);},
          async deliverRevocation(bindingId,operationId){
            supervision?.assertCurrent();
            if(sessions.runApprovalEndorsements.deliverPendingRevocation)return (await sessions.runApprovalEndorsements.deliverPendingRevocation(operationId,bindingId)).receipt;
            const notice=sessions.runApprovalEndorsements.prepareRevocationDelivery(operationId);
            const result=await peerTransport.deliverRunEndorsementRevocation(bindingId,notice);supervision?.assertCurrent();return result;
          },revocationDeliveryStatus:()=>endorsementRevocationDelivery?.status()??null
        })
      }):null}) : null,
    close() {
      stopping ??= cleanup();
      return stopping;
    }});
  function closeFor(cause) {
    try { if(!closing)referencePublication?.invalidate?.(cause); }
    catch { /* Close the service even when the reference journal is unavailable. */ }
    finally { void application.close().catch(() => {}); }
  }
  supervision?.onLost(() => closeFor('supervisor_lost'));
  timeProviderLink?.onLost(() => closeFor('provider_lost'));
  if(!closing && (referencePublication?.invalidate || (supervision && storage.reconcileReferenceProtection))){
    referenceWatcher=setInterval(()=>{
      try {
        referencePublication?.current();
        const pending=referencePublication?.reconcileProtection?.() ?? storage.reconcileReferenceProtection?.();
        void pending?.catch(()=>{});
      }
      catch { closeFor('authority_changed'); }
    },500);
    referenceWatcher.unref();
  }
  referenceSchedule?.start();
  return application;
}
