#!/usr/bin/env node
import path from 'node:path';
import {initializeStorage, migrateStorage, openStorage, StorageError} from './storage.mjs';
import {currentStorageRevision} from './storage-revision.mjs';
import {startController} from './server.mjs';
import {startProcessHost, initializeProcessHost, upgradeProcessHost, installedCoreDigest, ProcessHostError} from './process-host.mjs';
import {IdentityError} from './identity-crypto.mjs';
import {requireLocalAdministrator, requirePrivatePipes, readEnrollmentInput} from './local-admin.mjs';

import canonicalize from 'canonicalize';
import {openNativeClock} from './native-clock.mjs';
import {BootstrapError, validateBootstrapPolicy, createCoreBootstrapChannel, verifyCoreAssignment, verifyCoreAdmission} from './core-bootstrap.mjs';
import {connectCoreSupervisor, SupervisorError} from './supervisor-control.mjs';
import {openTrustedControllerClock, readTrustedPairingProfile, readTrustedStandaloneProfile} from './trusted-pairing-profile.mjs';
import {readProtectedIngressProfile} from './protected-ingress-profile.mjs';
import {LocalPairingError, runLocalPairingAdmin} from './local-pairing-admin.mjs';
import {discoverObsScenes,inspectObsCut,ObsDiscoveryError} from './obs-discovery.mjs';
import {initializeLinuxSecretStore,initializeWindowsSecretStore,openLinuxSecretStore,openWindowsSecretStore} from './secret-store.mjs';
import {windowsSecretDirectory} from './windows-secret-files.mjs';
const authenticatedCore = process.argv[2] === 'contained-core-auth';
const emit = value => (authenticatedCore ? process.stderr : process.stdout).write(JSON.stringify(value) + '\n');
const trustedStartupError = code => /^(pairing_(profile|clock)|standalone_profile)_[a-z_]+$/.test(code);
let app;
try {
  const [command, ...args] = process.argv.slice(2);
  const obsInspector=command==='inspect-obs'?discoverObsScenes:command==='inspect-obs-cut'?inspectObsCut:null;
  const secretCommands = ['init-obs-secret-store', 'seal-obs-resource-credential', 'observe-obs-resource'];
  const allowed = secretCommands.includes(command) ? ['--data-dir','--secret-dir',...(command==='init-obs-secret-store'?['--new-key-dir']:[])] :
    command === 'start-protected-ingress' ? ['--data-dir','--ingress-profile'] :
    command === 'pairing-admin' ? ['--origin','--ca-file'] : command === 'migrate-storage' ? ['--data-dir', '--to-revision'] : ['init-storage', 'init-process-host', 'upgrade-process-host', 'enroll-admin', 'identity-status', 'register-device', 'register-obs-resource'].includes(command) ? ['--data-dir'] : ['start', 'supervise', 'contained-core', 'contained-core-auth'].includes(command) ? ['--data-dir', '--host', '--port', ...(authenticatedCore ? ['--bootstrap-policy', '--supervisor-pipe', '--supervisor-channel','--time-provider-intent'] : []), ...((authenticatedCore || command === 'supervise') ? ['--pairing-profile','--standalone-profile'] : []), ...(command==='supervise'?['--stdin-control']:[])] : [];
  if ((!allowed.length && !obsInspector) || args.length % 2) throw new Error('arguments');
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.includes(args[i]) || Object.hasOwn(options, args[i])) throw new Error('arguments');
    options[args[i]] = args[i + 1];
  }
  if (command !== 'pairing-admin' && !obsInspector && (!options['--data-dir'] || !path.isAbsolute(options['--data-dir']))) throw new Error('arguments');
  if (obsInspector) {
    requirePrivatePipes();
    emit({event:command==='inspect-obs'?'obs_discovered':'obs_cut_checked',...await obsInspector(await readEnrollmentInput())});
  } else if (command === 'pairing-admin') {
    requirePrivatePipes();
    const bytes = await runLocalPairingAdmin({origin: options['--origin'], caFile: options['--ca-file'], input: await readEnrollmentInput()});
    process.stdout.write(bytes);
  } else if (command === 'upgrade-process-host') {
    emit(await upgradeProcessHost(options['--data-dir']));
  } else if (command === 'init-process-host') {
    emit(await initializeProcessHost(options['--data-dir']));
  } else if (command === 'init-storage') {
    const identity = initializeStorage(options['--data-dir']);
    emit({event: 'storage_initialized', ...identity, ready: false});
  } else if (command === 'migrate-storage') {
    const target = options['--to-revision'];
    if (target !== undefined && target!=='current' && !/^[1-9][0-9]*$/.test(target)) throw new Error('arguments');
    emit({event: 'storage_migrated', ...await migrateStorage(options['--data-dir'], target==='current'?currentStorageRevision:target===undefined?undefined:Number(target)), ready: false});
  } else if (command === 'register-device') {
    requireLocalAdministrator(); requirePrivatePipes();
    const storage = openStorage(options['--data-dir']);
    try { emit({event: 'device_registered', ...storage.registerDevice(await readEnrollmentInput()), ready: false}); }
    finally { storage.close(); }
  } else if (command === 'register-obs-resource') {
    requireLocalAdministrator(); requirePrivatePipes();
    const storage = openStorage(options['--data-dir']);
    try {
      const result = await storage.registerObsResource(await readEnrollmentInput());
      emit({event: 'obs_resource_registered', ...result, ready: false});
    } finally { storage.close(); }
  } else if (secretCommands.includes(command)) {
    requireLocalAdministrator();
    if (command !== 'init-obs-secret-store') requirePrivatePipes();
    const windows=process.platform==='win32', dataDir=options['--data-dir'];
    const windowsDirectory=windows?windowsSecretDirectory(dataDir):null;
    const directory=options['--secret-dir']??(windows&&command!=='observe-obs-resource'?windowsDirectory:undefined);
    if(!directory&&command!=='observe-obs-resource')throw new Error('arguments');
    if(windows&&(options['--new-key-dir']||(directory&&path.resolve(directory)!==windowsDirectory)))throw new Error('arguments');
    for(const location of [directory,options['--new-key-dir']].filter(Boolean)){
      if(!path.isAbsolute(location))throw new Error('arguments');
      const relative=path.relative(options['--data-dir'],location);
      if(!relative||(!path.isAbsolute(relative)&&!relative.startsWith('..'+path.sep)&&relative!=='..'))throw new Error('arguments');
    }
    const storage = openStorage(options['--data-dir']);
    let secrets;
    try {
      const owner=storage.identity.service_id;
      if(command==='init-obs-secret-store'){
        const initialize=windows?initializeWindowsSecretStore:initializeLinuxSecretStore;
        const result=initialize({owner,directory,credentialDirectory:options['--new-key-dir']});
        emit({event:'obs_secret_store_initialized',...result,ready:false});
      }else{
        const input=await readEnrollmentInput();
        const open=windows?openWindowsSecretStore:openLinuxSecretStore;
        if(directory)secrets=open({owner,directory,credentialDirectory:process.env.CREDENTIALS_DIRECTORY,readonly:command==='observe-obs-resource'});
        if(command==='seal-obs-resource-credential'){
          const result=await storage.sealObsResourceCredential(input,secrets);
          emit({event:'obs_resource_credential_sealed',...result,ready:false});
        }else{
          const result=await storage.observeObsResource(input,secrets);
          emit({event:'obs_resource_observed',...result,ready:false});
        }
      }
    } finally { secrets?.close(); storage.close(); }
  } else if (command === 'enroll-admin' || command === 'identity-status') {
    requireLocalAdministrator();
    if (command === 'enroll-admin') requirePrivatePipes();
    const storage = openStorage(options['--data-dir']);
    try {
      if (!storage.enrollment) throw new IdentityError('identity_migration_required');
      if (command === 'identity-status') emit({event: 'identity_status', ...storage.enrollment.summary(), ready: false});
      else {
        // 唯一一次秘密交付只写受控本机管道，不经普通日志、argv或环境变量。
        emit({event: 'initialization_capability', ...storage.enrollment.begin()});
        const result = await storage.enrollment.complete(await readEnrollmentInput());
        emit({event: 'identity_initialized', ...result, ready: false});
      }
    } finally { storage.close(); }
  } else {
    const rawPort = options['--port'] ?? '0';
    if (!/^(0|[1-9][0-9]{0,4})$/.test(rawPort)) throw new Error('arguments');
    const launch = {dataDir: options['--data-dir'], host: options['--host'] ?? '127.0.0.1', port: Number(rawPort)};
    if (command === 'start-protected-ingress') Object.assign(launch, readProtectedIngressProfile(options['--ingress-profile']));
    const pairingPath=options['--pairing-profile'],standalonePath=options['--standalone-profile'];
    if(pairingPath!==undefined&&standalonePath!==undefined)throw new Error('standalone_profile_conflict');
    let profile=null;
    if(standalonePath!==undefined)profile=readTrustedStandaloneProfile(standalonePath,launch.host,launch.port);
    if(pairingPath!==undefined)profile=readTrustedPairingProfile(pairingPath,launch.host,launch.port);
    if (command === 'supervise') {
      const stdinControl=options['--stdin-control'];
      if(stdinControl!==undefined){
        if(stdinControl!=='pipe')throw new Error('arguments');
        requirePrivatePipes();
      }
      app = await startProcessHost({...launch, onCoreOutput: chunk => process.stderr.write(chunk),
        ...(profile && {bootstrapPolicy: profile.policy, pairingProfile: pairingPath??null, standaloneProfile: standalonePath??null})});
      emit(app.containment);
      const stop = () => { app.close().catch(() => {}); };
      process.once('SIGINT', stop); process.once('SIGTERM', stop);
      let control='';
      const receive=data=>{
        if(control.length+data.length<=5)control+=data;
        else control='';
        if(control==='stop\n'||control===''||!'stop\n'.startsWith(control)){process.stdin.pause();stop();}
      };
      if(stdinControl){process.stdin.setEncoding('utf8').on('data',receive).once('end',stop).once('error',stop);process.stdin.resume();}
      try{const result=await app.exited;emit(result);process.exitCode=result.exitCode;}
      finally{
        process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);
        if(stdinControl){process.stdin.removeListener('data',receive).removeListener('end',stop).removeListener('error',stop);process.stdin.destroy();}
      }
    } else {
    const contained = command === 'contained-core' || authenticatedCore;
    if (contained) requirePrivatePipes();
    let channel = null;
    if (authenticatedCore) {
      const rawPolicy = options['--bootstrap-policy'];
      if (typeof rawPolicy !== 'string' || Buffer.byteLength(rawPolicy) > 8192) throw new BootstrapError('bootstrap_policy');
      const policy = validateBootstrapPolicy(JSON.parse(rawPolicy));
      if (canonicalize(policy) !== rawPolicy || policy.artifact_manifest_ref.digest !== installedCoreDigest()) throw new BootstrapError('bootstrap_artifact');
      if (profile && canonicalize(profile.policy) !== rawPolicy) throw new BootstrapError(standalonePath===undefined?'pairing_profile_bootstrap':'standalone_profile_bootstrap');
      let admittedCore;
      if (profile) {
        launch.tls = profile.tls;
        if(profile.pairing){launch.pairing=profile.pairing;launch.localPairingManagement=true;}
        launch.standalone=standalonePath!==undefined;
        if (profile.gui) {
          launch.guiDirectory = profile.gui.directory;
          launch.guiManifestSha256 = profile.gui.manifest_sha256;
        }
        launch.authenticationProvider = async input => {
          try { return await openTrustedControllerClock(profile, input, admittedCore.binding, admittedCore.supervision, emit); }
          catch (error) {
            const reason = error.code ?? error.message;
            // 核心关闭控制通道前交付诊断，此后由宿主确认退役。
            await new Promise(resolve => process.stderr.write(JSON.stringify({event: 'authentication_clock_rejected',
              reason: trustedStartupError(reason) ? reason : 'pairing_clock_evidence_invalid'}) + '\n', resolve));
            throw error;
          }
        };
      }
      channel = createCoreBootstrapChannel(process.stdin, process.stdout, {timeoutMs: policy.bootstrap_timeout_ms});
      launch.coreBootstrap = async identity => {
        const source = openNativeClock();
        let assignment = await channel.assignment();
        verifyCoreAssignment(assignment, policy, identity);
        const current = () => {
          const tick = source.tick();
          if (tick < BigInt(assignment.issued_tick_ns) || tick >= BigInt(assignment.expires_tick_ns)) throw new BootstrapError('bootstrap_expired');
        };
        current();
        const receipt = await channel.proveAndReceive(assignment);
        current();
        const binding = await verifyCoreAdmission(assignment, receipt, policy);
        current(); assignment = null;
        channel.release();
        const supervision = await connectCoreSupervisor({pipe: options['--supervisor-pipe'], channelId: options['--supervisor-channel'],
          binding, policy, timeProviderIntent: options['--time-provider-intent'] ?? null});
        admittedCore = {binding, policy, supervision};
        return admittedCore;
      };
    }
    try { app = await startController(launch); }
    catch (error) { channel?.close(); if (contained) process.stdin.destroy(); throw error; }
    let shuttingDown = false;
    const shutdown = async () => {
      if (shuttingDown) return; shuttingDown = true;
      if (contained) { process.stdin.removeAllListeners('data'); process.stdin.removeAllListeners('end'); process.stdin.destroy(); }
      try { await app.close(); emit({event: 'stopped'}); }
      catch { process.stderr.write('{"error":"shutdown_failed"}\n'); process.exitCode = 1; }
    };
    process.once('SIGINT', shutdown); process.once('SIGTERM', shutdown);
    if (contained) {
      let control = '';
      process.stdin.setEncoding('utf8').on('data', data => {
        control += data;
        if (control === 'stop\n' || control.length >= 5 || !'stop\n'.startsWith(control)) void shutdown();
      });
      process.stdin.once('end', shutdown);
      process.stdin.once('error', shutdown);
      process.stdin.resume();
    }
    emit({event: 'listening', host: app.address.address, port: app.address.port, service_id: app.identity.service_id,
      database_instance_id: app.identity.database_instance_id, service_boot_id: app.serviceBootId,
      ...(app.pairing && {pairing_origin: app.pairing.transport.origin}), ready: false});
    }
  }
} catch (error) {
  if (app) await app.close().catch(() => {});
  const code = error.code ?? error.message;
  const known = error instanceof StorageError || error instanceof IdentityError || error instanceof ProcessHostError ||
    error instanceof BootstrapError || error instanceof SupervisorError || error instanceof LocalPairingError ||
    error instanceof ObsDiscoveryError || trustedStartupError(code) ||
    ['protected_ingress_profile','protected_ingress_platform','protected_ingress_address'].includes(code);
  process.stderr.write(JSON.stringify({error: known ? code : 'startup_failed'}) + '\n');
  process.exitCode = 1;
}
