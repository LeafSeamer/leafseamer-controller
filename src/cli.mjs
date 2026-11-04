#!/usr/bin/env node
import path from 'node:path';
import {initializeStorage, migrateStorage, openStorage, StorageError} from './storage.mjs';
import {startController} from './server.mjs';
import {startProcessHost, initializeProcessHost, upgradeProcessHost, installedCoreDigest, ProcessHostError} from './process-host.mjs';
import {IdentityError} from './identity-crypto.mjs';
import {requireLocalAdministrator, requirePrivatePipes, readEnrollmentInput} from './local-admin.mjs';

import canonicalize from 'canonicalize';
import {openNativeClock} from './native-clock.mjs';
import {BootstrapError, validateBootstrapPolicy, createCoreBootstrapChannel, verifyCoreAssignment, verifyCoreAdmission} from './core-bootstrap.mjs';
const authenticatedCore = process.argv[2] === 'contained-core-auth';
const emit = value => (authenticatedCore ? process.stderr : process.stdout).write(JSON.stringify(value) + '\n');
let app;
try {
  const [command, ...args] = process.argv.slice(2);
  const allowed = ['init-storage', 'init-process-host', 'upgrade-process-host', 'migrate-storage', 'enroll-admin', 'identity-status', 'register-device'].includes(command) ? ['--data-dir'] : ['start', 'supervise', 'contained-core', 'contained-core-auth'].includes(command) ? ['--data-dir', '--host', '--port', ...(authenticatedCore ? ['--bootstrap-policy'] : [])] : [];
  if (!allowed.length || args.length % 2) throw new Error('arguments');
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.includes(args[i]) || Object.hasOwn(options, args[i])) throw new Error('arguments');
    options[args[i]] = args[i + 1];
  }
  if (!options['--data-dir'] || !path.isAbsolute(options['--data-dir'])) throw new Error('arguments');
  if (command === 'upgrade-process-host') {
    emit(await upgradeProcessHost(options['--data-dir']));
  } else if (command === 'init-process-host') {
    emit(await initializeProcessHost(options['--data-dir']));
  } else if (command === 'init-storage') {
    const identity = initializeStorage(options['--data-dir']);
    emit({event: 'storage_initialized', ...identity, ready: false});
  } else if (command === 'migrate-storage') {
    emit({event: 'storage_migrated', ...await migrateStorage(options['--data-dir']), ready: false});
  } else if (command === 'register-device') {
    requireLocalAdministrator(); requirePrivatePipes();
    const storage = openStorage(options['--data-dir']);
    try { emit({event: 'device_registered', ...storage.registerDevice(await readEnrollmentInput()), ready: false}); }
    finally { storage.close(); }
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
    if (command === 'supervise') {
      app = await startProcessHost({...launch, onCoreOutput: chunk => process.stderr.write(chunk)});
      emit(app.containment);
      const stop = () => { app.close().catch(() => {}); };
      process.once('SIGINT', stop); process.once('SIGTERM', stop);
      const result = await app.exited; emit(result); process.exitCode = result.exitCode;
      process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
    } else {
    const contained = command === 'contained-core' || authenticatedCore;
    if (contained) requirePrivatePipes();
    let channel = null;
    if (authenticatedCore) {
      const rawPolicy = options['--bootstrap-policy'];
      if (typeof rawPolicy !== 'string' || Buffer.byteLength(rawPolicy) > 8192) throw new BootstrapError('bootstrap_policy');
      const policy = validateBootstrapPolicy(JSON.parse(rawPolicy));
      if (canonicalize(policy) !== rawPolicy || policy.artifact_manifest_ref.digest !== installedCoreDigest()) throw new BootstrapError('bootstrap_artifact');
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
        return {binding, policy};
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
      database_instance_id: app.identity.database_instance_id, service_boot_id: app.serviceBootId, ready: false});
    }
  }
} catch (error) {
  if (app) await app.close().catch(() => {});
  process.stderr.write(JSON.stringify({error: error instanceof StorageError || error instanceof IdentityError || error instanceof ProcessHostError || error instanceof BootstrapError ? error.code : 'startup_failed'}) + '\n');
  process.exitCode = 1;
}
