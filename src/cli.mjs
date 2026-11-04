#!/usr/bin/env node
import path from 'node:path';
import {initializeStorage, StorageError} from './storage.mjs';
import {startController} from './server.mjs';

const emit = value => process.stdout.write(JSON.stringify(value) + '\n');
let app;
try {
  const [command, ...args] = process.argv.slice(2);
  const allowed = command === 'init-storage' ? ['--data-dir'] : command === 'start' ? ['--data-dir', '--host', '--port'] : [];
  if (!allowed.length || args.length % 2) throw new Error('arguments');
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.includes(args[i]) || Object.hasOwn(options, args[i])) throw new Error('arguments');
    options[args[i]] = args[i + 1];
  }
  if (!options['--data-dir'] || !path.isAbsolute(options['--data-dir'])) throw new Error('arguments');
  if (command === 'init-storage') {
    const identity = initializeStorage(options['--data-dir']);
    emit({event: 'storage_initialized', ...identity, ready: false});
  } else {
    const rawPort = options['--port'] ?? '0';
    if (!/^(0|[1-9][0-9]{0,4})$/.test(rawPort)) throw new Error('arguments');
    app = await startController({dataDir: options['--data-dir'], host: options['--host'] ?? '127.0.0.1', port: Number(rawPort)});
    const shutdown = async () => {
      try { await app.close(); emit({event: 'stopped'}); }
      catch { process.stderr.write('{"error":"shutdown_failed"}\n'); process.exitCode = 1; }
    };
    process.once('SIGINT', shutdown); process.once('SIGTERM', shutdown);
    emit({event: 'listening', host: app.address.address, port: app.address.port, service_id: app.identity.service_id,
      database_instance_id: app.identity.database_instance_id, service_boot_id: app.serviceBootId, ready: false});
  }
} catch (error) {
  if (app) await app.close().catch(() => {});
  process.stderr.write(JSON.stringify({error: error instanceof StorageError ? error.code : 'startup_failed'}) + '\n');
  process.exitCode = 1;
}
