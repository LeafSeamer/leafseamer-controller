import fs from 'node:fs';
import canonicalize from 'canonicalize';
import {bootstrapDeviceWorker} from '../../dist/worker-bootstrap.mjs';

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const options = {input: process.stdin, output: process.stdout, intentBytes: Buffer.from(canonicalize(config.intent)),
  identity: config.identity, descriptor: config.descriptor, timeoutMs: config.timeoutMs};
process.stderr.write(JSON.stringify({event: 'waiting'}) + '\n');
try {
  const pending = bootstrapDeviceWorker(options);
  if (config.mutate) {
    options.intentBytes.fill(32); options.identity.service_id = 'changed'; options.descriptor.runtime_generation = 'changed';
  }
  const result = await pending;
  process.stderr.write(JSON.stringify({event: 'closed', result,
    frozen: Object.isFrozen(result) && Object.isFrozen(result.intent.extension_binding) && Object.isFrozen(result.receipt)}) + '\n');
} catch (error) {
  process.stderr.write(JSON.stringify({event: 'rejected', code: error.code ?? error.reason ?? 'invalid'}) + '\n');
  process.exitCode = 1;
} finally { process.stdin.destroy(); }
