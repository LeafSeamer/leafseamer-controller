import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {decodeBootstrap, decodeProtectedLaunchIntent, bootstrapVersion} from './sdk/bootstrap.mjs';

export class BootstrapError extends Error { constructor(code) { super(code); this.name = 'BootstrapError'; this.code = code; } }
const check = (ok, code) => { if (!ok) throw new BootstrapError(code); };
const digest = value => 'sha256:' + crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same = (a, b) => canonicalize(a) === canonicalize(b);
const proofFields = ['bootstrap_version', 'bootstrap_id', 'launch_id', 'launch_intent_digest', 'member_id', 'member_boot_id', 'role',
  'artifact_manifest_ref', 'channel_binding_id', 'challenge_id'];
const scalar = /^[A-Za-z0-9_.:-]+$(?![\s\S])/;

export function validateBootstrapPolicy(input) {
  const keys = (v, names) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === names.split(',').sort().join(',');
  const id = v => typeof v === 'string' && v.length <= 128 && scalar.test(v);
  const revision = v => typeof v === 'string' && /^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(v);
  check(keys(input, 'format,service_id,database_instance_id,artifact_manifest_ref,platform_profile_ref,policy_revision,bootstrap_timeout_ms,clock_backend_revision') &&
    input.format === 'leafseamer-core-bootstrap-policy/1' && id(input.service_id) && id(input.database_instance_id) && id(input.clock_backend_revision) &&
    revision(input.policy_revision) && Number.isInteger(input.bootstrap_timeout_ms) && input.bootstrap_timeout_ms >= 1 && input.bootstrap_timeout_ms <= 60000,
    'bootstrap_policy');
  const a = input.artifact_manifest_ref, p = input.platform_profile_ref;
  check(keys(a, 'manifest_id,revision,digest') && id(a.manifest_id) && revision(a.revision) && typeof a.digest === 'string' &&
    /^sha256:[0-9a-f]{64}$(?![\s\S])/.test(a.digest) && keys(p, 'profile_id,revision') && id(p.profile_id) && revision(p.revision), 'bootstrap_policy');
  return Object.freeze({...input, artifact_manifest_ref: Object.freeze({...a}), platform_profile_ref: Object.freeze({...p})});
}

// 只接受已经由独立SDK入口解析的对象；政策由可信本机装配提供，不能由网络或Assignment自证。
export function verifyCoreAssignment(assignment, policy, identity) {
  const descriptor = assignment.clock_domain_descriptor;
  check(assignment.role === 'core' && descriptor.authority_service_id === identity.service_id && policy.service_id === identity.service_id &&
    policy.database_instance_id === identity.database_instance_id, 'bootstrap_scope');
  check(same(assignment.artifact_manifest_ref, policy.artifact_manifest_ref) && descriptor.platform_profile_id === policy.platform_profile_ref.profile_id &&
    descriptor.platform_profile_revision === policy.platform_profile_ref.revision && descriptor.clock_backend_revision === policy.clock_backend_revision &&
    descriptor.clock_backend_id === 'windows_interrupt_precise' && descriptor.namespace_identity === 'windows-global' &&
    descriptor.tick_unit === 'ns' && descriptor.suspend_accounting === 'included', 'bootstrap_policy');
  for (const value of Object.values(descriptor)) if (typeof value === 'string') check(value === 'clock-domain/1' || scalar.test(value), 'bootstrap_descriptor');
  const {clock_domain_id, descriptor_digest, ...body} = descriptor;
  check(digest(body) === descriptor_digest && clock_domain_id === 'clock_' + descriptor_digest.slice(7), 'bootstrap_descriptor');
  check(BigInt(assignment.expires_tick_ns) > BigInt(assignment.issued_tick_ns) &&
    BigInt(assignment.expires_tick_ns) - BigInt(assignment.issued_tick_ns) === BigInt(policy.bootstrap_timeout_ms) * 1000000n, 'bootstrap_window');
}

export function coreProof(assignment) {
  const base = Object.fromEntries(proofFields.map(name => [name, assignment[name]]));
  const descriptor = assignment.clock_domain_descriptor;
  const domain = {clock_domain_id: descriptor.clock_domain_id, descriptor_digest: descriptor.descriptor_digest};
  const projection = {...base, ...domain, challenge_nonce: assignment.challenge_nonce, issued_tick_ns: assignment.issued_tick_ns, expires_tick_ns: assignment.expires_tick_ns};
  const key = Buffer.from(assignment.secret, 'base64url');
  check(key.length === 32 && key.toString('base64url') === assignment.secret, 'bootstrap_secret');
  try {
    const proof = crypto.createHmac('sha256', key).update('leafseamer-bootstrap-proof/v1\0', 'ascii').update(canonicalize(projection), 'utf8').digest('base64url');
    return {version: bootstrapVersion, type: 'PROOF', payload: {...base, ...domain, proof}};
  } finally { key.fill(0); }
}

export async function verifyCoreAdmission(assignment, receipt, policy) {
  for (const name of proofFields.filter(n => !['bootstrap_version', 'challenge_id'].includes(n))) check(same(receipt[name], assignment[name]), 'bootstrap_receipt_binding');
  const descriptor = assignment.clock_domain_descriptor;
  check(receipt.gate_state === 'closed' && receipt.domain_ref.clock_domain_id === descriptor.clock_domain_id &&
    receipt.domain_ref.descriptor_digest === descriptor.descriptor_digest && receipt.containment_ref.backend === 'windows_job', 'bootstrap_receipt_binding');
  check(BigInt(receipt.admitted_tick_ns) >= BigInt(assignment.issued_tick_ns) && BigInt(receipt.admitted_tick_ns) < BigInt(assignment.expires_tick_ns), 'bootstrap_receipt_expired');
  const intent = await decodeProtectedLaunchIntent(Buffer.from(canonicalize({launch_id: receipt.launch_id, service_id: policy.service_id,
    supervisor_instance_id: descriptor.supervisor_instance_id, runtime_generation: descriptor.runtime_generation, member_id: receipt.member_id, role: 'core',
    artifact_manifest_ref: receipt.artifact_manifest_ref, containment_ref: receipt.containment_ref, device_ids: [], policy_revision: policy.policy_revision})));
  check(digest(intent) === assignment.launch_intent_digest, 'bootstrap_intent');
  return Object.freeze({intent, descriptor, receipt});
}

export function createCoreBootstrapChannel(input, output, {timeoutMs}) {
  check(Number.isInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 60000, 'bootstrap_timeout');
  let pending = null, buffer = Buffer.alloc(0), state = 'await_assignment', failed = null;
  const stop = error => { failed ??= error; const call = pending; pending = null; if (call) { clearTimeout(call.timer); call.reject(failed); } };
  const onData = chunk => {
    if (failed) return;
    if (!Buffer.isBuffer(chunk) || !pending || buffer.length + chunk.length > 16385) { stop(new BootstrapError('bootstrap_frame')); return; }
    buffer = Buffer.concat([buffer, chunk]); const end = buffer.indexOf(10);
    if (end < 0) return;
    if (end !== buffer.length - 1) { stop(new BootstrapError('bootstrap_frame')); return; }
    const call = pending; pending = null; clearTimeout(call.timer); const bytes = buffer.subarray(0, end); buffer = Buffer.alloc(0); call.resolve(bytes);
  };
  const onEnd = () => stop(new BootstrapError('bootstrap_channel_closed'));
  input.on('data', onData); input.on('end', onEnd); input.on('error', onEnd); output.on('error', onEnd);
  const read = type => new Promise((resolve, reject) => {
    if (failed) { reject(failed); return; }
    check(!pending, 'bootstrap_concurrent');
    const timer = setTimeout(() => stop(new BootstrapError('bootstrap_timeout')), timeoutMs);
    pending = {resolve, reject, timer};
  }).then(bytes => decodeBootstrap(bytes, type));
  return Object.freeze({
    async assignment() { check(state === 'await_assignment', 'bootstrap_state'); state = 'reading_assignment'; const frame = await read('ASSIGNMENT'); state = 'assignment_received'; return frame.payload; },
    async proveAndReceive(assignment) {
      check(state === 'assignment_received', 'bootstrap_state'); state = 'proof_sent';
      const proof = canonicalize(coreProof(assignment));
      const received = read('ADMISSION');
      output.write(proof + '\n', error => { if (error) stop(new BootstrapError('bootstrap_channel_closed')); });
      const frame = await received; state = 'admitted_closed'; return frame.payload;
    },
    release() { check(state === 'admitted_closed' && !failed && !pending && buffer.length === 0, 'bootstrap_state');
      input.pause(); input.removeListener('data', onData); input.removeListener('end', onEnd); input.removeListener('error', onEnd); output.removeListener('error', onEnd); state = 'released'; },
    close() { stop(new BootstrapError('bootstrap_channel_closed')); input.removeListener('data', onData); input.removeListener('end', onEnd); input.removeListener('error', onEnd); output.removeListener('error', onEnd); },
  });
}
