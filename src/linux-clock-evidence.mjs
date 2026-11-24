import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {canonical, context, fields, need} from './auth-clock-value.mjs';
import {clockInteger} from './native-clock.mjs';
import {pairingUuid} from './peer-pairing-value.mjs';
import {authenticationClockChallenge, verifyClockEvidence} from './clock-evidence-envelope.mjs';

const flags = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
const json = bytes => JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
const absolute = value => typeof value === 'string' && path.isAbsolute(value) && value !== '/' &&
  path.normalize(value) === value && !value.endsWith('/');

function protectedDirectory(directory) {
  need(absolute(directory), 'linux_clock_evidence_profile');
  const uid = process.geteuid();
  for (let current = directory; current !== '/'; current = path.dirname(current)) {
    const stat = fs.lstatSync(current);
    const stickyParent = current !== directory && ['/tmp', '/var/tmp'].includes(current) &&
      stat.uid === 0 && (stat.mode & 0o1000) !== 0;
    need(stat.isDirectory() && (stat.uid === 0 || stat.uid === uid) &&
      ((stat.mode & 0o022) === 0 || stickyParent), 'linux_clock_evidence_directory');
  }
}

function read(file, limit) {
  need(absolute(file), 'linux_clock_evidence_file');
  const directory = path.dirname(file);
  if (directory !== '/') protectedDirectory(directory);
  const fd = fs.openSync(file, flags);
  try {
    const stat = fs.fstatSync(fd);
    need(stat.isFile() && stat.size > 0 && stat.size <= limit && (stat.mode & 0o022) === 0 &&
      (stat.uid === 0 || stat.uid === process.geteuid()), 'linux_clock_evidence_file');
    const bytes = Buffer.alloc(stat.size + 1);
    let offset = 0, count;
    while (offset < bytes.length && (count = fs.readSync(fd, bytes, offset, bytes.length - offset, null)) > 0) offset += count;
    need(offset === stat.size, 'linux_clock_evidence_file');
    return bytes.subarray(0, offset);
  } finally { fs.closeSync(fd); }
}

export function readLinuxClockEvidenceProfile(file, policy, role) {
  try {
    need(process.platform === 'linux', 'linux_clock_evidence_platform');
    const profile = json(read(file, 16384));
    fields(profile, ['format', 'service_id', 'database_instance_id', 'policy_digest', 'public_key_file', 'exchange_directory']);
    const {format, service_id, database_instance_id, policy_digest, public_key_file, exchange_directory} = profile;
    pairingUuid(service_id); pairingUuid(database_instance_id);
    const authentication = role === 'controller' && format === 'leafseamer.controller-linux-clock-evidence-profile/2';
    need((authentication || (role === 'controller' || role === 'seamer') && format === 'leafseamer.'+role+'-linux-clock-evidence-profile/1') && service_id === policy.service_id &&
      database_instance_id === policy.database_instance_id && typeof policy_digest === 'string' &&
      policy_digest.length === 71 && /^sha256:[0-9a-f]{64}$/.test(policy_digest), 'linux_clock_evidence_profile');
    protectedDirectory(exchange_directory);
    const key = crypto.createPublicKey(read(public_key_file, 16384));
    need(key.asymmetricKeyType === 'ed25519', 'linux_clock_evidence_profile');
    return Object.freeze({policy_digest, exchange_directory, key, authentication});
  } catch { throw Object.assign(new Error('linux_clock_evidence_profile'), {code: 'linux_clock_evidence_profile'}); }
}

// Publish a complete challenge without replacing an existing file or alias.
function publishChallenge(directory, challenge) {
  protectedDirectory(directory);
  const file = path.join(directory, 'challenge-'+challenge.service_boot_id+'.json');
  const temp = path.join(directory, '.challenge-'+crypto.randomUUID());
  const fd = fs.openSync(temp, 'wx', 0o600);
  try {
    try { fs.writeFileSync(fd, canonical(challenge)); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    fs.linkSync(temp, file);
  } finally { fs.unlinkSync(temp); }
}

export function inspectLinuxClockEvidence(profile, scope, {policy, binding}, source) {
  const {descriptor, receipt} = binding;
  need(descriptor.clock_backend_id === 'linux_boottime' && descriptor.authority_service_id === scope.service_id &&
    receipt.containment_ref.backend === 'linux_cgroup_v2' && receipt.gate_state === 'closed', 'linux_clock_evidence_binding');
  pairingUuid(scope.service_boot_id);
  const challenge = authenticationClockChallenge(scope, policy.database_instance_id, source, source.capture(), descriptor);
  const directory = profile.exchange_directory;
  publishChallenge(directory, challenge);
  const evidenceFile = path.join(directory, 'evidence-'+scope.service_boot_id+'.json');
  function current() {
    let bytes;
    try {
      bytes = read(evidenceFile, 65536);
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
    const evidence = verifyClockEvidence(bytes, profile.key);
    const capture = source.capture(), now = source.tick();
    need(evidence?.policy?.digest === profile.policy_digest && capture.continuity === challenge.continuity &&
      evidence.runtime?.continuity === challenge.continuity && evidence.runtime.clock_domain_id === challenge.clock_domain_id &&
      evidence.runtime.descriptor_digest === challenge.descriptor_digest && evidence.health?.state === 'synchronized',
      'linux_clock_evidence_binding');
    context(evidence, scope, source.artifactDigest, now);
    need(clockInteger(evidence.health.valid_before_tick_ns) <= now + clockInteger(evidence.policy.sample_ttl_ns),
      'linux_clock_evidence_binding');
    return evidence;
  }
  return Object.freeze({
    read: current,
    status() {
      try { return current() === null ? 'missing' : 'verified'; }
      catch (error) { return error.code === 'auth_clock_evidence_expired' ? 'expired' : 'rejected'; }
    }
  });
}
