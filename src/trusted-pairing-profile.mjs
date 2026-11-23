import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {isIP} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import {canonical,context,fields} from './auth-clock-value.mjs';
import {pairingUuid} from './peer-pairing-value.mjs';
import {validateBootstrapPolicy} from './core-bootstrap.mjs';

const evidenceFormat = 'leafseamer.authentication-clock-evidence/1';
const hash = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const read = (file, limit = 65536) => {
  if (typeof file !== 'string' || !path.isAbsolute(file) || !fs.statSync(file).isFile()) throw new Error('local_file');
  const fd = fs.openSync(file, 'r');
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > limit) throw new Error('local_file_size');
    const bytes = Buffer.alloc(stat.size + 1);
    let offset = 0, count;
    while (offset < bytes.length && (count = fs.readSync(fd, bytes, offset, bytes.length - offset, null)) > 0) offset += count;
    if (offset !== stat.size) throw new Error('local_file_size');
    return bytes.subarray(0, offset);
  } finally { fs.closeSync(fd); }
};
const json = bytes => JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
const need = (condition, code) => { if (!condition) throw Object.assign(new Error(code), {code}); };
function httpsOrigin(value) {
  const url = new URL(value);
  need(url.protocol === 'https:' && url.origin === value, 'pairing_profile_endpoint');
  return url;
}

export function readTrustedPairingProfile(file, host, port) {
  try {
    const profile = json(read(file)), {bootstrap, https, local, seamer, clock} = profile;
    fields(profile, ['format', 'bootstrap', 'https', 'local', 'seamer', 'clock', ...(Object.hasOwn(profile, 'gui') ? ['gui'] : [])]);
    need(profile.format === 'leafseamer.controller-pairing-profile/1', 'pairing_profile_format');
    const policy = validateBootstrapPolicy(bootstrap);
    pairingUuid(policy.service_id); pairingUuid(policy.database_instance_id);
    fields(https, ['origin', 'certificate_file', 'private_key_file']);
    const site = httpsOrigin(https.origin), hostname = host === '::1' ? '[::1]' : host;
    need(site.hostname === hostname && Number(site.port || 443) === port, 'pairing_profile_endpoint');
    fields(local, ['credential_id', 'host', 'port', 'certificate_file', 'private_key_file', 'ca_files',
      ...(Object.hasOwn(local,'network')?['network']:[]), ...(Object.hasOwn(local,'server_name')?['server_name']:[])]);
    fields(seamer, ['identity', 'origin', 'server_name', 'certificate_file', 'trust_bundle_digest']);
    fields(seamer.identity, ['service_id', 'database_instance_id', 'service_kind', 'issuer_id', 'issuer_epoch', 'credential_id']);
    fields(clock, ['policy_digest', 'evidence_file', 'public_key_file']);
    const {service_kind, ...ids} = seamer.identity;
    Object.values(ids).forEach(pairingUuid); pairingUuid(local.credential_id);
    httpsOrigin(seamer.origin);
    const network=local.network===true;
    need(service_kind === 'seamer' && ids.service_id !== policy.service_id &&
      (['127.0.0.1', '::1'].includes(local.host)||network&&isIP(local.host)!==0) &&
      (!Object.hasOwn(local,'network')||typeof local.network==='boolean') &&
      (!Object.hasOwn(local,'server_name')||typeof local.server_name==='string'&&local.server_name.length>0&&local.server_name.length<=253) &&
      Number.isInteger(local.port) && local.port > 0 && local.port <= 65535 && !(local.host === host && local.port === port) &&
      Array.isArray(local.ca_files) && local.ca_files.length > 0 && local.ca_files.length <= 8 &&
      typeof seamer.server_name === 'string' && seamer.server_name.length > 0 && seamer.server_name.length <= 253 &&
      hash(seamer.trust_bundle_digest) && hash(clock.policy_digest) && typeof clock.evidence_file === 'string' &&
      path.isAbsolute(clock.evidence_file), 'pairing_profile_scope');
    const key = crypto.createPublicKey(read(clock.public_key_file, 16384));
    need(key.asymmetricKeyType === 'ed25519', 'pairing_profile_signer');
    const gui = profile.gui ?? null;
    if (Object.hasOwn(profile, 'gui')) {
      fields(gui, ['directory', 'manifest_sha256']);
      need(typeof gui.directory === 'string' && path.isAbsolute(gui.directory) && hash(gui.manifest_sha256), 'pairing_profile_gui');
    }
    return {policy, gui, clock: {...clock, key}, tls: {origin: https.origin, cert: read(https.certificate_file), key: read(https.private_key_file)},
      pairing: {credential_id: local.credential_id, host: local.host, port: local.port, network, serverName:local.server_name??local.host, cert: read(local.certificate_file),
        key: read(local.private_key_file), ca: local.ca_files.map(file => read(file)), peers: [{identity: seamer.identity,
          origin: seamer.origin, server_name: seamer.server_name, trust_bundle_digest: seamer.trust_bundle_digest,
          cert: read(seamer.certificate_file).toString('utf8')}]}};
  } catch { throw Object.assign(new Error('pairing_profile_invalid'), {code: 'pairing_profile_invalid'}); }
}

export async function openTrustedPairingClock(profile, {scope, source}, binding, supervision, emit) {
  const {policy, clock} = profile, domain = binding.descriptor;
  supervision.assertCurrent();
  need(scope.service_id === policy.service_id && domain.authority_service_id === scope.service_id, 'pairing_profile_identity');
  const capture = source.capture();
  need(capture.continuity_available, 'pairing_clock_continuity');
  function current(allowPreviousBoot = false) {
    supervision.assertCurrent();
    let bytes;
    try { bytes = read(clock.evidence_file); }
    catch (error) { if (allowPreviousBoot && error.code === 'ENOENT') return null; throw error; }
    const packet = json(bytes);
    fields(packet, ['format', 'evidence', 'signature']);
    const {format, evidence, signature} = packet;
    need(format === evidenceFormat && canonical(packet) === bytes.toString('utf8') &&
      typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), 'pairing_clock_encoding');
    const signed = Buffer.from(signature, 'base64url');
    need(signed.toString('base64url') === signature &&
      crypto.verify(null, Buffer.from(format + '\0' + canonical(evidence)), clock.key, signed), 'pairing_clock_signature');
    need(evidence.policy?.digest === clock.policy_digest && evidence.runtime?.service_id === scope.service_id, 'pairing_clock_policy');
    if (allowPreviousBoot && evidence.runtime.service_boot_id !== scope.service_boot_id) return null;
    context(evidence, scope, source.artifactDigest, source.tick());
    need(evidence.runtime.clock_domain_id === domain.clock_domain_id && evidence.runtime.descriptor_digest === domain.descriptor_digest &&
      evidence.runtime.continuity === capture.continuity, 'pairing_clock_domain');
    return evidence;
  }
  emit({event: 'authentication_clock_challenge', ...scope, database_instance_id: policy.database_instance_id,
    native_binary_digest: source.artifactDigest, continuity: capture.continuity, tick_ns: String(source.tick()),
    clock_domain_id: domain.clock_domain_id, descriptor_digest: domain.descriptor_digest});
  const deadline = performance.now() + 10000;
  for (;;) {
    if (current(true)) return {read: () => current()};
    need(performance.now() < deadline, 'pairing_clock_evidence_unavailable');
    await delay(50);
  }
}
