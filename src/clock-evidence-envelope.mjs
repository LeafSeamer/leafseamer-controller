import crypto from 'node:crypto';
import {canonical, fields, need} from './auth-clock-value.mjs';

export const clockEvidenceFormat = 'leafseamer.authentication-clock-evidence/1';

export function verifyClockEvidence(bytes, key) {
  const packet = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
  fields(packet, ['format', 'evidence', 'signature']);
  const {format, evidence, signature} = packet;
  need(format === clockEvidenceFormat && canonical(packet) === bytes.toString('utf8') &&
    typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature), 'pairing_clock_encoding');
  const signed = Buffer.from(signature, 'base64url');
  need(signed.toString('base64url') === signature &&
    crypto.verify(null, Buffer.from(format + '\0' + canonical(evidence)), key, signed), 'pairing_clock_signature');
  return evidence;
}

export function authenticationClockChallenge(scope, databaseInstanceId, source, capture, domain = null) {
  return {event: 'authentication_clock_challenge', ...scope, database_instance_id: databaseInstanceId,
    native_binary_digest: source.artifactDigest, continuity: capture.continuity, tick_ns: String(source.tick()),
    ...(domain && {clock_domain_id: domain.clock_domain_id, descriptor_digest: domain.descriptor_digest})};
}
