import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {clockInteger} from './native-clock.mjs';

const purpose = 'reference_time_capture';
const format = 'leafseamer-time-provider-capture/1';
const algorithm = 'aes-256-gcm';
const tagLength = 16;
const maximum = 98304;
const identifier = /^[A-Za-z0-9_.:-]{1,128}$/;
const need = (ok, reason) => { if (!ok) throw new Error('time_provider_capture_' + reason); };
const digest = value => 'sha256:' + crypto.createHash('sha256').update(value).digest('hex');

function unpack(value, min, max) {
  need(typeof value === 'string' && value.length <= Math.ceil(max * 4 / 3), 'bytes');
  const bytes = Buffer.from(value, 'base64url');
  need(bytes.length >= min && bytes.length <= max && bytes.toString('base64url') === value, 'bytes');
  return bytes;
}

function ntsIdentifier(packet) {
  let uid=null,offset=48;
  while(offset<packet.length){
    need(packet.length-offset>=4,'nts_extension');
    const type=packet.readUInt16BE(offset),size=packet.readUInt16BE(offset+2),end=offset+size;
    need(size>=4&&size%4===0&&end<=packet.length,'nts_extension');
    if(type===0x0104){
      need(uid===null&&size===36,'nts_identifier');
      uid=packet.subarray(offset+4,end);
    }
    if(type===0x0404){
      need(uid!==null&&end===packet.length&&size>=8,'nts_authenticator');
      return uid;
    }
    offset=end;
  }
  throw new Error('time_provider_capture_nts_authenticator');
}

function validateDatagrams(candidate) {
  const nts = candidate.key_reply !== null;
  const max = nts ? 1232 : 48;
  const req = unpack(candidate.request, 48, max), res = unpack(candidate.response, 48, max);
  try {
    const match = req.subarray(40,48).equals(res.subarray(24,32));
    const nonzero = (data, start) => data.readBigUInt64BE(start) !== 0n;
    need(req[0] === 35 && res[0] === 36 && res[1] >= 1 && res[1] <= 15 && match && nonzero(req,40) &&
      [16,32,40].every(offset => nonzero(res,offset)), 'datagram_binding');
    if (nts) {
      need(ntsIdentifier(req).equals(ntsIdentifier(res)),'nts_identifier');
      const keyReply = unpack(candidate.key_reply, 1, 65536);
      try { need(digest(keyReply) === candidate.key_reply_digest, 'key_reply_digest'); }
      finally { keyReply.fill(0); }
    } else need(candidate.key_reply_digest === null, 'datagram_binding');
  } finally { req.fill(0); res.fill(0); }
}

export function timeProviderCaptureStore(db, identity, protection, publication = null) {
  need(typeof protection?.currentKey === 'function' && typeof protection?.readKey === 'function', 'protection');
  const scope = Object.freeze({service_id: identity.service_id, database_instance_id: identity.database_instance_id, purpose});

  function keyFor(value, expectedId, encrypting) {
    need(value && typeof value.id === 'string' && value.id.trim() === value.id && identifier.test(value.id) &&
      (expectedId === null || value.id === expectedId) && value.service_id === scope.service_id &&
      value.database_instance_id === scope.database_instance_id && value.purpose === purpose &&
      (!encrypting || value.writable === true) && value.key instanceof crypto.KeyObject &&
      value.key.type === 'secret' && value.key.symmetricKeySize === 32, 'key');
    const material = value.key.export();
    try { return {id: value.id, key: value.key, digest: digest(material)}; }
    finally { material.fill(0); }
  }

  function reserveNonce(key) {
    return db.transaction(() => {
      const count = db.prepare('SELECT count(*) FROM time_provider_capture_nonce WHERE key_digest=?').pluck().get(key.digest);
      need(count < 16777216, 'key_capacity');
      const insert = db.prepare('INSERT INTO time_provider_capture_nonce VALUES (?,?,?) ON CONFLICT(key_digest,nonce) DO NOTHING');
      for (let i = 0; i < 8; i++) {
        const nonce = crypto.randomBytes(12);
        if (insert.run(key.digest,nonce,key.id).changes === 1) return nonce;
      }
      throw new Error('time_provider_capture_nonce_unavailable');
    }).immediate();
  }

  function writableKey() {
    const key = keyFor(protection.currentKey(scope),null,true);
    const prior = db.prepare('SELECT key_digest FROM time_provider_capture_nonce WHERE key_id=? LIMIT 1').pluck().get(key.id);
    need(prior === undefined || prior === key.digest, 'key_identity');
    return key;
  }

  function reference(body, value) {
    return {capture_ref: {id: body.capture_id, revision: '1', digest: value}, poll_ref: body.poll_ref,
      attempt_id: body.attempt_id, m1_tick_ns: body.m1_tick_ns, m4_tick_ns: body.m4_tick_ns,
      plaintext_digest: body.plaintext_digest};
  }

  function lookup(pollRef) {
    need(typeof pollRef?.id === 'string' && typeof pollRef.digest === 'string', 'reference');
    const row = db.prepare(`SELECT capture_id,key_id,key_digest,nonce,tag,ciphertext,body_jcs,body_digest,poll_digest
      FROM time_provider_capture WHERE poll_id=?`).raw().get(pollRef.id);
    if (!row) return null;
    const [captureId,keyId,keyDigest,nonce,tag,ciphertext,text,bodyDigest,pollDigest] = row;
    const body = JSON.parse(text);
    need(pollDigest === pollRef.digest && body.poll_ref.id === pollRef.id && body.poll_ref.digest === pollRef.digest &&
      body.format === format && body.algorithm === algorithm && body.capture_id === captureId && body.key_id === keyId &&
      body.service_id === scope.service_id && body.database_instance_id === scope.database_instance_id && body.purpose === purpose &&
      canonicalize(body) === text && digest(text) === bodyDigest && body.plain_bytes === ciphertext.length, 'integrity');
    return {receipt: reference(body,bodyDigest), body,text,keyId,keyDigest,nonce,tag,ciphertext};
  }

  return Object.freeze({
    assertWritable() { writableKey(); },
    store({attempt,reservation,candidate,authorize,network,ntsBootstrap=null}) {
      need(!db.inTransaction, 'outer_transaction');
      authorize();
      validateDatagrams(candidate);
      const m1 = clockInteger(candidate.m1_tick_ns), m4 = clockInteger(candidate.m4_tick_ns);
      need(m1 >= clockInteger(attempt.attempted_tick_ns) && m4 >= m1 && m4 - m1 < 2000000000n &&
        m4 < clockInteger(attempt.valid_before_tick_ns), 'bracket');
      const key = writableKey();
      const plain = Buffer.from(canonicalize(candidate));
      try {
        const body = {format, algorithm, ...scope, key_id:key.id, capture_id:crypto.randomUUID(), attempt_id:attempt.attempt_id,
          runtime_digest:attempt.runtime_digest, poll_ref:attempt.poll_ref, plain_bytes:plain.length, plaintext_digest:digest(plain),
          m1_tick_ns:candidate.m1_tick_ns, m4_tick_ns:candidate.m4_tick_ns};
        const text = canonicalize(body), bodyDigest = digest(text);
        const associated = Buffer.from(text);
        const remainingBytes=reservation.reserved_bytes-(associated.length + plain.length + 12 + tagLength);
        need(plain.length <= maximum && associated.length <= 8192 && remainingBytes>=0,'capacity');
        const receipt=reference(body,bodyDigest);
        const proposed=publication?.prepare({reservation,candidate,receipt,network,attempt,ntsBootstrap});
        const nonce = reserveNonce(key);
        const cipher = crypto.createCipheriv(algorithm,key.key,nonce,{authTagLength:tagLength});
        cipher.setAAD(associated);
        const encrypted = Buffer.concat([cipher.update(plain),cipher.final()]);
        const tag = cipher.getAuthTag();
        db.transaction(() => {
          authorize();
          const inserted = db.prepare('INSERT INTO time_provider_capture VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(
            attempt.poll_ref.id,attempt.attempt_id,attempt.poll_ref.digest,body.capture_id,key.id,key.digest,nonce,tag,
            encrypted,text,bodyDigest);
          need(inserted.changes === 1, 'storage');
          publication?.commit(proposed,remainingBytes);
          authorize();
        }).immediate();
        return receipt;
      } finally { plain.fill(0); }
    },
    lookup(pollRef) { return lookup(pollRef)?.receipt ?? null; },
    release({receipt, acknowledgement, reservation, assertCurrent}) {
      need(!db.inTransaction, 'outer_transaction');
      db.transaction(() => {
        assertCurrent();
        const original = lookup(receipt.poll_ref);
        need(original && canonicalize(original.receipt) === canonicalize(receipt) &&
          canonicalize(acknowledgement.receipt) === canonicalize(receipt) &&
          acknowledgement.binding_digest === reservation.runtime_digest &&
          acknowledgement.type === 'POLL_STORED_ACK', 'acknowledgement');
        const next = clockInteger(receipt.m4_tick_ns) + clockInteger(reservation.authorization.minimum_poll_interval_ns);
        const deadline = String(clockInteger(String(next))).padStart(20,'0');
        const text = canonicalize(acknowledgement);
        need(Buffer.byteLength(text) <= 2048, 'acknowledgement');
        const inserted = db.prepare('INSERT INTO time_provider_poll_release VALUES (?,?,?,?,?,?)').run(
          receipt.poll_ref.id,receipt.capture_ref.id,receipt.capture_ref.digest,deadline,text,digest(text));
        need(inserted.changes === 1, 'release_storage');
        assertCurrent();
      }).immediate();
    },
    read(pollRef) {
      const original = lookup(pollRef);
      if (!original) return null;
      const key = keyFor(protection.readKey(scope,original.keyId),original.keyId,false);
      need(key.digest === original.keyDigest && original.nonce.length === 12 && original.tag.length === tagLength, 'integrity');
      const decipher = crypto.createDecipheriv(algorithm,key.key,original.nonce,{authTagLength:tagLength});
      decipher.setAAD(Buffer.from(original.text));
      decipher.setAuthTag(original.tag);
      const staged = decipher.update(original.ciphertext);
      let plain;
      try {
        try { plain = Buffer.concat([staged,decipher.final()]); }
        catch { throw new Error('time_provider_capture_authentication'); }
        need(plain.length === original.body.plain_bytes && digest(plain) === original.body.plaintext_digest, 'integrity');
        const text = plain.toString('utf8'), candidate = JSON.parse(text);
        need(canonicalize(candidate) === text && candidate.m1_tick_ns === original.body.m1_tick_ns &&
          candidate.m4_tick_ns === original.body.m4_tick_ns, 'integrity');
        validateDatagrams(candidate);
        return {receipt: original.receipt, candidate};
      } finally { staged.fill(0); plain?.fill(0); }
    }
  });
}
