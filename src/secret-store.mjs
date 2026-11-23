import fs from 'node:fs';
import path from 'node:path';
import {createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID, timingSafeEqual} from 'node:crypto';
import Database from 'better-sqlite3';
import {canonical} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';

const keyFile = 'leafseamer-master-key';
const ledgerFile = 'nonce.sqlite';
const profile = 'leafseamer-secret-store/1';
const limit = 65536;
const ledgerBudget = 2 ** 24;
const flags = fs.constants;
const atom = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}(?![\s\S])/.test(value);
const need = (ok, reason) => { if (!ok) throw new IdentityError('secret_store_' + reason); };
const keyIdentity = key => createHmac('sha256', key).update('LeafSeamer/secret-store/key-identity/v1').digest('hex');

function privateDirectory(location) {
  need(process.platform === 'linux' && typeof location === 'string' && path.isAbsolute(location), 'profile');
  const fd = fs.openSync(location, flags.O_RDONLY | flags.O_DIRECTORY | flags.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    need(stat.isDirectory() && stat.uid === process.geteuid() && (stat.mode & 0o077) === 0, 'directory_permissions');
    return {fd, location: '/proc/self/fd/' + fd, identity: stat.dev + ':' + stat.ino};
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function verifyFile(fd, maximum, readOnly = false) {
  const stat = fs.fstatSync(fd);
  need(stat.isFile() && stat.uid === process.geteuid() && (stat.mode & 0o400) !== 0 &&
    (stat.mode & (readOnly ? 0o377 : 0o077)) === 0 &&
    stat.size > 0 && stat.size <= maximum, 'file_permissions');
}

function readKey(directory) {
  const fd = fs.openSync(path.join(directory.location, keyFile), flags.O_RDONLY | flags.O_NOFOLLOW | flags.O_NONBLOCK);
  try {
    verifyFile(fd, 32, true);
    const info = fs.readFileSync('/proc/self/fdinfo/' + fd, 'utf8');
    const match = /^mnt_id:\s+(\d+)$/m.exec(info);
    const mount = match && fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n').find(line => line.startsWith(match[1] + ' '));
    need(mount?.split(' ')[5]?.split(',').includes('ro'), 'credential_mount');
    const bytes = fs.readFileSync(fd);
    if (bytes.length !== 32) { bytes.fill(0); need(false, 'key'); }
    return bytes;
  } finally { fs.closeSync(fd); }
}

function createFile(filename, contents, mode = 0o600) {
  const fd = fs.openSync(filename, 'wx', mode);
  try { fs.writeFileSync(fd, contents); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}

function protectedLedger(directory, options) {
  const filename = path.join(directory.location, ledgerFile);
  const handle = fs.openSync(filename, flags.O_RDONLY | flags.O_NOFOLLOW | flags.O_NONBLOCK);
  try { verifyFile(handle, 1073741824); } finally { fs.closeSync(handle); }
  return new Database(filename, {fileMustExist: true, timeout: 1000, ...options});
}

export function initializeLinuxSecretStore({owner, directory, credentialDirectory}) {
  need(atom(owner), 'owner');
  let store, credentials, db, key;
  try {
    store = privateDirectory(directory);
    credentials = privateDirectory(credentialDirectory);
    need(store.identity !== credentials.identity && fs.readdirSync(store.location).length === 0 &&
      fs.readdirSync(credentials.location).length === 0, 'initialize_existing');
    key = randomBytes(32);
    const keyId = keyIdentity(key);
    const filename = path.join(store.location, ledgerFile);
    createFile(filename, Buffer.alloc(0));
    db = new Database(filename, {fileMustExist: true, timeout: 1000});
    db.pragma('synchronous = FULL');
    db.transaction(() => {
      db.exec(`CREATE TABLE secret_store_identity (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), owner TEXT NOT NULL, key_id TEXT NOT NULL
      ) STRICT;
      CREATE TABLE secret_nonce (
        reservation INTEGER PRIMARY KEY CHECK(reservation BETWEEN 1 AND 16777216),
        nonce BLOB NOT NULL UNIQUE CHECK(length(nonce)=12)
      ) STRICT;
      CREATE TRIGGER secret_nonce_no_update BEFORE UPDATE ON secret_nonce
      BEGIN SELECT RAISE(ABORT, 'immutable_nonce'); END;
      CREATE TRIGGER secret_nonce_no_delete BEFORE DELETE ON secret_nonce
      BEGIN SELECT RAISE(ABORT, 'immutable_nonce'); END;`);
      db.prepare('INSERT INTO secret_store_identity VALUES (1, ?, ?)').run(owner, keyId);
    }).immediate();
    db.close(); db = null;
    fs.fsyncSync(store.fd);
    createFile(path.join(credentials.location, keyFile), key, 0o400);
    fs.fsyncSync(credentials.fd);
    return {profile_id: profile, owner_service_id: owner, key_id: keyId};
  } catch (error) {
    if (error instanceof IdentityError) throw error;
    throw new IdentityError('secret_store_initialize');
  } finally {
    key?.fill(0);
    db?.close();
    if (store) fs.closeSync(store.fd);
    if (credentials) fs.closeSync(credentials.fd);
  }
}

export function openLinuxSecretStore({owner, directory, credentialDirectory, readonly = false}) {
  need(atom(owner), 'owner');
  let store, credentials, db, key, opened = false;
  try {
    store = privateDirectory(directory);
    credentials = privateDirectory(credentialDirectory);
    need(store.identity !== credentials.identity, 'directory_binding');
    key = readKey(credentials);
    const keyId = keyIdentity(key);
    db = protectedLedger(store, {readonly});
    if (!readonly) db.pragma('synchronous = FULL');
    const bound = db.prepare('SELECT owner,key_id FROM secret_store_identity WHERE singleton=1').raw().get();
    need(bound?.[0] === owner && bound[1] === keyId && db.pragma('quick_check', {simple: true}) === 'ok', 'ledger_binding');

    function header(ref) {
      need(!closed && ref && Object.keys(ref).sort().join(',') === 'owner_service_id,purpose,secret_id,version' &&
        ref.owner_service_id === owner && atom(ref.secret_id) && typeof ref.version === 'string' && /^(?:[1-9][0-9]{0,8})(?![\s\S])/.test(ref.version) &&
        ref.purpose === 'obs_websocket', 'reference');
      return {profile_id: profile, owner_service_id: owner, secret_id: ref.secret_id,
        version: ref.version, purpose: ref.purpose, key_id: keyId};
    }
    const targetFor = head => path.join(store.location, head.secret_id + '.' + head.version + '.secret');
    function decode(value, length) {
      need(typeof value === 'string' && value.length <= Math.ceil(length * 4 / 3), 'envelope');
      const bytes = Buffer.from(value, 'base64url');
      need(bytes.length <= length && bytes.toString('base64url') === value, 'envelope');
      return bytes;
    }
    function read(ref) {
      const head = header(ref);
      let partial, last;
      try {
        const fd = fs.openSync(targetFor(head), flags.O_RDONLY | flags.O_NOFOLLOW | flags.O_NONBLOCK);
        let text;
        try { verifyFile(fd, 98304); text = fs.readFileSync(fd, 'utf8'); }
        finally { fs.closeSync(fd); }
        const envelope = JSON.parse(text);
        need(canonical(envelope) === text && Object.keys(envelope).sort().join(',') === 'ciphertext,header,nonce,tag' &&
          canonical(envelope.header) === canonical(head), 'envelope');
        const nonce = decode(envelope.nonce, 12), tag = decode(envelope.tag, 16);
        need(nonce.length === 12 && tag.length === 16 && db.prepare('SELECT 1 FROM secret_nonce WHERE nonce=?').pluck().get(nonce) === 1, 'envelope');
        const decipher = createDecipheriv('aes-256-gcm', key, nonce, {authTagLength: 16});
        decipher.setAAD(Buffer.from(canonical(head)));
        decipher.setAuthTag(tag);
        partial = decipher.update(decode(envelope.ciphertext, limit));
        last = decipher.final();
        return Buffer.concat([partial, last]);
      } catch (error) {
        if (error instanceof IdentityError) throw error;
        throw new IdentityError(error.code === 'ENOENT' ? 'secret_store_missing' : 'secret_store_envelope');
      } finally { partial?.fill(0); last?.fill(0); }
    }
    const reserve = db.transaction(() => {
      need(db.prepare('SELECT coalesce(max(reservation),0) FROM secret_nonce').pluck().get() < ledgerBudget, 'nonce_budget');
      const insert = db.prepare('INSERT INTO secret_nonce(nonce) VALUES (?) ON CONFLICT(nonce) DO NOTHING');
      for (let attempts = 0; attempts < 8; attempts++) {
        const nonce = randomBytes(12);
        if (insert.run(nonce).changes === 1) return nonce;
      }
      need(false, 'nonce_collision');
    });
    function write(ref, plaintext) {
      const head = header(ref);
      need(!readonly && Buffer.isBuffer(plaintext) && plaintext.length >= 1 && plaintext.length <= limit, 'write');
      const target = targetFor(head);
      const matches = () => {
        let previous;
        try {
          previous = read(ref);
          need(previous.length === plaintext.length && timingSafeEqual(previous, plaintext), 'version_conflict');
          return true;
        } catch (error) {
          if (error.code === 'secret_store_missing') return false;
          throw error;
        } finally { previous?.fill(0); }
      };
      let temporary;
      try {
        if (matches()) { fs.fsyncSync(store.fd); return; }
        const nonce = reserve.immediate();
        const cipher = createCipheriv('aes-256-gcm', key, nonce, {authTagLength: 16});
        cipher.setAAD(Buffer.from(canonical(head)));
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        temporary = path.join(store.location, '.pending-' + randomUUID());
        createFile(temporary, canonical({header: head, nonce: nonce.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'),
          ciphertext: ciphertext.toString('base64url')}));
        try { fs.linkSync(temporary, target); }
        catch (error) { if (error.code !== 'EEXIST' || !matches()) throw error; }
        fs.fsyncSync(store.fd);
      } catch (error) {
        if (error instanceof IdentityError) throw error;
        throw new IdentityError('secret_store_publish');
      } finally {
        if (temporary) {
          try { fs.unlinkSync(temporary); } catch {}
        }
      }
    }
    let closed = false;
    opened = true;
    return Object.freeze({read, write, close() {
      if (closed) return;
      closed = true;
      key.fill(0); db.close(); fs.closeSync(store.fd);
    }});
  } catch (error) {
    if (error instanceof IdentityError) throw error;
    throw new IdentityError('secret_store_unavailable');
  } finally {
    if (credentials) fs.closeSync(credentials.fd);
    if (!opened) {
      key?.fill(0); db?.close();
      if (store) fs.closeSync(store.fd);
    }
  }
}
