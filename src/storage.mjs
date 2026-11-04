import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import {identityStore} from './identity-store.mjs';
import {authenticationClockStore} from './auth-clock-store.mjs';
import {sessionStore} from './session-store.mjs';

const sql = fs.readFileSync(new URL('./storage.sql', import.meta.url), 'utf8');
const scriptDigest = 'sha256:' + crypto.createHash('sha256').update(sql).digest('hex');
const identitySql = fs.readFileSync(new URL('./identity.sql', import.meta.url), 'utf8');
const identityDigest = 'sha256:' + crypto.createHash('sha256').update(identitySql).digest('hex');
const clockSql = fs.readFileSync(new URL('./clock.sql', import.meta.url), 'utf8');
const clockDigest = 'sha256:' + crypto.createHash('sha256').update(clockSql).digest('hex');
const authClockSql = fs.readFileSync(new URL('./auth-clock.sql', import.meta.url), 'utf8');
const authClockDigest = 'sha256:' + crypto.createHash('sha256').update(authClockSql).digest('hex');
const sessionSql = fs.readFileSync(new URL('./session.sql', import.meta.url), 'utf8');
const sessionDigest = 'sha256:' + crypto.createHash('sha256').update(sessionSql).digest('hex');
const applicationId = 0x4c53434c;
const engine = Object.freeze({version: '3.53.4', source: '2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc'});
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export class StorageError extends Error {
  constructor(code) { super(code); this.name = 'StorageError'; this.code = code; }
}
function require(ok, code) { if (!ok) throw new StorageError(code); }
function rows(db, sqlText) {
  const stmt = db.prepare(sqlText), names = stmt.columns().map(column => column.name);
  return stmt.raw().all().map(values => Object.fromEntries(names.map((name, index) => [name, values[index]])));
}
function pragma(db, source) {
  const stmt = db.prepare('PRAGMA ' + source);
  if (stmt.reader) return stmt.raw().get()?.[0];
  stmt.run();
}
function filename(dataDir) {
  require(typeof dataDir === 'string' && path.isAbsolute(dataDir), 'absolute_data_directory_required');
  return path.join(path.resolve(dataDir), 'controller.sqlite');
}
function open(file) {
  const db = new Database(file, {fileMustExist: true, timeout: 0});
  try {
    const actual = rows(db, 'SELECT sqlite_version() AS version, sqlite_source_id() AS source')[0];
    require(actual.version === engine.version && actual.source === engine.source, 'sqlite_engine_mismatch');
    pragma(db, 'foreign_keys = ON'); pragma(db, 'trusted_schema = OFF');
    pragma(db, 'locking_mode = EXCLUSIVE');
    pragma(db, 'wal_autocheckpoint = 0');
    require(pragma(db, 'foreign_keys') === 1, 'foreign_keys_unavailable');
    require(pragma(db, 'locking_mode') === 'exclusive', 'exclusive_mode_unavailable');
    require(pragma(db, 'wal_autocheckpoint') === 0, 'checkpoint_mode_unavailable');
    return db;
  } catch (error) { db.close(); throw error; }
}
function identity(db, revision = '1') {
  const records = rows(db, 'SELECT * FROM service_state');
  require(records.length === 1 && records[0].singleton === 1 && records[0].authority === 'controller', 'service_identity_invalid');
  const row = records[0];
  for (const field of ['service_id', 'database_instance_id', 'control_epoch', 'request_epoch']) require(uuid.test(row[field]), 'service_identity_invalid');
  require(row.schema_revision === revision && row.maintenance_state === 'protected' && row.state_revision === '0', 'service_state_invalid');
  return Object.freeze({...row});
}
export function initializeStorage(dataDir) {
  const file = filename(dataDir);
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
  let handle;
  try { handle = fs.openSync(file, 'wx', 0o600); }
  catch (error) { throw new StorageError(error.code === 'EEXIST' ? 'database_already_exists' : 'database_create_failed'); }
  fs.closeSync(handle);
  let db;
  try {
    db = open(file);
    require(pragma(db, 'journal_mode = WAL') === 'wal', 'wal_unavailable');
    pragma(db, 'synchronous = FULL');
    db.transaction(() => {
      db.exec(sql);
      pragma(db, 'application_id = ' + applicationId); pragma(db, 'user_version = 1');
      db.prepare("INSERT INTO service_state VALUES (1, 'controller', ?, ?, ?, ?, '1', 'protected', '0')")
        .run(crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID());
      db.prepare("INSERT INTO schema_migration VALUES (?, '0', '1', ?, NULL, 'committed', ?)")
        .run(crypto.randomUUID(), scriptDigest, crypto.randomUUID());
    }).immediate();
    return identity(db);
  } finally { db?.close(); }
}
function validateStorage(db) {
  const revision = pragma(db, 'user_version');
  require(pragma(db, 'application_id') === applicationId && [1, 2, 3, 4, 5].includes(revision), 'database_version_mismatch');
  require(pragma(db, 'journal_mode') === 'wal', 'journal_mode_mismatch');
  pragma(db, 'synchronous = FULL');
  require(pragma(db, 'synchronous') === 2, 'synchronous_mismatch');
  require(pragma(db, 'quick_check') === 'ok' && rows(db, 'PRAGMA foreign_key_check').length === 0, 'database_integrity');
  const migrations = rows(db, 'SELECT * FROM schema_migration ORDER BY to_revision');
  require(migrations.length === revision && migrations[0].from_revision === '0' && migrations[0].to_revision === '1' && migrations[0].state === 'committed' && migrations[0].script_digest === scriptDigest, 'migration_mismatch');
  for (let i = 1; i < revision; i++) require(migrations[i].from_revision === String(i) && migrations[i].to_revision === String(i + 1) && migrations[i].state === 'committed' && migrations[i].script_digest === [scriptDigest, identityDigest, clockDigest, authClockDigest, sessionDigest][i] && /^sha256:[0-9a-f]{64}$/.test(migrations[i].backup_ref), 'migration_mismatch');
  return identity(db, String(revision));
}
export async function migrateStorage(dataDir, targetRevision = 5) {
  require([2, 3, 4, 5].includes(targetRevision), 'migration_target');
  const file = filename(dataDir);
  let db;
  try {
    db = open(file);
    const state = validateStorage(db);
    const current = Number(state.schema_revision);
    require(targetRevision >= current, 'migration_downgrade');
    if (current === targetRevision) return {schema_revision: String(current), changed: false};
    const steps = [];
    for (let next = current + 1; next <= targetRevision; next++) {
      const backupName = 'controller-before-v' + next + '-' + crypto.randomUUID() + '.sqlite';
      const backupPath = path.join(path.dirname(file), backupName);
      const fd = fs.openSync(backupPath, 'wx', 0o600); fs.closeSync(fd);
      await db.backup(backupPath);
      const backupRef = 'sha256:' + crypto.createHash('sha256').update(fs.readFileSync(backupPath)).digest('hex');
      pragma(db, 'foreign_keys = OFF');
      require(pragma(db, 'foreign_keys') === 0, 'migration_setup_failed');
      db.transaction(() => {
        db.exec([identitySql, clockSql, authClockSql, sessionSql][next - 2]);
        db.prepare("INSERT INTO schema_migration VALUES (?, ?, ?, ?, ?, 'committed', ?)")
          .run(crypto.randomUUID(), String(next - 1), String(next), [identityDigest, clockDigest, authClockDigest, sessionDigest][next - 2], backupRef, crypto.randomUUID());
        pragma(db, 'user_version = ' + next);
        require(rows(db, 'PRAGMA foreign_key_check').length === 0, 'migration_integrity');
      }).immediate();
      pragma(db, 'foreign_keys = ON');
      require(pragma(db, 'foreign_keys') === 1, 'foreign_keys_unavailable');
      validateStorage(db);
      steps.push({schema_revision: String(next), backup_file: backupName, backup_ref: backupRef});
    }
    return {...steps.at(-1), changed: true, steps};
  } catch (error) {
    if (error instanceof StorageError) throw error;
    throw new StorageError(error.code === 'SQLITE_BUSY' ? 'database_in_use' : 'migration_failed');
  } finally { db?.close(); }
}
function clockJournal(db, bootId) {
  let samples = 0;
  return Object.freeze({
    current() {
      const row = db.prepare('SELECT state, reason FROM authentication_clock_diagnostic WHERE service_boot_id = ?').raw().get(bootId);
      require(row !== undefined, 'clock_journal_missing'); return {state: row[0], reason: row[1]};
    },
    sample(capture, artifactDigest) {
      const body = Buffer.from(JSON.stringify(capture));
      require(body.length <= 8192 && /^sha256:[0-9a-f]{64}$/.test(artifactDigest), 'clock_journal_input');
      db.transaction(() => {
        const result = db.prepare("UPDATE authentication_clock_diagnostic SET sequence = sequence + 1, last_capture = ?, native_artifact_digest = ?, reason = 'clock_approval_missing' WHERE service_boot_id = ? AND state = 'unqualified' AND sequence < 9007199254740991")
          .run(body, artifactDigest, bootId);
        require(result.changes === 1, 'clock_journal_closed');
      }).immediate();
      // 当前只有保护态诊断写入；不把此小范围checkpoint当完整业务容量调度。
      if (++samples % 32 === 0) {
        const [busy, log, checkpointed] = db.prepare('PRAGMA wal_checkpoint(PASSIVE)').raw().get();
        require(busy === 0 && log === checkpointed, 'clock_checkpoint_incomplete');
      }
    },
    fault(reason) {
      require(typeof reason === 'string' && /^[a-z_]{1,80}$/.test(reason), 'clock_fault_reason');
      db.transaction(() => {
        db.prepare("UPDATE authentication_clock_diagnostic SET state = 'faulted', reason = ? WHERE service_boot_id = ? AND state = 'unqualified'").run(reason, bootId);
      }).immediate();
    }
  });
}
export function openStorage(dataDir) {
  let db;
  try {
    db = open(filename(dataDir));
    const state = validateStorage(db), bootId = crypto.randomUUID();
    db.transaction(() => {
      db.prepare("INSERT INTO service_boot VALUES (?, ?, ?, ?, NULL, 'started')")
        .run(state.service_id, state.database_instance_id, bootId, new Date().toISOString());
      if (state.schema_revision !== '1') db.prepare("UPDATE first_admin_challenge SET state = 'invalidated' WHERE state = 'pending'").run();
      if (Number(state.schema_revision) >= 3) db.prepare("INSERT INTO authentication_clock_diagnostic VALUES (?, 'unqualified', 'clock_not_sampled', 0, NULL, NULL)").run(bootId);
    }).immediate();
    let closed = false, sessions = null, sessionClock = null;
    return Object.freeze({identity: state, serviceBootId: bootId, engine,
      enrollment: state.schema_revision !== '1' ? identityStore(db, bootId) : null,
      clockJournal: Number(state.schema_revision) >= 3 ? clockJournal(db, bootId) : null,
      authenticationClock: Number(state.schema_revision) >= 4 ? authenticationClockStore(db, {service_id: state.service_id, service_boot_id: bootId}) : null,
      sessions(clock) {
        require(state.schema_revision === '5' && !closed, 'session_migration_required');
        require(clock && typeof clock.current === 'function' && (!sessionClock || sessionClock === clock), 'session_clock_binding');
        sessionClock = clock; sessions ??= sessionStore(db, state.service_id, clock); return sessions;
      },
      close() {
        if (closed) return; closed = true; sessions?.stop();
        try {
          db.transaction(() => {
            if (state.schema_revision !== '1') db.prepare("UPDATE first_admin_challenge SET state = 'invalidated' WHERE service_boot_id = ? AND state = 'pending'").run(bootId);
            db.prepare("UPDATE service_boot SET state = 'stopped', stopped_utc = ? WHERE service_boot_id = ? AND state = 'started'")
            .run(new Date().toISOString(), bootId); }).immediate();
        } finally { db.close(); }
      }});
  } catch (error) {
    if (db?.open) db.close();
    if (error instanceof StorageError) throw error;
    throw new StorageError(error.code === 'SQLITE_BUSY' ? 'database_in_use' : 'database_unavailable');
  }
}
