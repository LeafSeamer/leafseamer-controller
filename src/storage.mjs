import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';

const sql = fs.readFileSync(new URL('./storage.sql', import.meta.url), 'utf8');
const scriptDigest = 'sha256:' + crypto.createHash('sha256').update(sql).digest('hex');
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
    require(pragma(db, 'foreign_keys') === 1, 'foreign_keys_unavailable');
    require(pragma(db, 'locking_mode') === 'exclusive', 'exclusive_mode_unavailable');
    return db;
  } catch (error) { db.close(); throw error; }
}
function identity(db) {
  const records = rows(db, 'SELECT * FROM service_state');
  require(records.length === 1 && records[0].singleton === 1 && records[0].authority === 'controller', 'service_identity_invalid');
  const row = records[0];
  for (const field of ['service_id', 'database_instance_id', 'control_epoch', 'request_epoch']) require(uuid.test(row[field]), 'service_identity_invalid');
  require(row.schema_revision === '1' && row.maintenance_state === 'protected' && row.state_revision === '0', 'service_state_invalid');
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
export function openStorage(dataDir) {
  let db;
  try {
    db = open(filename(dataDir));
    // 未知库先拒绝，不对缺失或其它版本静默建库／迁移。
    require(pragma(db, 'application_id') === applicationId && pragma(db, 'user_version') === 1, 'database_version_mismatch');
    require(pragma(db, 'journal_mode') === 'wal', 'journal_mode_mismatch');
    pragma(db, 'synchronous = FULL');
    require(pragma(db, 'synchronous') === 2, 'synchronous_mismatch');
    require(pragma(db, 'quick_check') === 'ok' && rows(db, 'PRAGMA foreign_key_check').length === 0, 'database_integrity');
    const migrations = rows(db, 'SELECT * FROM schema_migration');
    require(migrations.length === 1 && migrations[0].to_revision === '1' && migrations[0].state === 'committed' && migrations[0].script_digest === scriptDigest, 'migration_mismatch');
    const state = identity(db), bootId = crypto.randomUUID();
    db.transaction(() => {
      db.prepare("INSERT INTO service_boot VALUES (?, ?, ?, ?, NULL, 'started')")
        .run(state.service_id, state.database_instance_id, bootId, new Date().toISOString());
    }).immediate();
    let closed = false;
    return Object.freeze({identity: state, serviceBootId: bootId, engine,
      close() {
        if (closed) return; closed = true;
        try {
          db.transaction(() => { db.prepare("UPDATE service_boot SET state = 'stopped', stopped_utc = ? WHERE service_boot_id = ? AND state = 'started'")
            .run(new Date().toISOString(), bootId); }).immediate();
        } finally { db.close(); }
      }});
  } catch (error) {
    if (db?.open) db.close();
    if (error instanceof StorageError) throw error;
    throw new StorageError(error.code === 'SQLITE_BUSY' ? 'database_in_use' : 'database_unavailable');
  }
}
