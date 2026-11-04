import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {createOpaqueSecret, opaqueVerifier, verifyOpaqueSecret, hashPassword, verifyPassword, passwordProfile} from '../dist/identity-crypto.mjs';
import {requireLocalAdministrator} from '../dist/local-admin.mjs';

const password = 'synthetic-admin-password-012345';
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-identity-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  return dir;
}
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
const input = capability => ({token_id: capability.token_id, secret: capability.secret, login: 'synthetic-admin', password, mode: 'standalone'});

test('固定密码profile实际计算、验证与并发预算', {timeout: 20000}, async () => {
  const phc = await hashPassword(password);
  assert.match(phc, /^\$argon2id\$v=19\$m=65536,p=1,t=3\$/);
  assert.equal(await verifyPassword(password, phc), true);
  assert.equal(await verifyPassword(password + 'different', phc), false);
  await assert.rejects(verifyPassword(password, phc.replace('m=65536', 'm=999999999')), e => e.code === 'password_profile');
  await assert.rejects(verifyPassword(password, phc, 'unknown'), e => e.code === 'password_profile');
  await assert.rejects(verifyPassword(password, phc + '\n'), e => e.code === 'password_profile');
  await assert.rejects(hashPassword('short'), e => e.code === 'password_input');
  await assert.rejects(hashPassword(password + '\ud800'), e => e.code === 'password_input');
  const results = await Promise.allSettled(Array.from({length: 11}, () => hashPassword(password)));
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 10);
  assert.equal(results[10].reason.code, 'password_busy');
  assert.equal(new Set(results.slice(0, 10).map(r => r.value)).size, 10);
});

test('随机秘密按用途分域，非规范尾位与跨用途拒绝', () => {
  const {secret, verifier} = createOpaqueSecret('first_admin');
  assert.equal(secret.length, 43);
  assert(verifyOpaqueSecret('first_admin', secret, verifier));
  assert.equal(verifyOpaqueSecret('access_token', secret, verifier), false);
  const expected = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('LeafSeamer/opaque-verifier/v1\0first_admin\0'), Buffer.from(secret, 'base64url')])).digest();
  assert.deepEqual(verifier, expected);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const altered = secret.slice(0, -1) + alphabet[alphabet.indexOf(secret.at(-1)) | 1];
  assert.throws(() => opaqueVerifier('first_admin', altered), e => e.code === 'secret_encoding');
  assert.throws(() => opaqueVerifier('first_admin', secret + '='), e => e.code === 'secret_encoding');
  assert.throws(() => opaqueVerifier('custom_kind', secret), e => e.code === 'secret_kind');
});

test('显式v2迁移保留scope与启动历史，并生成可校验v1备份', async t => {
  const dir = temporary(t), original = initializeStorage(dir);
  const first = openStorage(dir); first.close();
  const migrated = await migrateStorage(dir);
  assert.equal(migrated.changed, true);
  const backup = fs.readFileSync(path.join(dir, migrated.backup_file));
  assert.equal(migrated.backup_ref, 'sha256:' + crypto.createHash('sha256').update(backup).digest('hex'));
  const backupDb = new Database(path.join(dir, migrated.backup_file), {readonly: true, fileMustExist: true});
  try {
    assert.equal(backupDb.pragma('user_version', {simple: true}), 1);
    assert.equal(backupDb.prepare('SELECT service_id FROM service_state').pluck().get(), original.service_id);
  } finally { backupDb.close(); }
  const second = openStorage(dir);
  try {
    assert.equal(second.identity.service_id, original.service_id);
    assert.equal(second.identity.database_instance_id, original.database_instance_id);
    assert.equal(second.identity.control_epoch, original.control_epoch);
    assert.equal(second.identity.request_epoch, original.request_epoch);
    assert.equal(second.identity.schema_revision, '2');
    assert.deepEqual(second.enrollment.summary(), {initialized: false});
    await assert.rejects(migrateStorage(dir), e => e.code === 'database_in_use');
  } finally { second.close(); }
  assert.deepEqual(await migrateStorage(dir), {schema_revision: '2', changed: false});
  assert.equal(inspect(dir, db => db.prepare('SELECT count(*) FROM service_boot').pluck().get()), 2);
});

test('首次管理员、能力消费与回执同库提交；重开可查原且不能再初始化', async t => {
  const dir = temporary(t); initializeStorage(dir); await migrateStorage(dir);
  const app = openStorage(dir), capability = app.enrollment.begin();
  let result;
  try {
    const submitted = input(capability);
    const pending = app.enrollment.complete(submitted);
    submitted.login = '\u0000'; // 异步KDF期间不能换掉已验证输入。
    result = await pending;
    assert.deepEqual(app.enrollment.summary(), result);
    assert.throws(() => app.enrollment.begin(), e => e.code === 'identity_already_initialized');
    await assert.rejects(app.enrollment.complete(input(capability)), e => e.code === 'identity_already_initialized');
  } finally { app.close(); }
  const data = inspect(dir, db => ({
    password: db.prepare('SELECT password_phc FROM local_principal').pluck().get(),
    login: db.prepare('SELECT login FROM local_principal').pluck().get(),
    consumed: db.prepare('SELECT state FROM first_admin_challenge').pluck().get(),
    receipt: db.prepare('SELECT count(*) FROM identity_receipt').pluck().get(),
    foreignKeys: db.prepare('PRAGMA foreign_key_check').raw().all()
  }));
  assert.equal(data.login, 'synthetic-admin'); assert.equal(data.consumed, 'consumed'); assert.equal(data.receipt, 1);
  assert.deepEqual(data.foreignKeys, []); assert(await verifyPassword(password, data.password, passwordProfile));
  const disk = fs.readFileSync(path.join(dir, 'controller.sqlite'));
  assert.equal(disk.includes(Buffer.from(password)), false); assert.equal(disk.includes(Buffer.from(capability.secret)), false);
  const reopened = openStorage(dir);
  try { assert.deepEqual(reopened.enrollment.summary(), result); }
  finally { reopened.close(); }
});

test('错误能力、截止等号与旧boot能力拒绝，不留管理员', async t => {
  const dir = temporary(t); initializeStorage(dir); await migrateStorage(dir);
  let app = openStorage(dir);
  const old = app.enrollment.begin();
  await assert.rejects(app.enrollment.complete({...input(old), secret: createOpaqueSecret('first_admin').secret}), e => e.code === 'initialization_capability_invalid');
  app.close(); app = openStorage(dir);
  try {
    await assert.rejects(app.enrollment.complete(input(old)), e => e.code === 'initialization_capability_invalid');
    const now = process.hrtime.bigint();
    t.mock.method(process.hrtime, 'bigint', () => now);
    const expiring = app.enrollment.begin();
    process.hrtime.bigint.mock.mockImplementation(() => now + 600_000_000_000n);
    await assert.rejects(app.enrollment.complete(input(expiring)), e => e.code === 'initialization_capability_invalid');
    t.mock.restoreAll();
    assert.deepEqual(app.enrollment.summary(), {initialized: false});
  } finally { app.close(); t.mock.restoreAll(); }
});

test('初始化每个写入失败均回滚完整身份与能力消费', {timeout: 20000}, async t => {
  for (const table of ['identity_issuer', 'subject', 'local_principal', 'local_authorization', 'first_admin_challenge', 'identity_initialization', 'identity_receipt']) {
    const dir = temporary(t); initializeStorage(dir); await migrateStorage(dir);
    inspect(dir, db => db.exec(`CREATE TRIGGER injected_failure BEFORE ${table === 'first_admin_challenge' ? 'UPDATE' : 'INSERT'} ON ${table} ${table === 'first_admin_challenge' ? "WHEN NEW.state = 'consumed'" : ''} BEGIN SELECT RAISE(ABORT, 'injected'); END;`));
    const app = openStorage(dir), capability = app.enrollment.begin();
    try {
      await assert.rejects(app.enrollment.complete(input(capability)), /injected/);
      assert.deepEqual(app.enrollment.summary(), {initialized: false});
    } finally { app.close(); }
    inspect(dir, db => {
      for (const name of ['identity_issuer', 'subject', 'local_principal', 'local_authorization', 'identity_initialization', 'identity_receipt']) assert.equal(db.prepare(`SELECT count(*) FROM ${name}`).pluck().get(), 0, name);
      assert.equal(db.prepare("SELECT count(*) FROM first_admin_challenge WHERE state = 'consumed'").pluck().get(), 0);
      db.exec('DROP TRIGGER injected_failure');
    });
  }
});

test('本机CLI拒绝非管理员，绝不提供绕过参数或消费秘密', t => {
  let authorized = false;
  try { requireLocalAdministrator(); authorized = true; } catch (e) { assert.equal(e.code, 'local_administrator_required'); }
  if (authorized) { t.skip('此用例需要非管理员账户'); return; }
  const dir = temporary(t), cli = fileURLToPath(new URL('../dist/cli.mjs', import.meta.url));
  const result = spawnSync(process.execPath, ['--disallow-code-generation-from-strings', cli, 'enroll-admin', '--data-dir', dir], {encoding: 'utf8', windowsHide: true, timeout: 10000});
  assert.equal(result.status, 1); assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr).error, 'local_administrator_required');
  assert.equal(fs.existsSync(path.join(dir, 'controller.sqlite')), false);
});

test('并发消费最多一个管理员；KDF完成时仍重核截止', async t => {
  const dir = temporary(t); initializeStorage(dir); await migrateStorage(dir);
  const app = openStorage(dir);
  try {
    const now = process.hrtime.bigint(); t.mock.method(process.hrtime, 'bigint', () => now);
    const expiring = app.enrollment.begin();
    const pending = app.enrollment.complete(input(expiring));
    process.hrtime.bigint.mock.mockImplementation(() => now + 600_000_000_000n);
    await assert.rejects(pending, e => e.code === 'initialization_capability_invalid');
    t.mock.restoreAll();
    const capability = app.enrollment.begin();
    const results = await Promise.allSettled([app.enrollment.complete(input(capability)), app.enrollment.complete({...input(capability), login: 'another-admin'})]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(results.find(r => r.status === 'rejected').reason.code, 'identity_already_initialized');
  } finally { app.close(); t.mock.restoreAll(); }
  assert.equal(inspect(dir, db => db.prepare('SELECT count(*) FROM local_principal').pluck().get()), 1);
});

test('升级途中DDL失败整笔回滚，既有v1仍可启动', async t => {
  const dir = temporary(t), original = initializeStorage(dir);
  const first = openStorage(dir); first.close();
  inspect(dir, db => db.exec('CREATE TABLE identity_receipt (injected INTEGER)'));
  await assert.rejects(migrateStorage(dir), e => e.code === 'migration_failed');
  inspect(dir, db => {
    assert.equal(db.pragma('user_version', {simple: true}), 1);
    assert.equal(db.prepare('SELECT count(*) FROM schema_migration').pluck().get(), 1);
    assert.equal(db.prepare('SELECT schema_revision FROM service_state').pluck().get(), '1');
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(), []);
    db.exec('DROP TABLE identity_receipt');
  });
  const reopened = openStorage(dir);
  try { assert.deepEqual(reopened.identity, original); }
  finally { reopened.close(); }
});

test('本机继承管道可读有界输入，超限及UTF8错误拒绝', () => {
  const moduleUrl = new URL('../dist/local-admin.mjs', import.meta.url).href;
  const script = `import {requirePrivatePipes,readEnrollmentInput} from ${JSON.stringify(moduleUrl)}; try { requirePrivatePipes(); const v=await readEnrollmentInput(); console.log(JSON.stringify({fields:Object.keys(v).sort()})); } catch(e) { console.error(JSON.stringify({error:e.code})); process.exitCode=1; }`;
  const invoke = inputBytes => spawnSync(process.execPath, ['--disallow-code-generation-from-strings', '--input-type=module', '-e', script], {input: inputBytes, encoding: 'utf8', windowsHide: true, timeout: 10000});
  const valid = invoke(JSON.stringify({login: 'synthetic', password}));
  assert.equal(valid.status, 0, valid.stderr); assert.deepEqual(JSON.parse(valid.stdout).fields, ['login', 'password']);
  for (const bytes of [Buffer.alloc(65537, 32), Buffer.from([0xff])]) {
    const invalid = invoke(bytes); assert.equal(invalid.status, 1); assert.equal(JSON.parse(invalid.stderr).error, 'initialization_input');
  }
});
