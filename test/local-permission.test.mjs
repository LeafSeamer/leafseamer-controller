import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';
import {localIdentityPermissions} from '../dist/local-permission-store.mjs';
import {fixture} from './auth-clock-fixture.mjs';

const login = {login: 'synthetic-local-admin', password: 'synthetic-local-password-012345'};
const input = x => ({credential_id: x.credential_id, secret: x.secret, csrf: x.csrf});
const tokenInput = x => ({token_id: x.token.token_id, secret: x.secret});
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
function directory(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-permissions-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  return dir;
}
async function enroll(storage) {
  const c = storage.enrollment.begin();
  return storage.enrollment.complete({...login, mode: 'standalone', token_id: c.token_id, secret: c.secret});
}
async function setup(t, beforeOpen = () => {}) {
  const dir = directory(t); initializeStorage(dir); await migrateStorage(dir); beforeOpen(dir);
  const storage = openStorage(dir); await enroll(storage);
  const f = fixture(storage.authenticationClock.scope), realClock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  const state = {offset: 0n};
  const clock = {current() { const v = realClock.current(); return {...v, lower_ns: String(BigInt(v.lower_ns) + state.offset), upper_ns: String(BigInt(v.upper_ns) + state.offset)}; }};
  const sessions = storage.sessions(clock), logged = await sessions.login(login), credentials = input(logged);
  const issue = (scopes = ['identity.read'], audience = storage.identity.service_id) => sessions.issueToken(credentials, {request_id: crypto.randomUUID(), audience, requested_scopes: scopes});
  const change = (permissions, revision = sessions.localPermissions(credentials).revision) => ({request_id: crypto.randomUUID(), principal_id: logged.session.principal_id, expected_revision: revision, permissions});
  return {dir, storage, realClock, sessions, logged, credentials, issue, change, f, state, close() { realClock.stop(); storage.close(); }};
}

test('持久管理员权限成为默认真实token来源，不使用合成权限解析器', async t => {
  const app = await setup(t); let grant;
  try {
    grant = app.sessions.localPermissions(app.credentials);
    assert.deepEqual(grant.permissions, localIdentityPermissions); assert.equal(grant.revision, '1');
    const token = app.issue(), verified = app.sessions.verifyToken(tokenInput(token), app.storage.identity.service_id);
    assert.equal(verified.active, true); assert.deepEqual(verified.permissions, ['identity.read']);
    assert.throws(() => app.issue(['device.command']), e => e.code === 'local_authorization_denied');
    assert.throws(() => app.issue(['identity.read'], crypto.randomUUID()), e => e.code === 'local_authorization_audience');
  } finally { app.close(); }
  inspect(app.dir, db => {
    assert.equal(JSON.parse(db.prepare('SELECT body FROM local_permission_revision').pluck().get().toString()).digest, grant.digest);
    assert.equal(db.prepare('SELECT count(*) FROM access_token').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM session_audience').pluck().get(), 1);
    assert.throws(() => db.exec("UPDATE local_permission_revision SET state = 'pending'"));
    assert.throws(() => db.exec('DELETE FROM local_permission_head'));
  });
});

test('权限增收按CAS落新版本并终止旧token，幂等查原不增加修订', async t => {
  const app = await setup(t);
  try {
    const old = app.issue(), request = app.change([...localIdentityPermissions, 'device.read']);
    const operation = app.sessions.replaceLocalPermissions(app.credentials, request);
    assert.equal(operation.reduced, false); assert.equal(operation.state, 'pending');
    assert.equal(app.sessions.localPermissions(app.credentials).revision, '2');
    assert.deepEqual(app.sessions.replaceLocalPermissions(app.credentials, request), operation);
    assert.throws(() => app.sessions.replaceLocalPermissions(app.credentials, {...request, permissions: [...localIdentityPermissions]}), e => e.code === 'local_authorization_conflict');
    assert.throws(() => app.sessions.replaceLocalPermissions(app.credentials, app.change([...localIdentityPermissions], '1')), e => e.code === 'local_authorization_revision');
    assert.throws(() => app.sessions.verifyToken(tokenInput(old), app.storage.identity.service_id), e => e.code === 'token_invalid');
    const next = app.issue(['device.read']); assert.equal(app.sessions.verifyToken(tokenInput(next), app.storage.identity.service_id).active, true);
  } finally { app.close(); }
  inspect(app.dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM local_permission_revision').pluck().get(), 2);
    assert.equal(db.prepare('SELECT count(*) FROM local_permission_operation').pluck().get(), 1);
  });
});

test('减收固定全部关联目标并保持pending，不能重新签发或复活旧token', async t => {
  const remote = crypto.randomUUID();
  const app = await setup(t, dir => inspect(dir, db => db.exec(`CREATE TRIGGER synthetic_target AFTER INSERT ON auth_session BEGIN
    INSERT INTO session_target_binding VALUES (NEW.session_id, '${remote}', 'synthetic-subscription', 'subscription'); END`)));
  let principal;
  try {
    principal = app.logged.session.principal_id; const token = app.issue();
    const operation = app.sessions.replaceLocalPermissions(app.credentials, app.change(localIdentityPermissions.filter(p => p !== 'status.read')));
    assert.equal(operation.reduced, true); assert.deepEqual(operation.target_service_ids, [remote, app.storage.identity.service_id].sort());
    assert.equal(app.sessions.localPermissions(app.credentials).state, 'pending');
    assert.throws(() => app.issue(), e => e.code === 'local_authorization_denied');
    assert.throws(() => app.sessions.verifyToken(tokenInput(token), app.storage.identity.service_id), e => e.code === 'token_invalid');
    assert.equal(app.sessions.current(app.credentials).session.state, 'active');
  } finally { app.close(); }
  const reopened = openStorage(app.dir); reopened.close();
  inspect(app.dir, db => {
    assert.equal(db.prepare('SELECT state FROM local_permission_revision WHERE principal_id = ? ORDER BY revision DESC LIMIT 1').pluck().get(principal), 'pending');
    assert.equal(db.prepare("SELECT count(*) FROM local_permission_target WHERE state = 'pending'").pluck().get(), 2);
    assert.equal(db.prepare('SELECT count(*) FROM local_permission_outbox').pluck().get(), 2);
    assert.equal(db.prepare("SELECT count(*) FROM access_token WHERE state = 'active'").pluck().get(), 0);
  });
});

test('管理核近期认证与合法目录，不接受角色或远端权限自报', async t => {
  const app = await setup(t);
  try {
    for (const permissions of [['auth.manage', 'device.command'], ['auth.manage', 'auth.manage']])
      assert.throws(() => app.sessions.replaceLocalPermissions(app.credentials, app.change(permissions)), e => e.code === 'local_authorization_request');
    assert.throws(() => app.sessions.replaceLocalPermissions({...app.credentials, csrf: 'A'.repeat(43)}, app.change([...localIdentityPermissions])), e => e.code === 'session_invalid');
    assert.throws(() => app.sessions.replaceLocalPermissions(app.credentials, {...app.change([...localIdentityPermissions]), role: 'administrator'}), e => e.code === 'local_authorization_request');
    // 合成时间偏移仅检查管理近期边界，不表示实际平台持续采样资格。
    app.state.offset = 300000000000n;
    assert.throws(() => app.sessions.replaceLocalPermissions(app.credentials, app.change([...localIdentityPermissions])), e => e.code === 'local_authorization_management_denied');
    assert.equal(app.sessions.localPermissions(app.credentials).revision, '1');
  } finally { app.close(); }
});

test('已有v6管理员显式迁移保留身份，新增授权只来自已保存初始化角色', async t => {
  const dir = directory(t), identity = initializeStorage(dir); await migrateStorage(dir, 6);
  const old = openStorage(dir); const initial = await enroll(old); old.close();
  const migrated = await migrateStorage(dir); assert.equal(migrated.schema_revision, '7');
  const next = openStorage(dir);
  try { assert.equal(next.identity.service_id, identity.service_id); assert.deepEqual(next.enrollment.summary(), initial); }
  finally { next.close(); }
  assert.equal((await migrateStorage(dir)).changed, false);
  inspect(dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM local_permission_revision').pluck().get(), 1);
    const body = JSON.parse(db.prepare('SELECT body FROM local_permission_revision').pluck().get().toString());
    assert.equal(body.principal_id, initial.principal_id); assert.equal(body.initialization_tx_id, initial.transaction_id);
    assert.deepEqual(body.permissions, localIdentityPermissions);
  });
});

test('权限版本、head、token撤销与传播任一写失败均完整回滚', async t => {
  for (const [table, action, condition] of [
    ['local_permission_revision', 'INSERT', "WHEN NEW.revision > '00000000000000000001'"],
    ['local_permission_head', 'UPDATE', ''], ['access_token', 'UPDATE', ''],
    ['local_permission_operation', 'INSERT', ''], ['local_permission_target', 'INSERT', ''], ['local_permission_outbox', 'INSERT', ''],
  ]) {
    const app = await setup(t, dir => inspect(dir, db => db.exec(`CREATE TRIGGER synthetic_write_failure BEFORE ${action} ON ${table} ${condition} BEGIN SELECT RAISE(ABORT, 'synthetic_write_failure'); END`)));
    try {
      app.issue();
      assert.throws(() => app.sessions.replaceLocalPermissions(app.credentials, app.change([...localIdentityPermissions, 'device.read'])));
      assert.throws(() => app.sessions.current(app.credentials), e => e.code === 'session_service_stopped');
    } finally { app.close(); }
    inspect(app.dir, db => {
      assert.equal(db.prepare('SELECT count(*) FROM local_permission_revision').pluck().get(), 1);
      assert.equal(db.prepare('SELECT count(*) FROM local_permission_operation').pluck().get(), 0);
      assert.equal(db.prepare('SELECT count(*) FROM local_permission_outbox').pluck().get(), 0);
      assert.equal(db.prepare("SELECT count(*) FROM access_token WHERE state = 'active'").pluck().get(), 1);
    });
  }
});

test('首次管理员与初始权限写入同事务，权限写失败不留下半个身份', async t => {
  for (const table of ['local_permission_revision', 'local_permission_head']) {
    const dir = directory(t); initializeStorage(dir); await migrateStorage(dir);
    inspect(dir, db => db.exec(`CREATE TRIGGER synthetic_initialization_failure BEFORE INSERT ON ${table}
      BEGIN SELECT RAISE(ABORT, 'synthetic_initialization_failure'); END`));
    const store = openStorage(dir);
    try { await assert.rejects(enroll(store)); assert.deepEqual(store.enrollment.summary(), {initialized: false}); }
    finally { store.close(); }
    inspect(dir, db => {
      for (const name of ['identity_initialization', 'identity_issuer', 'subject', 'local_principal', 'local_authorization', 'identity_receipt', 'local_permission_revision', 'local_permission_head'])
        assert.equal(db.prepare('SELECT count(*) FROM ' + name).pluck().get(), 0);
    });
  }
});
