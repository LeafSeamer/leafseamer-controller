import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';
import {fixture} from './auth-clock-fixture.mjs';

const login = {login: 'synthetic-session-admin', password: 'synthetic-session-password-012345'};
const input = result => ({credential_id: result.credential_id, secret: result.secret, csrf: result.csrf});
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
async function setup(t, beforeOpen = () => {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-session-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  initializeStorage(dir); await migrateStorage(dir); beforeOpen(dir);
  const storage = openStorage(dir), {token_id, secret} = storage.enrollment.begin();
  await storage.enrollment.complete({token_id, secret, ...login, mode: 'standalone'});
  const f = fixture(storage.authenticationClock.scope), clock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  const sessions = storage.sessions(clock);
  return {dir, storage, f, clock, sessions, close() { clock.stop(); storage.close(); }};
}

test('实际密码库、认证原件和人员会话闭环，退出持久保存本地拒绝与待确认传播', async t => {
  const app = await setup(t); let logged;
  try {
    logged = await app.sessions.login(login);
    assert.equal(logged.session.principal_kind, 'human');
    assert.equal(BigInt(logged.session.expires_ns) - BigInt(logged.session.not_before_ns), 28800000000000n);
    assert.equal(BigInt(logged.session.idle_before_ns) - BigInt(logged.session.not_before_ns), 1800000000000n);
    assert.equal(BigInt(logged.session.recent_before_ns) - BigInt(logged.session.not_before_ns), 300000000000n);
    assert.deepEqual(app.sessions.current(input(logged)).session, logged.session);
    assert.equal(app.storage.sessions(app.clock), app.sessions);
    const operation = app.sessions.logout(input(logged));
    assert.equal(operation.local_session_state, 'revoked'); assert.equal(operation.propagation.propagation, 'pending');
    assert.deepEqual(operation.propagation.target_service_ids, [app.storage.identity.service_id]);
    assert.throws(() => app.sessions.current(input(logged)), e => e.code === 'session_invalid');
    assert.throws(() => app.sessions.refresh(input(logged)), e => e.code === 'session_invalid');
  } finally { app.close(); }
  inspect(app.dir, db => {
    assert.deepEqual(db.prepare('SELECT state, revision FROM auth_session').raw().get(), ['revoked', 2]);
    assert.equal(db.prepare('SELECT revision_floor FROM session_revocation_floor').pluck().get(), 2);
    assert.equal(db.prepare('SELECT count(*) FROM session_revocation_outbox').pluck().get(), 1);
    assert.throws(() => db.exec("UPDATE auth_session SET state = 'active'"));
    assert.throws(() => db.exec('DELETE FROM session_revocation_floor'));
    assert.throws(() => db.prepare('INSERT INTO session_audience VALUES (?, ?, ?)').run(logged.session.session_id, crypto.randomUUID(), crypto.randomUUID()));
    assert.throws(() => db.exec("UPDATE session_revocation_target SET target_service_id = 'changed'"));
    assert.equal(db.prepare('PRAGMA foreign_key_check').raw().all().length, 0);
  });
  const bytes = fs.readFileSync(path.join(app.dir, 'controller.sqlite'));
  for (const value of [login.password, logged.secret, logged.csrf]) assert.equal(bytes.includes(Buffer.from(value)), false);
});

test('刷新单次消费且保留会话绝对截止，旧凭据复用撤销全部后代', async t => {
  const app = await setup(t);
  try {
    const first = await app.sessions.login(login); app.f.source.advance(500000000n); app.clock.refresh();
    const refreshed = app.sessions.refresh(input(first));
    assert.equal(refreshed.session.session_id, first.session.session_id);
    assert.equal(refreshed.session.expires_ns, first.session.expires_ns);
    assert.notEqual(refreshed.credential_id, first.credential_id);
    assert.equal(BigInt(refreshed.session.idle_before_ns) - BigInt(first.session.idle_before_ns), 500000000n);
    const next = {...input(refreshed), csrf: first.csrf};
    assert.equal(app.sessions.current(next).session.state, 'active');
    assert.throws(() => app.sessions.refresh(input(first)), e => e.code === 'session_invalid');
    assert.throws(() => app.sessions.current(next), e => e.code === 'session_invalid');
  } finally { app.close(); }
  inspect(app.dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM session_refresh_credential').pluck().get(), 2);
    assert.equal(db.prepare('SELECT cause FROM session_revocation').pluck().get(), 'refresh_reuse');
    assert.equal(db.prepare('SELECT count(*) FROM session_refresh_reuse').pluck().get(), 1);
  });
});

test('空闲期限等号拒绝并保存终态，合成较早认证区间不能复活会话', async t => {
  const app = await setup(t); app.close();
  const storage = openStorage(app.dir), f = fixture(storage.authenticationClock.scope), real = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  // 生命周期长时跨度使用合成认证接口；实际2秒采样调度由独立时钟用例验证。
  let offset = 0n;
  const clock = {current() { const v = real.current(); return {...v, lower_ns: String(BigInt(v.lower_ns) + offset), upper_ns: String(BigInt(v.upper_ns) + offset)}; }};
  const sessions = storage.sessions(clock);
  try {
    const logged = await sessions.login(login), initial = clock.current();
    offset = BigInt(logged.session.idle_before_ns) - BigInt(initial.upper_ns);
    assert.throws(() => sessions.current(input(logged)), e => e.code === 'session_expired');
    offset = 0n;
    assert.throws(() => sessions.current(input(logged)), e => e.code === 'session_invalid');
  } finally { real.stop(); storage.close(); }
  assert.equal(inspect(app.dir, db => db.prepare('SELECT state FROM auth_session').pluck().get()), 'expired');
});

test('KDF期间时钟失信不提交会话，旧会话每次使用重新检查时钟', async t => {
  const app = await setup(t);
  try {
    const pending = app.sessions.login(login); app.f.source.break();
    await assert.rejects(pending);
  } finally { app.close(); }
  assert.equal(inspect(app.dir, db => db.prepare('SELECT count(*) FROM auth_session').pluck().get()), 0);
  const next = await setup(t);
  try {
    const logged = await next.sessions.login(login); next.f.source.break();
    assert.throws(() => next.sessions.current(input(logged)));
  } finally { next.close(); }
});

test('错CSRF和错秘密不消费凭据，登录限速不阻止已有会话退出', async t => {
  const app = await setup(t);
  try {
    const logged = await app.sessions.login(login);
    assert.throws(() => app.sessions.refresh({...input(logged), csrf: crypto.randomBytes(32).toString('base64url')}), e => e.code === 'session_invalid');
    assert.throws(() => app.sessions.logout({...input(logged), secret: crypto.randomBytes(32).toString('base64url')}), e => e.code === 'session_invalid');
    assert.throws(() => app.sessions.current({...input(logged), credential_id: {bad: 'input'}}), e => e.code === 'session_invalid');
    for (let i = 0; i < 5; i++) await assert.rejects(app.sessions.login({...login, password: login.password + 'wrong'}), e => e.code === 'login_invalid');
    await assert.rejects(app.sessions.login(login), e => e.code === 'login_throttled');
    await assert.rejects(app.sessions.login({...login, login: 'synthetic-missing'}), e => e.code === 'login_invalid');
    assert.equal(app.sessions.logout(input(logged)).local_session_state, 'revoked');
  } finally { app.close(); }
});

test('退出捕获audience与执行订阅目标的并集，离线目标保留pending', async t => {
  const remoteA = crypto.randomUUID(), remoteB = crypto.randomUUID();
  const app = await setup(t, dir => inspect(dir, db => db.exec(`CREATE TRIGGER synthetic_bindings AFTER INSERT ON auth_session BEGIN
    INSERT INTO session_audience VALUES (NEW.session_id, '${remoteA}', NEW.created_tx_id);
    INSERT INTO session_target_binding VALUES (NEW.session_id, '${remoteA}', 'synthetic-execution', 'execution');
    INSERT INTO session_target_binding VALUES (NEW.session_id, '${remoteB}', 'synthetic-subscription', 'subscription'); END`)));
  try {
    const logged = await app.sessions.login(login), operation = app.sessions.logout(input(logged));
    assert.deepEqual(operation.propagation.target_service_ids, [remoteA, remoteB, app.storage.identity.service_id].sort());
  } finally { app.close(); }
  assert.equal(inspect(app.dir, db => db.prepare('SELECT count(*) FROM session_revocation_target').pluck().get()), 3);
  assert.equal(inspect(app.dir, db => db.prepare('SELECT count(*) FROM session_revocation_outbox').pluck().get()), 3);
});

test('登录每个写点失败均回滚，退出outbox故障不能返回已撤销结果', async t => {
  for (const table of ['auth_session', 'session_refresh_credential', 'session_audience', 'session_revocation_outbox']) {
    const app = await setup(t, dir => inspect(dir, db => db.exec(`CREATE TRIGGER synthetic_failure BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT, 'synthetic_failure'); END`)));
    try {
      if (table === 'session_revocation_outbox') {
        const logged = await app.sessions.login(login); assert.throws(() => app.sessions.logout(input(logged)));
        assert.throws(() => app.sessions.current(input(logged)), e => e.code === 'session_service_stopped');
      } else await assert.rejects(app.sessions.login(login));
    } finally { app.close(); }
    inspect(app.dir, db => {
      assert.equal(db.prepare('SELECT count(*) FROM auth_session').pluck().get(), table === 'session_revocation_outbox' ? 1 : 0);
      assert.equal(db.prepare('SELECT count(*) FROM session_revocation').pluck().get(), 0);
      assert.equal(db.prepare('SELECT count(*) FROM session_revocation_floor').pluck().get(), 0);
      if (table === 'session_revocation_outbox') assert.equal(db.prepare('SELECT state FROM auth_session').pluck().get(), 'active');
    });
  }
});
