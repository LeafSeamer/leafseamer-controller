import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';
import {seal, digest} from '../dist/auth-clock-value.mjs';
import {fixture} from './auth-clock-fixture.mjs';

const login = {login: 'synthetic-token-admin', password: 'synthetic-token-password-012345'};
const sessionInput = x => ({credential_id: x.credential_id, secret: x.secret, csrf: x.csrf});
const tokenInput = x => ({token_id: x.token.token_id, secret: x.secret});
const request = audience => ({request_id: crypto.randomUUID(), audience, requested_scopes: ['identity.read']});
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
async function setup(t, beforeOpen = () => {}, syntheticTime = false) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-token-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  initializeStorage(dir); await migrateStorage(dir); beforeOpen(dir);
  const storage = openStorage(dir), capability = storage.enrollment.begin();
  await storage.enrollment.complete({token_id: capability.token_id, secret: capability.secret, ...login, mode: 'standalone'});
  const f = fixture(storage.authenticationClock.scope), realClock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  const state = {offset: 0n, policy: '1', extra: false, expiry: '1700000100000000000', changeOnCall: 0, calls: 0};
  const clock = syntheticTime ? {current() { const v = realClock.current(); return {...v, lower_ns: String(BigInt(v.lower_ns) + state.offset), upper_ns: String(BigInt(v.upper_ns) + state.offset)}; }} : realClock;
  const records = new Map();
  const authority = {resolve(binding) {
    state.calls++; if (state.changeOnCall === state.calls) state.policy = '2';
    const permissions = state.extra ? ['device.write'] : binding.requested_scopes.filter(v => ['identity.read', 'device.observe'].includes(v)).sort();
    const key = JSON.stringify([binding.credential_id, binding.audience, permissions]);
    if (!records.has(key)) records.set(key, crypto.randomUUID());
    const {requested_scopes, ...parent} = binding;
    return seal({id: records.get(key), revision: state.policy, ...parent, subject_revision: '1', policy_revision: state.policy,
      permissions, scope_digest: digest({permissions}), not_before_ns: '1699999999000000000', expires_ns: state.expiry});
  }};
  const sessions = storage.sessions(clock, authority), logged = await sessions.login(login);
  return {dir, storage, f, realClock, clock, state, authority, sessions, logged, input: sessionInput(logged),
    close() { realClock.stop(); storage.close(); }};
}

test('定向token实际签发与验证，重复请求不重交秘密且不能跨audience使用', async t => {
  const app = await setup(t), audience = crypto.randomUUID(), req = request(audience); let issued;
  try {
    issued = app.sessions.issueToken(app.input, req);
    assert.equal(issued.replay, false); assert.equal(issued.secret.length, 43);
    assert.equal(BigInt(issued.token.expires_ns) - BigInt(issued.token.not_before_ns), 60000000000n);
    const verified = app.sessions.verifyToken(tokenInput(issued), audience);
    assert.equal(verified.active, true); assert.equal(verified.session_id, app.logged.session.session_id);
    assert.deepEqual(verified.permissions, ['identity.read']);
    assert.throws(() => app.sessions.verifyToken(tokenInput(issued), crypto.randomUUID()), e => e.code === 'token_invalid');
    const duplicate = app.sessions.issueToken(app.input, req);
    assert.equal(duplicate.replay, true); assert.equal(duplicate.secret, null); assert.deepEqual(duplicate.token, issued.token);
    assert.throws(() => app.sessions.issueToken(app.input, {...req, audience: crypto.randomUUID()}), e => e.code === 'token_request_conflict');
  } finally { app.close(); }
  inspect(app.dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM access_token').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM session_audience').pluck().get(), 2);
    assert.throws(() => db.exec("UPDATE access_token SET audience = 'changed'"));
    assert.equal(db.prepare('PRAGMA foreign_key_check').raw().all().length, 0);
  });
  assert.equal(fs.readFileSync(path.join(app.dir, 'controller.sqlite')).includes(Buffer.from(issued.secret)), false);
});

test('八个活跃token上限同writer执行，刷新后代仍归原session且退出全撤', async t => {
  const app = await setup(t), audience = crypto.randomUUID();
  try {
    const tokens = Array.from({length: 8}, () => app.sessions.issueToken(app.input, request(audience)));
    assert.throws(() => app.sessions.issueToken(app.input, request(audience)), e => e.code === 'token_capacity');
    const fresh = app.sessions.refresh(app.input), current = {...sessionInput(fresh), csrf: app.logged.csrf};
    assert.equal(app.sessions.verifyToken(tokenInput(tokens[0]), audience).active, true);
    const next = app.sessions.issueToken(current, request(audience));
    assert.equal(next.token.session_id, app.logged.session.session_id);
    const revoked = app.sessions.logout(current);
    assert(revoked.propagation.target_service_ids.includes(audience));
    for (const token of [...tokens, next]) assert.throws(() => app.sessions.verifyToken(tokenInput(token), audience), e => e.code === 'token_invalid');
  } finally { app.close(); }
  assert.equal(inspect(app.dir, db => db.prepare("SELECT count(*) FROM access_token WHERE state = 'revoked'").pluck().get()), 9);
});

test('注销先提交则后续签发拒绝，不会增加固定目标集合', async t => {
  const app = await setup(t), audience = crypto.randomUUID();
  try {
    app.sessions.logout(app.input);
    assert.throws(() => app.sessions.issueToken(app.input, request(audience)), e => e.code === 'session_invalid');
  } finally { app.close(); }
  inspect(app.dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM access_token').pluck().get(), 0);
    assert.equal(db.prepare('SELECT count(*) FROM session_audience').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM session_revocation_target').pluck().get(), 1);
  });
});

test('合成长期区间到期等号永久禁用token，较早时间不能使其复活', async t => {
  const app = await setup(t, () => {}, true), audience = crypto.randomUUID();
  try {
    const token = app.sessions.issueToken(app.input, request(audience));
    app.state.offset = BigInt(token.token.expires_ns) - BigInt(app.clock.current().upper_ns);
    assert.throws(() => app.sessions.verifyToken(tokenInput(token), audience), e => e.code === 'token_expired');
    app.state.offset = 0n;
    assert.throws(() => app.sessions.verifyToken(tokenInput(token), audience), e => e.code === 'token_invalid');
  } finally { app.close(); }
  assert.equal(inspect(app.dir, db => db.prepare('SELECT state FROM access_token').pluck().get()), 'expired');
});

test('权限扩张拒绝，授权版本变化使旧token终止，发放期间变化整笔回滚', async t => {
  const app = await setup(t), audience = crypto.randomUUID();
  try {
    app.state.extra = true;
    assert.throws(() => app.sessions.issueToken(app.input, request(audience)), e => e.code === 'token_authorization_invalid');
    app.state.extra = false;
    const token = app.sessions.issueToken(app.input, request(audience));
    app.state.policy = '2';
    assert.throws(() => app.sessions.verifyToken(tokenInput(token), audience), e => e.code === 'token_invalid');
    app.state.policy = '1';
    assert.throws(() => app.sessions.verifyToken(tokenInput(token), audience), e => e.code === 'token_invalid');
    app.state.changeOnCall = app.state.calls + 2;
    assert.throws(() => app.sessions.issueToken(app.input, request(audience)), e => e.code === 'token_authorization_changed');
  } finally { app.close(); }
  assert.equal(inspect(app.dir, db => db.prepare('SELECT count(*) FROM access_token').pluck().get()), 1);
});

test('授权更早截止优先，时钟失信不接受或新签令牌', async t => {
  const app = await setup(t), audience = crypto.randomUUID();
  try {
    app.state.expiry = String(BigInt(app.clock.current().lower_ns) + 10000000000n);
    const token = app.sessions.issueToken(app.input, request(audience));
    assert.equal(token.token.expires_ns, app.state.expiry);
    app.f.source.break();
    assert.throws(() => app.sessions.verifyToken(tokenInput(token), audience));
    assert.throws(() => app.sessions.issueToken(app.input, request(audience)));
  } finally { app.close(); }
});

test('token与audience任一写失败均无部分签发，停止失败实例继续使用', async t => {
  for (const table of ['access_token', 'session_audience']) {
    const audience = crypto.randomUUID();
    const app = await setup(t, dir => inspect(dir, db => db.exec(`CREATE TRIGGER synthetic_token_failure BEFORE INSERT ON ${table}
      ${table === 'session_audience' ? `WHEN NEW.audience = '${audience}'` : ''}
      BEGIN SELECT RAISE(ABORT, 'synthetic_token_failure'); END`)));
    try {
      assert.throws(() => app.sessions.issueToken(app.input, request(audience)));
      assert.throws(() => app.sessions.current(app.input), e => e.code === 'session_service_stopped');
    } finally { app.close(); }
    inspect(app.dir, db => {
      assert.equal(db.prepare('SELECT count(*) FROM access_token').pluck().get(), 0);
      assert.equal(db.prepare('SELECT count(*) FROM session_audience').pluck().get(), 1);
    });
  }
});
