import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {contractSelection as selection} from '@leafseamer/sdk';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';
import {fixture} from './auth-clock-fixture.mjs';

const login = {login: 'synthetic-context-admin', password: 'synthetic-context-password-012345'};
const input = x => ({credential_id: x.credential_id, secret: x.secret, csrf: x.csrf});
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
async function setup(t, revision = 8, beforeOpen = () => {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-context-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  initializeStorage(dir); await migrateStorage(dir, revision); beforeOpen(dir);
  const storage = openStorage(dir), capability = storage.enrollment.begin();
  await storage.enrollment.complete({token_id: capability.token_id, secret: capability.secret, ...login, mode: 'standalone'});
  const f = fixture(storage.authenticationClock.scope), real = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  const state = {offset: 0n};
  // 保留真实已入库采样引用，仅用合成时间跨度验证生命周期边界。
  const clock = {current() { const v = real.current(); return {...v, lower_ns: String(BigInt(v.lower_ns) + state.offset), upper_ns: String(BigInt(v.upper_ns) + state.offset)}; }};
  const sessions = storage.sessions(clock), logged = await sessions.login(login);
  const token = (scopes = ['request.create', 'session.read']) => {
    const issued = sessions.issueToken(input(logged), {request_id: crypto.randomUUID(), audience: storage.identity.service_id, requested_scopes: scopes});
    return {token_id: issued.token.token_id, secret: issued.secret};
  };
  const request = {audience: storage.identity.service_id, operations: ['getSession'], selection, ttl_ms: 10000, max_unique_requests: 8};
  return {dir, storage, sessions, logged, state, clock, token, request, close() { real.stop(); storage.close(); }};
}

test('上下文绑定真实token和授权操作，签发缩短期限和容量且不交付秘密', async t => {
  const a = await setup(t), token = a.token();
  try {
    const context = a.sessions.createRequestContext(token, {...a.request, ttl_ms: 86400000, max_unique_requests: 4096});
    assert.equal(context.max_unique_requests, 256); assert(context.ttl_ms > 59000 && context.ttl_ms <= 60000);
    assert.equal(Date.parse(context.expires_at) - Date.parse(context.issued_at), context.ttl_ms);
    assert.deepEqual(a.sessions.getRequestContext(token, context.context_id, 'getSession'), context);
    assert.throws(() => a.sessions.getRequestContext(a.token(), context.context_id), e => e.code === 'request_context_denied');
    assert.throws(() => a.sessions.getRequestContext(token, context.context_id, 'createRequestContext'), e => e.code === 'request_context_permission');
    for (const change of [{audience: crypto.randomUUID()}, {operations: ['getSession', 'createCommand']}, {operations: ['login']}, {operations: ['getSession', 'getSession']}, {selection: {...selection, contract_id: 'wrong'}}]) {
      assert.throws(() => a.sessions.createRequestContext(token, {...a.request, ...change}), e => /^request_context_/.test(e.code));
    }
    assert.throws(() => a.sessions.createRequestContext(a.token(['session.read']), a.request), e => e.code === 'request_context_permission');
    a.close();
    inspect(a.dir, db => {
      assert.equal(db.prepare('SELECT count(*) FROM request_context').pluck().get(), 1);
      assert.equal(db.prepare('SELECT used_count FROM request_context').pluck().get(), 0);
      assert(!db.prepare('SELECT body FROM request_context').pluck().get().includes(Buffer.from(token.secret)));
      assert.throws(() => db.exec("UPDATE request_context SET body = x'00'"));
      assert.throws(() => db.exec('DELETE FROM request_context'));
      assert.equal(db.prepare('PRAGMA foreign_key_check').raw().all().length, 0);
    });
  } finally { a.close(); }
});

test('上下文期限等号关闭并持久保留，较早合成时间不能复活', async t => {
  const a = await setup(t), token = a.token();
  try {
    const context = a.sessions.createRequestContext(token, a.request);
    a.state.offset = BigInt(Date.parse(context.expires_at)) * 1000000n - BigInt(a.clock.current().upper_ns);
    assert.throws(() => a.sessions.getRequestContext(token, context.context_id), e => e.code === 'request_context_expired');
    a.state.offset = 0n;
    assert.throws(() => a.sessions.getRequestContext(token, context.context_id), e => e.code === 'request_context_closed');
    a.close();
    inspect(a.dir, db => {
      assert.equal(db.prepare('SELECT state FROM request_context').pluck().get(), 'expired');
      assert.throws(() => db.exec("UPDATE request_context SET state='active', closed_reason=NULL"));
    });
  } finally { a.close(); }
});

test('注销同事务关闭上下文；普通重启保留记录和epoch但关闭新受理资格', async t => {
  const a = await setup(t), token = a.token(); let context;
  try {
    context = a.sessions.createRequestContext(token, a.request);
    a.sessions.logout(input(a.logged));
    assert.throws(() => a.sessions.getRequestContext(token, context.context_id));
    a.close();
    inspect(a.dir, db => assert.equal(db.prepare('SELECT state FROM request_context').pluck().get(), 'closed'));
  } finally { a.close(); }
  const b = await setup(t), next = b.sessions.createRequestContext(b.token(), b.request); b.close();
  const reopened = openStorage(b.dir);
  try {
    reopened.close();
    inspect(b.dir, db => {
      assert.deepEqual(db.prepare('SELECT context_id, context_epoch, state, closed_reason FROM request_context').raw().get(), [next.context_id, next.context_epoch, 'closed', 'restarted']);
      assert.equal(db.prepare('SELECT request_epoch FROM service_state').pluck().get(), next.context_epoch);
    });
  } finally { reopened.close(); }
});

test('同主体签发预算不删除旧记录；写入故障不会留下半个上下文', async t => {
  const a = await setup(t), token = a.token();
  try {
    for (let i = 0; i < 64; i++) a.sessions.createRequestContext(token, a.request);
    assert.throws(() => a.sessions.createRequestContext(token, a.request), e => e.code === 'request_context_capacity');
    a.close();
    inspect(a.dir, db => assert.equal(db.prepare('SELECT count(*) FROM request_context').pluck().get(), 64));
  } finally { a.close(); }
  const b = await setup(t, 8, dir => inspect(dir, db => db.exec("CREATE TRIGGER context_fault AFTER INSERT ON request_context BEGIN SELECT RAISE(ABORT, 'synthetic_context_failure'); END"))), proof = b.token();
  try {
    assert.throws(() => b.sessions.createRequestContext(proof, b.request));
    b.close();
    inspect(b.dir, db => assert.equal(db.prepare('SELECT count(*) FROM request_context').pluck().get(), 0));
  } finally { b.close(); }
});

test('v7显式升级v8保留身份、备份和原权限；未升级不能签发上下文', async t => {
  const a = await setup(t, 7), identity = a.storage.identity;
  try { assert.throws(() => a.sessions.createRequestContext(a.token(), a.request), e => e.code === 'request_context_migration_required'); }
  finally { a.close(); }
  const migrated = await migrateStorage(a.dir); assert.equal(migrated.schema_revision, '8');
  const reopened = openStorage(a.dir);
  try { assert.equal(reopened.identity.service_id, identity.service_id); }
  finally { reopened.close(); }
  inspect(a.dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM local_permission_revision').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM request_context').pluck().get(), 0);
    assert(db.prepare("SELECT backup_ref FROM schema_migration WHERE to_revision='8'").pluck().get());
  });
});
