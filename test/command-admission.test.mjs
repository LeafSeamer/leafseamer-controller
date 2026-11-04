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
import {digest} from '../dist/auth-clock-value.mjs';
import {commandContent} from '../dist/command-admission-store.mjs';
import {localIdentityPermissions} from '../dist/local-permission-store.mjs';
import {fixture} from './auth-clock-fixture.mjs';

const login = {login: 'synthetic-command-admin', password: 'synthetic-command-password-012345'};
const input = x => ({credential_id: x.credential_id, secret: x.secret, csrf: x.csrf});
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
async function setup(t, revision = 9, beforeOpen = () => {}) {
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
  sessions.replaceLocalPermissions(input(logged), {request_id: crypto.randomUUID(), principal_id: logged.session.principal_id, expected_revision: '1', permissions: [...localIdentityPermissions, 'command.read', 'command.cancel']});
  const token = (scopes = ['request.create', 'command.read', 'command.cancel']) => {
    const issued = sessions.issueToken(input(logged), {request_id: crypto.randomUUID(), audience: storage.identity.service_id, requested_scopes: scopes});
    return {token_id: issued.token.token_id, secret: issued.secret};
  };
  const request = {audience: storage.identity.service_id, operations: ['lookupCommandAdmission', 'rejectCommandAdmission'], selection, ttl_ms: 10000, max_unique_requests: 8};
  return {dir, storage, sessions, logged, state, clock, token, request, close() { real.stop(); storage.close(); }};
}

const content = () => ({device_id: 'synthetic-device', action_id: 'synthetic.action', capability_version: '1.0.0',
  parameters: {value: 1, context_id: 'nested-business-field'}, expected_control: {epoch: 'synthetic-control', version: '1'},
  origin: 'manual', automation_binding: null, required_completion: 'sent', preconditions: [], dispatch: {mode: 'immediate', max_queue_ms: 1000}, evidence_timeout_ms: 1000});
function identity(a, context, body = content()) {
  return {key: {target_scope: {authority_service_id: a.storage.identity.service_id, database_instance_id: a.storage.identity.database_instance_id},
    issuer_id: context.issuer_id, issuer_epoch: context.issuer_epoch, principal_id: context.principal_id, request_epoch: context.context_epoch,
    operation_id: 'createCommand', idempotency_key: crypto.randomUUID()}, request_digest: digest(body)};
}
test('真实文件库拒收同键永久查原，换context和关联标识不增加命令或改变摘要', async t => {
  const a = await setup(t), token = a.token();
  try {
    const ctx = a.sessions.createRequestContext(token, a.request), body = content(), id = identity(a, ctx, body);
    const request = {rejection_operation_id: crypto.randomUUID(), identity: id, content: body};
    assert.deepEqual(await a.sessions.lookupCommandAdmission(token, id), {state: 'not_found', adjudication: null});
    const result = await a.sessions.rejectCommandAdmission(token, request);
    assert.equal(result.decision, 'rejected'); assert.equal(result.command_ref, null);
    const {adjudication_digest, ...signed} = result; assert.equal(adjudication_digest, digest(signed));
    assert.deepEqual(await a.sessions.rejectCommandAdmission(token, request), result);
    assert.deepEqual(await a.sessions.rejectCommandAdmission(token, {...request, rejection_operation_id: crypto.randomUUID()}), result);
    const other = a.sessions.createRequestContext(token, a.request);
    for (const context_id of [ctx.context_id, other.context_id]) {
      const submission = {...body, context_id, idempotency_key: id.key.idempotency_key, correlation_id: crypto.randomUUID()};
      assert.equal(digest(commandContent(submission)), id.request_digest);
      assert.deepEqual(await a.sessions.submitCommand(token, submission), result);
    }
    const changed = {...body, parameters: {...body.parameters, context_id: 'different-business-field'}};
    await assert.rejects(a.sessions.rejectCommandAdmission(token, {...request, content: changed, identity: {...id, request_digest: digest(changed)}}), e => e.code === 'command_conflict');
    await assert.rejects(a.sessions.submitCommand(token, {...body, context_id: ctx.context_id, idempotency_key: crypto.randomUUID()}), e => e.code === 'command_admission_unavailable');
    a.close();
    inspect(a.dir, db => {
      assert.equal(db.prepare('SELECT count(*) FROM ca_request_key').pluck().get(), 1);
      assert.equal(db.prepare('SELECT count(*) FROM ca_rejection').pluck().get(), 2);
      assert.equal(db.prepare('SELECT count(*) FROM ca_command_initial').pluck().get(), 0);
      assert.equal(db.prepare('SELECT count(*) FROM ca_notification').pluck().get(), 2);
      assert.equal(db.prepare('SELECT sum(used_count) FROM request_context').pluck().get(), 0);
      assert.equal(db.prepare('PRAGMA foreign_key_check').raw().all().length, 0);
      assert.throws(() => db.exec('DELETE FROM ca_adjudication'));
      assert.throws(() => db.exec("UPDATE ca_adjudication SET decision='accepted'"));
      db.pragma('recursive_triggers=ON');
      assert.throws(() => db.exec('INSERT OR REPLACE INTO ca_request_key SELECT * FROM ca_request_key'));
    });
  } finally { a.close(); }
});

test('旧context到期或重启不阻止当前授权人员保护自身namespace，其他主体和错scope拒绝', async t => {
  const a = await setup(t), token = a.token(), ctx = a.sessions.createRequestContext(token, a.request), body = content(), id = identity(a, ctx, body);
  const request = {rejection_operation_id: crypto.randomUUID(), identity: id, content: body};
  try {
    a.state.offset = 15000000000n;
    assert.throws(() => a.sessions.getRequestContext(token, ctx.context_id), e => e.code === 'request_context_expired');
    assert.equal((await a.sessions.rejectCommandAdmission(token, request)).decision, 'rejected');
    const readOnly = a.token(['command.read']);
    await assert.rejects(a.sessions.rejectCommandAdmission(readOnly, request), e => e.code === 'command_permission');
    for (const change of [{principal_id: crypto.randomUUID()}, {issuer_epoch: crypto.randomUUID()}, {target_scope: {...id.key.target_scope, database_instance_id: crypto.randomUUID()}}]) {
      await assert.rejects(a.sessions.lookupCommandAdmission(token, {...id, key: {...id.key, ...change}}), e => e.code === 'command_permission');
    }
  } finally { a.close(); }
  const storage = openStorage(a.dir), f = fixture(storage.authenticationClock.scope), clock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  try {
    const sessions = storage.sessions(clock), logged = await sessions.login(login);
    const issued = sessions.issueToken(input(logged), {request_id: crypto.randomUUID(), audience: storage.identity.service_id, requested_scopes: ['command.read', 'command.cancel']});
    const current = {token_id: issued.token.token_id, secret: issued.secret};
    assert.equal((await sessions.lookupCommandAdmission(current, id)).state, 'found');
    assert.equal((await sessions.rejectCommandAdmission(current, {...request, rejection_operation_id: crypto.randomUUID()})).decision, 'rejected');
    sessions.logout(input(logged));
    await assert.rejects(sessions.lookupCommandAdmission(current, id), e => e.code === 'token_invalid');
  } finally { clock.stop(); storage.close(); }
});

test('拒收每个写点失败均全量回滚，未提交裁决不返回永久拒收证明', async t => {
  for (const table of ['ca_namespace', 'ca_request_key', 'ca_adjudication', 'ca_commit', 'ca_audit', 'ca_notification', 'ca_rejection']) {
    const a = await setup(t, 9, dir => inspect(dir, db => db.exec(`CREATE TRIGGER fault AFTER INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_fault'); END`)));
    try {
      const token = a.token(), ctx = a.sessions.createRequestContext(token, a.request), body = content();
      await assert.rejects(a.sessions.rejectCommandAdmission(token, {rejection_operation_id: crypto.randomUUID(), identity: identity(a, ctx, body), content: body}));
      a.close();
      inspect(a.dir, db => {
        for (const name of ['ca_namespace', 'ca_request_key', 'ca_adjudication', 'ca_commit', 'ca_audit', 'ca_notification', 'ca_rejection']) assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(), 0, table+' -> '+name);
      });
    } finally { a.close(); }
  }
});
