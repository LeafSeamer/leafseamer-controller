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
import {localIdentityPermissions} from '../dist/local-permission-store.mjs';
import {digest} from '../dist/auth-clock-value.mjs';
import {fixture} from './auth-clock-fixture.mjs';

const login = {login: 'synthetic-context-admin', password: 'synthetic-context-password-012345'};
const input = x => ({credential_id: x.credential_id, secret: x.secret, csrf: x.csrf});
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
async function setup(t, revision = 10, beforeOpen = () => {}) {
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
  sessions.replaceLocalPermissions(input(logged), {request_id: crypto.randomUUID(), principal_id: logged.session.principal_id, expected_revision: '1', permissions: [...localIdentityPermissions, 'device.read', 'control.read']});
  const token = (scopes = ['device.read', 'control.read']) => {
    const issued = sessions.issueToken(input(logged), {request_id: crypto.randomUUID(), audience: storage.identity.service_id, requested_scopes: scopes});
    return {token_id: issued.token.token_id, secret: issued.secret};
  };
  const request = {audience: storage.identity.service_id, operations: ['getSession'], selection, ttl_ms: 10000, max_unique_requests: 8};
  return {dir, storage, sessions, logged, state, clock, token, request, close() { real.stop(); storage.close(); }};
}

const registration = () => ({request_id: crypto.randomUUID(), device_kind: 'synthetic-device', display_name: '待配置的测试设备'});
test('登记与初始控制原件同事务，重复查回执，重启不改变设备身份或控制epoch', async t => {
  const a = await setup(t), request = registration(), receipt = a.storage.registerDevice(request), token = a.token(); let control;
  try {
    assert.deepEqual(a.storage.registerDevice({...request}), receipt);
    assert.throws(() => a.storage.registerDevice({...request, display_name: '更换内容'}), e => e.code === 'device_registration_conflict');
    const page = a.sessions.listDevices(token); assert.equal(page.catalog_revision, '1'); assert.equal(page.next_cursor, null);
    assert.equal(page.items[0].device_id, receipt.device_id); assert.equal(page.items[0].connection_state, 'disconnected');
    assert.deepEqual(page.items[0].actions, []); assert.equal(page.items[0].state_schema.document, false);
    assert.equal(page.items[0].state_schema.digest, digest(false));
    control = a.sessions.getControl(token, receipt.device_id);
    assert.equal(control.mode, 'automatic'); assert.equal(control.holder, null); assert.equal(control.gate_state, 'protected');
    assert.equal(control.effective_version, '0'); assert.equal(control.reserved_version, '0');
    const {record_digest, ...body} = control; assert.equal(record_digest, digest(body));
    assert.equal(record_digest, receipt.control_ref.digest);
    a.close();
    inspect(a.dir, db => {
      assert.equal(db.prepare('SELECT count(*) FROM device_record').pluck().get(), 1);
      assert.equal(db.prepare('SELECT count(*) FROM device_registration_commit').pluck().get(), 1);
      assert.equal(db.prepare('PRAGMA foreign_key_check').raw().all().length, 0);
      assert.throws(() => db.exec('DELETE FROM device_control_history'));
      assert.throws(() => db.exec("UPDATE device_control_history SET control_epoch='changed'"));
    });
  } finally { a.close(); }
  const storage = openStorage(a.dir), f = fixture(storage.authenticationClock.scope), clock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  try {
    assert.deepEqual(storage.registerDevice(request), receipt);
    const sessions = storage.sessions(clock), logged = await sessions.login({login: 'synthetic-context-admin', password: 'synthetic-context-password-012345'});
    const issued = sessions.issueToken(input(logged), {request_id: crypto.randomUUID(), audience: storage.identity.service_id, requested_scopes: ['control.read']});
    assert.deepEqual(sessions.getControl({token_id: issued.token.token_id, secret: issued.secret}, receipt.device_id), control);
  } finally { clock.stop(); storage.close(); }
});

test('目录分页不混修订，伪造游标拒绝；读取权限不能从有效token名称推断', async t => {
  const a = await setup(t), token = a.token();
  try {
    const ids = Array.from({length: 66}, () => a.storage.registerDevice(registration()).device_id);
    const first = a.sessions.listDevices(token); assert.equal(first.items.length, 64); assert(first.next_cursor);
    const second = a.sessions.listDevices(token, first.next_cursor); assert.equal(second.items.length, 2); assert.equal(second.next_cursor, null);
    assert.deepEqual([...first.items, ...second.items].map(x => x.device_id), ids);
    assert.throws(() => a.sessions.listDevices(token, first.next_cursor.slice(0,-1) + (first.next_cursor.endsWith('0') ? '1' : '0')), e => e.code === 'device_cursor_invalid');
    a.storage.registerDevice(registration());
    assert.throws(() => a.sessions.listDevices(token, first.next_cursor), e => e.code === 'device_cursor_stale');
    assert.throws(() => a.sessions.listDevices(a.token(['control.read'])), e => e.code === 'device_read_denied');
    assert.throws(() => a.sessions.getControl(a.token(['device.read']), ids[0]), e => e.code === 'device_read_denied');
    assert.throws(() => a.sessions.getControl(token, crypto.randomUUID()), e => e.code === 'device_not_found');
    a.sessions.logout(input(a.logged));
    assert.throws(() => a.sessions.listDevices(token), e => e.code === 'token_invalid');
  } finally { a.close(); }
});

test('设备登记逐写故障全回滚，目录修订不提前增长，数据库不能缺半边提交', async t => {
  for (const table of ['device_registration', 'device_record', 'device_control_history', 'device_registration_commit']) {
    const a = await setup(t, 10, dir => inspect(dir, db => db.exec(`CREATE TRIGGER fault AFTER INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_fault'); END`)));
    try {
      assert.throws(() => a.storage.registerDevice(registration())); a.close();
      inspect(a.dir, db => {
        assert.equal(db.prepare('SELECT revision FROM device_catalog').pluck().get(), 0);
        for (const name of ['device_registration', 'device_record', 'device_control_history', 'device_registration_commit']) assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(), 0);
        db.pragma('foreign_keys=ON');
        assert.throws(() => db.prepare('INSERT INTO device_registration VALUES (?,?,?,?,?)').run('incomplete','digest','device','tx',Buffer.from('{}')));
      });
    } finally { a.close(); }
  }
});

test('旧库显式升级至两位schema版本保留身份和已有权限，旧schema不自动登记设备', async t => {
  const a = await setup(t, 9), original = a.storage.identity;
  try { assert.throws(() => a.storage.registerDevice(registration()), e => e.code === 'device_migration_required'); }
  finally { a.close(); }
  const migrated = await migrateStorage(a.dir, 10); assert.equal(migrated.schema_revision, '10');
  const storage = openStorage(a.dir);
  try {
    assert.equal(storage.identity.service_id, original.service_id); assert.equal(storage.identity.database_instance_id, original.database_instance_id);
    assert(storage.registerDevice(registration()).device_id);
  } finally { storage.close(); }
  assert.equal((await migrateStorage(a.dir, 10)).changed, false);
});
