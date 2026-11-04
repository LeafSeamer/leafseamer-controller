import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {seal, policy, captureInterval, extrapolate} from '../dist/auth-clock-value.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';

import {fixture} from './auth-clock-fixture.mjs';
const wall = 1700000000000000000n;
async function directory(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-auth-clock-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  initializeStorage(dir); await migrateStorage(dir); return dir;
}
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
const counts = dir => inspect(dir, db => ['evidence', 'acquisition', 'head', 'fault'].map(name => db.prepare('SELECT count(*) FROM authentication_clock_' + name).pluck().get()));

test('整数外包算法使用固定期望值，拒绝零误差、溢出和被篡改的policy', () => {
  const f = fixture({service_id: crypto.randomUUID(), service_boot_id: crypto.randomUUID()}), capture = f.source.capture();
  assert.deepEqual(captureInterval(capture, f.evidence.policy), {lower_ns: String(wall - 1122n), upper_ns: String(wall + 1143n)});
  const p = f.evidence.policy;
  for (const change of [{max_system_error_ns: '0'}, {wall_quantization_ns: '0'}, {sample_ttl_ns: '2000000001'}, {drift_ppb: 1000001}]) {
    const {digest, ...body} = p; assert.throws(() => policy(seal({...body, ...change})));
  }
  assert.throws(() => policy({...p, max_system_error_ns: '1'}), e => e.code === 'auth_clock_digest');
  const {digest, ...body} = p;
  assert.throws(() => captureInterval(capture, seal({...body, max_system_error_ns: '18446744073709551615'})), e => e.code === 'auth_clock_range');
  assert.throws(() => captureInterval({...capture, w: '1'}, p), e => e.code === 'auth_clock_capture');
});

test('真实文件库同事务保存原件、依赖和head，每次读取外推且故障永久保留', async t => {
  const dir = await directory(t), storage = openStorage(dir), f = fixture(storage.authenticationClock.scope);
  const clock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  try {
    assert.equal(clock.status().qualified, true);
    const first = clock.current(); assert.equal(first.lower_ns, String(wall - 1122n));
    f.source.advance(500000000n); clock.refresh();
    const second = clock.current(); assert.notDeepEqual(second.acquisition_ref, first.acquisition_ref);
    const record = storage.authenticationClock.current(f.evidence.runtime.clock_domain_id);
    assert.equal(record.sequence, '2'); assert.deepEqual(record.parent_ref, first.acquisition_ref);
    assert.equal(record.effective_upper_ns, String(wall + 500500000n + 1143n));
    assert.throws(() => extrapolate(record, BigInt(record.valid_before_tick_ns)), e => e.code === 'auth_clock_expired');
    f.source.advance(2000000000n); clock.refresh();
    assert.equal(clock.status().qualified, false); assert.throws(() => clock.current());
    clock.refresh(); assert.equal(storage.authenticationClock.current(f.evidence.runtime.clock_domain_id).sequence, '2');
  } finally { clock.stop(); storage.close(); }
  assert.deepEqual(counts(dir), [3, 2, 1, 1]);
  inspect(dir, db => {
    for (const name of ['evidence', 'acquisition', 'fault']) {
      assert.throws(() => db.exec('DELETE FROM authentication_clock_' + name));
      assert.throws(() => db.exec("UPDATE authentication_clock_" + name + " SET digest = 'changed'"));
    }
    assert.equal(db.prepare('PRAGMA foreign_key_check').raw().all().length, 0);
  });
});

test('相同id只查原，不延长期限；换采样正文使该域持久保护', async t => {
  const dir = await directory(t), storage = openStorage(dir), ledger = storage.authenticationClock, f = fixture(ledger.scope), id = crypto.randomUUID();
  try {
    const capture = f.source.capture();
    const first = ledger.ingest(capture, f.evidence, f.source, f.provider.read, id);
    f.source.advance(100000000n);
    const again = ledger.ingest(capture, f.evidence, f.source, f.provider.read, id);
    assert.deepEqual(again.acquisition_ref, first.acquisition_ref); assert.equal(again.replay, true);
    const wrong = ledger.ingest(f.source.capture(), f.evidence, f.source, f.provider.read, id);
    assert.equal(wrong.state, 'protected'); assert(wrong.fault_ref);
    assert.throws(() => ledger.read(f.evidence.runtime.clock_domain_id, f.source.tick(), f.evidence, f.source.artifactDigest));
  } finally { storage.close(); }
  assert.deepEqual(counts(dir), [3, 1, 1, 1]);
});

test('采样缺口、时钟跳变、恢复通知、上下文变化和读取失败立即拒绝', async t => {
  for (const change of [f => f.source.advance(2000000000n), f => f.source.jump(1000000000n), f => f.source.resume(),
    f => { f.evidence.health.state = 'unsynchronized'; }, f => f.source.break()]) {
    const dir = await directory(t), storage = openStorage(dir), f = fixture(storage.authenticationClock.scope);
    const clock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
    try { change(f); assert.throws(() => clock.current()); assert.equal(clock.status().qualified, false); assert.equal(clock.status().durable, true); }
    finally { clock.stop(); storage.close(); }
    assert.deepEqual(counts(dir), [3, 1, 1, 1]);
  }
});

test('提交前到期或配置变化回滚全部新原件并提交保护事实', async t => {
  for (const change of [f => f.source.advance(2000000000n), f => { f.evidence.health.valid_before_tick_ns = '1'; }]) {
    const dir = await directory(t), storage = openStorage(dir), ledger = storage.authenticationClock, f = fixture(ledger.scope);
    try {
      const before = structuredClone(f.evidence);
      const result = ledger.ingest(f.source.capture(), before, f.source, () => { change(f); return f.provider.read(); });
      assert.equal(result.state, 'protected'); assert.equal(result.acquisition_ref, null);
    } finally { storage.close(); }
    assert.deepEqual(counts(dir), [0, 0, 0, 1]);
  }
});

test('每个持久写点失败不留下部分原件，故障提交失败不谎报durable', async t => {
  for (const target of ['evidence', 'acquisition', 'head', 'fault']) {
    const dir = await directory(t);
    inspect(dir, db => db.exec(`CREATE TRIGGER synthetic_failure BEFORE INSERT ON authentication_clock_${target} BEGIN SELECT RAISE(ABORT, 'synthetic_failure'); END`));
    const storage = openStorage(dir), f = fixture(storage.authenticationClock.scope);
    if (target === 'fault') f.source.break();
    const clock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
    try {
      assert.equal(clock.status().qualified, false);
      assert.equal(clock.status().durable, target !== 'fault');
    } finally { clock.stop(); storage.close(); }
    assert.deepEqual(counts(dir), [0, 0, 0, target === 'fault' ? 0 : 1]);
  }
});

test('COMMIT之后到期保留原件并保护，缺可信提供者不能建立认证资格', async t => {
  const dir = await directory(t), storage = openStorage(dir), ledger = storage.authenticationClock, f = fixture(ledger.scope);
  const absent = startAuthenticationClock(f.source, ledger, null, {schedule: false});
  assert.equal(absent.status().qualified, false); assert.throws(() => absent.current()); absent.stop();
  const delayed = {...ledger, ingest(...args) { const result = ledger.ingest(...args); f.source.advance(2000000000n); return result; }};
  const clock = startAuthenticationClock(f.source, delayed, f.provider, {schedule: false});
  try { assert.equal(clock.status().qualified, false); assert.equal(clock.status().durable, true); }
  finally { clock.stop(); storage.close(); }
  assert.deepEqual(counts(dir), [3, 1, 1, 1]);
});

test('当前时间窗口不超出健康原件期限，健康更新不刷新旧采样的两秒期限', async t => {
  const dir = await directory(t), storage = openStorage(dir), f = fixture(storage.authenticationClock.scope);
  const {digest, ...health} = f.evidence.health;
  f.evidence.health = seal({...health, valid_before_tick_ns: String(f.source.tick() + 1000000000n)});
  const clock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
  try {
    assert.equal(clock.current().valid_before_tick_ns, '11000000000');
    f.source.advance(1000000000n);
    assert.throws(() => clock.current(), e => e.code === 'auth_clock_evidence_expired');
    assert.equal(clock.status().qualified, false);
  } finally { clock.stop(); storage.close(); }
});
