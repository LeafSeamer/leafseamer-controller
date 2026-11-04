import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {normalizeCapture, clockInteger, openNativeClock} from '../dist/native-clock.mjs';
import {startClockMonitor} from '../dist/clock-monitor.mjs';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {startController} from '../dist/server.mjs';

const epoch = 116444736000000000n;
const digest = 'sha256:' + '1'.repeat(64);
function windows(overrides = {}) {
  return {format: 'leafseamer-native-clock/1', platform: 'win32', before_100ns: '10000', after_100ns: '10001',
    wall_filetime_100ns: String(epoch + 10000000n), continuity_before: '0', continuity_after: '0', continuity_monitor: 'power_notifications', ...overrides};
}
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-clock-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  return dir;
}
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
function simulated() {
  let now = 1000100n, generation = '0', wall = epoch + 10000000n, broken = false;
  return {
    artifactDigest: digest,
    tick: () => now,
    capture() {
      if (broken) throw new Error('synthetic_read_failure');
      return normalizeCapture(windows({before_100ns: String(now / 100n), after_100ns: String(now / 100n),
        wall_filetime_100ns: String(wall), continuity_before: generation, continuity_after: generation}));
    },
    advance(ns) { now += ns; wall += ns / 100n; },
    resume() { generation = '1'; },
    regress() { wall -= 1n; },
    break() { broken = true; }
  };
}

test('原生制品实际加载，采样与tick同源，整数精确转换', () => {
  const source = openNativeClock(), before = source.tick(), frame = source.capture(), after = source.tick();
  assert.match(source.artifactDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(frame.raw.platform, process.platform);
  assert(before <= BigInt(frame.a)); assert(BigInt(frame.a) <= BigInt(frame.b)); assert(BigInt(frame.b) <= after);
  assert.equal(BigInt(frame.valid_before) - BigInt(frame.b), 2000000000n);
  if (process.platform === 'win32') assert.equal(BigInt(frame.w), (BigInt(frame.raw.wall_filetime_100ns) - epoch) * 100n);
  assert.equal(normalizeCapture(windows()).w, '1000000000');
});

test('原生整数边界、FILETIME纪元、采集预算与Linux命名空间严格拒绝', () => {
  for (const value of ['01', '-1', '1\n', '1.0', '18446744073709551616', 1]) assert.throws(() => clockInteger(value));
  assert.equal(clockInteger('18446744073709551615'), (1n << 64n) - 1n);
  assert.equal(normalizeCapture(windows({wall_filetime_100ns: String(epoch)})).w, '0');
  for (const overrides of [{wall_filetime_100ns: String(epoch - 1n)}, {before_100ns: '18446744073709551615'},
    {after_100ns: '9999'}, {after_100ns: '210001'}, {continuity_after: '1'}, {extra: true}]) assert.throws(() => normalizeCapture(windows(overrides)));
  assert.equal(normalizeCapture(windows({after_100ns: '210000'})).b, '21000000');
  const linux = {format: 'leafseamer-native-clock/1', platform: 'linux', before_sec: '1', before_nsec: '0',
    after_sec: '1', after_nsec: '1', wall_sec: '2', wall_nsec: '3', namespace_before: '1:2', namespace_after: '1:2', continuity_monitor: 'unavailable'};
  assert.equal(normalizeCapture(linux).w, '2000000003');
  for (const overrides of [{wall_nsec: '1000000000'}, {wall_sec: '18446744073709551615'}, {namespace_after: '1:3'},
    {namespace_before: '1:2\n', namespace_after: '1:2\n'}]) assert.throws(() => normalizeCapture({...linux, ...overrides}));
});

test('两秒等号、连续性变化、墙钟回退和读取失败均持久锁存，不由新采样恢复', async t => {
  for (const [change, reason] of [[s => s.advance(2000000000n), 'clock_sample_expired'],
    [s => s.resume(), 'clock_continuity'], [s => s.regress(), 'clock_wall_regressed'], [s => s.break(), 'clock_source_or_journal_failure']]) {
    const dir = temporary(t); initializeStorage(dir); await migrateStorage(dir);
    const storage = openStorage(dir), source = simulated(), monitor = startClockMonitor(source, storage.clockJournal, {schedule: false});
    const boot = storage.serviceBootId;
    try {
      assert.deepEqual(monitor.status(), {state: 'unqualified', reason: 'clock_approval_missing', qualified: false, durable: true});
      change(source); monitor.refresh();
      assert.equal(monitor.status().reason, reason); assert.equal(monitor.status().qualified, false);
      monitor.refresh(); assert.equal(storage.clockJournal.current().reason, reason);
      assert.throws(() => storage.clockJournal.sample(normalizeCapture(windows()), digest), e => e.code === 'clock_journal_closed');
    } finally { monitor.stop(); storage.close(); }
    inspect(dir, db => {
      assert.deepEqual(db.prepare('SELECT state, reason, sequence FROM authentication_clock_diagnostic WHERE service_boot_id = ?').raw().get(boot), ['faulted', reason, 1]);
      assert.throws(() => db.prepare("UPDATE authentication_clock_diagnostic SET state = 'unqualified'").run());
      assert.throws(() => db.prepare('DELETE FROM authentication_clock_diagnostic').run());
    });
  }
});

test('诊断提交故障不报告耐久成功；停止后不再采集', () => {
  const source = simulated(); let samples = 0;
  const journal = {current: () => ({state: 'unqualified'}), sample() { samples++; throw new Error('synthetic_disk_failure'); }, fault() { throw new Error('synthetic_disk_failure'); }};
  const monitor = startClockMonitor(source, journal, {schedule: false});
  assert.deepEqual(monitor.status(), {state: 'faulted', reason: 'clock_source_or_journal_failure', qualified: false, durable: false});
  monitor.stop(); monitor.refresh(); assert.equal(samples, 1);
});

test('实际诊断持续写入经checkpoint复用WAL，停止后保留最后采样', async t => {
  const dir = temporary(t); initializeStorage(dir); await migrateStorage(dir);
  const storage = openStorage(dir), source = simulated(), monitor = startClockMonitor(source, storage.clockJournal, {schedule: false});
  try {
    for (let i = 1; i < 32; i++) { source.advance(500000000n); monitor.refresh(); }
    const first = fs.statSync(path.join(dir, 'controller.sqlite-wal')).size;
    for (let i = 0; i < 32; i++) { source.advance(500000000n); monitor.refresh(); }
    assert(fs.statSync(path.join(dir, 'controller.sqlite-wal')).size <= first);
    assert.equal(monitor.status().state, 'unqualified');
  } finally { monitor.stop(); storage.close(); }
  assert.equal(inspect(dir, db => db.prepare('SELECT sequence FROM authentication_clock_diagnostic').pluck().get()), 64);
});

test('v2身份升级v3不改身份与回执，第二步失败保留已提交v2', async t => {
  const dir = temporary(t); initializeStorage(dir); await migrateStorage(dir, 2);
  const storage = openStorage(dir);
  let result;
  try {
    const {token_id, secret} = storage.enrollment.begin();
    result = await storage.enrollment.complete({token_id, secret, login: 'synthetic-clock-admin', password: 'synthetic-password-012345', mode: 'standalone'});
  } finally { storage.close(); }
  const migrated = await migrateStorage(dir); assert.equal(migrated.steps.length, 1); assert.equal(migrated.schema_revision, '3');
  const reopened = openStorage(dir);
  try { assert.deepEqual(reopened.enrollment.summary(), result); } finally { reopened.close(); }
  const failed = temporary(t); initializeStorage(failed);
  inspect(failed, db => db.exec('CREATE TABLE authentication_clock_diagnostic (collision TEXT)'));
  await assert.rejects(migrateStorage(failed), e => e.code === 'migration_failed');
  assert.equal(inspect(failed, db => db.pragma('user_version', {simple: true})), 2);
  const preserved = openStorage(failed); preserved.close();
});

test('schema3实际服务保存原生诊断并保持HTTP未就绪', async t => {
  const dir = temporary(t); initializeStorage(dir); await migrateStorage(dir);
  const app = await startController({dataDir: dir});
  try {
    const live = await fetch(`http://127.0.0.1:${app.address.port}/health/live`); assert.equal(live.status, 200);
    const ready = await fetch(`http://127.0.0.1:${app.address.port}/health/ready`);
    assert.equal(ready.status, 503); assert.deepEqual(await ready.json(), {ready: false, reason: 'authentication_clock_unqualified'});
  } finally { await app.close(); }
  inspect(dir, db => {
    const [state, body, artifact] = db.prepare('SELECT state, last_capture, native_artifact_digest FROM authentication_clock_diagnostic').raw().get();
    assert.equal(state, 'unqualified'); assert.match(artifact, /^sha256:[0-9a-f]{64}$/);
    const capture = JSON.parse(body.toString()); assert.equal(capture.raw.platform, process.platform); assert.equal(capture.qualified, undefined);
  });
});
