import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import canonicalize from 'canonicalize';
import {setTimeout as delay} from 'node:timers/promises';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {verifyCoreAdmission} from '../dist/core-bootstrap.mjs';
import {startProcessHost, initializeProcessHost, upgradeProcessHost, installedCoreDigest} from '../dist/process-host.mjs';

const options = {skip: process.platform !== 'win32', timeout: 30000};
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-bootstrap-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  return dir;
}
function row(db, sql) { const q = db.prepare(sql), columns = q.columns(); return Object.fromEntries(q.raw().get().map((v, i) => [columns[i].name, v])); }
function inspect(dir, file, callback) {
  const db = new Database(path.join(dir, file), {fileMustExist: true});
  try { return callback(db); } finally { db.close(); }
}
async function until(fn) {
  const end = performance.now() + 10000;
  while (!fn()) { assert(performance.now() < end, '核心未完成启动'); await delay(20); }
  return fn();
}
function policyFor(identity) {
  return {format: 'leafseamer-core-bootstrap-policy/1', service_id: identity.service_id, database_instance_id: identity.database_instance_id,
    artifact_manifest_ref: {manifest_id: 'local-integration', revision: '1', digest: installedCoreDigest()},
    platform_profile_ref: {profile_id: 'synthetic-windows-profile', revision: '1'}, policy_revision: '1', bootstrap_timeout_ms: 10000, clock_backend_revision: '1'};
}

test('真实CNG挑战、Node证明、双库回执与监听形成闭环，设备闸门保持关闭', options, async t => {
  const dir = temporary(t), identity = initializeStorage(dir);
  const migration = await migrateStorage(dir); assert.equal(migration.schema_revision, '11');
  assert(fs.existsSync(path.join(dir, migration.backup_file)));
  await initializeProcessHost(dir);
  let output = '';
  const app = await startProcessHost({dataDir: dir, bootstrapPolicy: policyFor(identity), onCoreOutput: chunk => { output += chunk; }});
  t.after(() => app.close());
  assert.equal(app.containment.bootstrap_authenticated, true); assert.equal(app.containment.runtime_admitted, false);
  const listening = await until(() => output.split('\n').filter(Boolean).map(s => JSON.parse(s)).find(f => f.event === 'listening'));
  assert.equal((await fetch(`http://127.0.0.1:${listening.port}/health/ready`)).status, 503);
  const result = await app.close(); assert.equal(result.exitCode, 0); assert.equal(result.forced, false);
  const binding = inspect(dir, 'controller.sqlite', db => {
    const b = row(db, 'SELECT * FROM core_runtime_binding');
    assert.equal(b.service_boot_id, listening.service_boot_id);
    assert.equal(db.prepare('SELECT state FROM service_boot WHERE service_boot_id=?').pluck().get(b.service_boot_id), 'stopped');
    assert.throws(() => db.prepare('DELETE FROM core_runtime_binding').run(), /immutable/);
    return b;
  });
  inspect(dir, 'supervisor-journal.db', db => {
    const a = row(db, 'SELECT * FROM core_admission');
    const b = row(db, 'SELECT * FROM core_bootstrap');
    assert.equal(a.receipt_id, binding.receipt_id); assert.equal(a.receipt_jcs, binding.receipt_jcs);
    assert.equal(b.intent_jcs, binding.intent_jcs); assert.equal(b.descriptor_jcs, binding.descriptor_jcs); assert.equal(b.policy_jcs, binding.policy_jcs);
    assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1);
  });
  assert(!/secret|challenge_nonce|"proof"/.test(JSON.stringify(binding) + output));
  const saved = {intent: JSON.parse(binding.intent_jcs), descriptor: JSON.parse(binding.descriptor_jcs), receipt: JSON.parse(binding.receipt_jcs)};
  const storage = openStorage(dir);
  try { assert.throws(() => storage.bindCoreRuntime(saved, policyFor(identity)), /UNIQUE/); }
  finally { storage.close(); }
  const assignment = {...saved.receipt, clock_domain_descriptor: saved.descriptor,
    issued_tick_ns: '0', expires_tick_ns: (BigInt(saved.receipt.admitted_tick_ns) + 1n).toString()};
  for (const change of [{member_boot_id: 'other'}, {gate_state: 'open'},
    {domain_ref: {...saved.receipt.domain_ref, clock_domain_id: 'other'}}, {admitted_tick_ns: assignment.expires_tick_ns}]) {
    await assert.rejects(verifyCoreAdmission(assignment, {...saved.receipt, ...change}, policyFor(identity)));
  }
});

test('核心绑定事务失败时不监听，监督准入原件仍保留且没有业务绑定', options, async t => {
  const dir = temporary(t), identity = initializeStorage(dir); await migrateStorage(dir); await initializeProcessHost(dir);
  inspect(dir, 'controller.sqlite', db => db.exec("CREATE TRIGGER fail_runtime BEFORE INSERT ON core_runtime_binding BEGIN SELECT RAISE(ABORT,'synthetic_write_failure'); END"));
  let output = '';
  const app = await startProcessHost({dataDir: dir, bootstrapPolicy: policyFor(identity), onCoreOutput: chunk => { output += chunk; }});
  const exit = await app.exited; assert.equal(exit.exitCode, 1); assert.equal(exit.active_processes, 0);
  assert(!output.includes('listening'));
  inspect(dir, 'supervisor-journal.db', db => assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 1));
  inspect(dir, 'controller.sqlite', db => {
    assert.equal(db.prepare('SELECT count(*) FROM core_runtime_binding').pluck().get(), 0);
    assert.equal(db.prepare('SELECT state FROM service_boot').pluck().get(), 'stopped');
  });
});

test('错误制品在创建前拒绝，错服务和旧业务库不能进入监听或保存准入', options, async t => {
  for (const mode of ['artifact', 'scope', 'old-schema']) {
    const dir = temporary(t), identity = initializeStorage(dir); if (mode !== 'old-schema') await migrateStorage(dir);
    await initializeProcessHost(dir); const policy = policyFor(identity);
    if (mode === 'artifact') policy.artifact_manifest_ref.digest = 'sha256:' + '0'.repeat(64);
    if (mode === 'scope') policy.service_id = 'different-service';
    let output = '';
    await assert.rejects(startProcessHost({dataDir: dir, bootstrapPolicy: policy, onCoreOutput: chunk => { output += chunk; }}));
    assert(!output.includes('listening'));
    inspect(dir, 'supervisor-journal.db', db => assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 0));
  }
});

test('监督日志v1必须显式备份迁移，保留历史且重复升级幂等', options, async t => {
  const dir = temporary(t); await initializeProcessHost(dir);
  inspect(dir, 'supervisor-journal.db', db => {
    for (const name of ['core_admission', 'core_bootstrap']) db.exec('DROP TABLE ' + name);
    db.pragma('user_version = 1');
    db.prepare('INSERT INTO core_attempt VALUES(?,?,?)').run('a'.repeat(32), 'old-job', '1');
    db.prepare('INSERT INTO core_observation VALUES(?,?,?,?)').run('a'.repeat(32), 1, '1', 'synthetic-image');
    db.prepare('INSERT INTO core_exit VALUES(?,?,0,?)').run('a'.repeat(32), '0', '0');
  });
  await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_journal_migration_required');
  assert.equal((await upgradeProcessHost(dir)).changed, true);
  const backups = fs.readdirSync(dir).filter(n => n.startsWith('supervisor-before-v2-')); assert.equal(backups.length, 1);
  inspect(dir, backups[0], db => { assert.equal(db.pragma('user_version', {simple: true}), 1); assert.equal(db.prepare('SELECT attempt_id FROM core_attempt').pluck().get(), 'a'.repeat(32)); });
  assert.equal((await upgradeProcessHost(dir)).changed, false);
  inspect(dir, 'supervisor-journal.db', db => { assert.equal(db.pragma('user_version', {simple: true}), 2); assert.equal(db.prepare('SELECT attempt_id FROM core_exit').pluck().get(), 'a'.repeat(32)); });
});

test('真实管道拒绝错误HMAC、角色、重复帧、EOF和超时，未决尝试阻止重启', options, async t => {
  for (const mode of ['proof', 'role', 'duplicate', 'eof', 'timeout']) {
    const dir = temporary(t), identity = initializeStorage(dir); await initializeProcessHost(dir);
    const policy = policyFor(identity); policy.bootstrap_timeout_ms = 1500;
    const child = spawn(fileURLToPath(new URL('../dist/native/leafseamer_process_host.exe', import.meta.url)),
      [dir, process.execPath, fileURLToPath(new URL('./fixtures/bootstrap-peer.mjs', import.meta.url)), 'contained-core-auth',
        '--bootstrap-policy', canonicalize(policy), '--mode', mode], {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
    let output = ''; child.stdout.on('data', chunk => { output += chunk; }); child.stderr.resume(); child.stdin.on('error', () => {});
    const closed = once(child, 'close');
    t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill(); await closed; });
    const [code] = await closed; assert.equal(code, 1);
    const frame = JSON.parse(output); assert.equal(frame.event, 'process_host_failed');
    assert.equal(frame.runtime_admitted, false);
    inspect(dir, 'supervisor-journal.db', db => {
      assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 0);
      assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 0);
      const pid = db.prepare('SELECT core_pid FROM core_observation').pluck().get();
      assert.throws(() => process.kill(pid, 0), {code: 'ESRCH'});
    });
    await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_recovery_required');
    await assert.rejects(upgradeProcessHost(dir), e => e.code === 'process_recovery_required');
  }
});
