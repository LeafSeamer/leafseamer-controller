import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import Database from 'better-sqlite3';
import {createClient, createFetchTransport, contractSelection} from '@leafseamer/sdk';
import {initializeStorage, openStorage} from '../dist/storage.mjs';
import {startController} from '../dist/server.mjs';

const cli = fileURLToPath(new URL('../dist/cli.mjs', import.meta.url));
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-controller-'));
  t.after(() => { const resolved = path.resolve(dir); assert.equal(path.dirname(resolved), path.resolve(os.tmpdir())); fs.rmSync(resolved, {recursive: true, force: true}); });
  return dir;
}
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { return fn(db); } finally { db.close(); }
}
function rows(db, sql) {
  const stmt = db.prepare(sql), names = stmt.columns().map(c => c.name);
  return stmt.raw().all().map(values => Object.fromEntries(names.map((name, i) => [name, values[i]])));
}
async function run(...args) {
  const child = spawn(process.execPath, ['--disallow-code-generation-from-strings', cli, ...args], {stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true});
  let stdout = '', stderr = '';
  child.stdout.setEncoding('utf8').on('data', x => { stdout += x; });
  child.stderr.setEncoding('utf8').on('data', x => { stderr += x; });
  const [code] = await once(child, 'close'); return {code, stdout, stderr};
}
async function launch(t, dir) {
  const child = spawn(process.execPath, ['--disallow-code-generation-from-strings', cli, 'start', '--data-dir', dir], {stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true});
  const closed = once(child, 'close'); let buffer = '', stderr = '';
  child.stderr.setEncoding('utf8').on('data', x => { stderr += x; });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill(); await closed; });
  const first = new Promise((resolve, reject) => {
    child.stdout.setEncoding('utf8').on('data', x => {
      buffer += x;
      if (buffer.includes('\n')) { try { resolve(JSON.parse(buffer.split('\n')[0])); } catch (error) { reject(error); } }
    });
    child.once('error', reject);
    child.once('exit', code => reject(new Error('startup_exit:' + code + ':' + stderr)));
  });
  return {child, closed, listening: await first};
}

test('业务库缺失拒绝启动，不自动分配新身份', t => {
  const dir = temporary(t);
  assert.throws(() => openStorage(dir), e => e.code === 'database_unavailable');
  assert.equal(fs.existsSync(path.join(dir, 'controller.sqlite')), false);
});

test('显式建库、持久身份、重启新boot及排他所有者', t => {
  const dir = temporary(t), initial = initializeStorage(dir);
  assert.equal(initial.maintenance_state, 'protected');
  const before = fs.readFileSync(path.join(dir, 'controller.sqlite'));
  assert.throws(() => initializeStorage(dir), e => e.code === 'database_already_exists');
  assert.deepEqual(fs.readFileSync(path.join(dir, 'controller.sqlite')), before);
  const first = openStorage(dir);
  try {
    assert.deepEqual(first.identity, initial);
    assert.equal(first.engine.version, '3.53.4');
    assert.throws(() => openStorage(dir), e => e.code === 'database_in_use');
  } finally { first.close(); }
  const second = openStorage(dir);
  try { assert.deepEqual(second.identity, initial); assert.notEqual(second.serviceBootId, first.serviceBootId); }
  finally { second.close(); }
  const boots = inspect(dir, db => rows(db, 'SELECT * FROM service_boot'));
  assert.equal(boots.length, 2); assert(boots.every(x => x.state === 'stopped' && x.stopped_utc));
  inspect(dir, db => {
    assert.throws(() => db.prepare('DELETE FROM service_state').run());
    assert.throws(() => db.prepare("UPDATE service_state SET service_id = 'different'").run());
    assert.throws(() => db.prepare('DELETE FROM service_boot').run());
    assert.equal(db.prepare('SELECT count(*) FROM schema_migration').pluck().get(), 1);
  });
});

test('未知库版本和迁移内容不自动修复或回退', t => {
  const dir = temporary(t); initializeStorage(dir);
  inspect(dir, db => db.pragma('user_version = 99'));
  assert.throws(() => openStorage(dir), e => e.code === 'database_version_mismatch');
  inspect(dir, db => {
    assert.equal(db.pragma('user_version', {simple: true}), 99);
    db.pragma('user_version = 1');
    db.exec('DROP TRIGGER schema_migration_no_update');
    db.prepare("UPDATE schema_migration SET script_digest = 'wrong'").run();
  });
  assert.throws(() => openStorage(dir), e => e.code === 'migration_mismatch');
  assert.equal(inspect(dir, db => db.prepare('SELECT count(*) FROM service_boot').pluck().get()), 0);
});

test('实际Controller与SDK连通，存活和业务就绪分开', {timeout: 10000}, async t => {
  const dir = temporary(t); initializeStorage(dir);
  const app = await startController({dataDir: dir});
  try {
    const baseUrl = `http://127.0.0.1:${app.address.port}`;
    const client = createClient('controller', contractSelection, createFetchTransport({authority: 'controller', baseUrl, allowInsecureLoopback: true}));
    const discovery = await client.call('discoverContracts');
    assert.equal(discovery.status, '503'); assert.equal(discovery.body, null);
    const live = await fetch(baseUrl + '/health/live'); assert.equal(live.status, 200); assert.deepEqual(await live.json(), {status: 'alive'});
    const ready = await fetch(baseUrl + '/health/ready'); assert.equal(ready.status, 503); assert.deepEqual(await ready.json(), {ready: false, reason: 'bootstrap_incomplete'});
    assert.equal((await fetch(baseUrl + '/api/v1/commands', {method: 'POST', body: '{}'})).status, 413);
    assert.equal((await fetch(baseUrl + '/api/v1/commands', {method: 'POST'})).status, 405);
    assert.equal((await fetch(baseUrl + '/health/live?extra=1')).status, 404);
    const head = await fetch(baseUrl + '/health/live', {method: 'HEAD'}); assert.equal(head.status, 200); assert.equal((await head.arrayBuffer()).byteLength, 0);
    const duplicate = await run('start', '--data-dir', dir); assert.equal(duplicate.code, 1); assert.equal(JSON.parse(duplicate.stderr).error, 'database_in_use');
  } finally { await app.close(); }
});

test('真实CLI进程强停后保留旧boot事实与scope，新进程仍关闭', {timeout: 15000}, async t => {
  const dir = temporary(t);
  const init = await run('init-storage', '--data-dir', dir); assert.equal(init.code, 0);
  const identity = JSON.parse(init.stdout); assert.equal(identity.ready, false);
  const first = await launch(t, dir); assert.equal(first.listening.ready, false);
  first.child.kill('SIGKILL'); await first.closed;
  const second = await launch(t, dir);
  assert.equal(second.listening.service_id, identity.service_id);
  assert.equal(second.listening.database_instance_id, identity.database_instance_id);
  assert.notEqual(second.listening.service_boot_id, first.listening.service_boot_id);
  assert.equal(second.listening.ready, false);
  second.child.kill('SIGKILL'); await second.closed;
  const boots = inspect(dir, db => rows(db, 'SELECT * FROM service_boot'));
  assert.equal(boots.length, 2); assert(boots.every(x => x.state === 'started' && x.stopped_utc === null));
});

test('CLI配置错误不建库，不暴露本机目录', async t => {
  const dir = temporary(t);
  const invalid = await run('start', '--data-dir', dir, '--port', '-1'); assert.equal(invalid.code, 1);
  assert.equal(invalid.stderr.includes(dir), false); assert.equal(fs.existsSync(path.join(dir, 'controller.sqlite')), false);
  const relative = await run('init-storage', '--data-dir', 'relative'); assert.equal(relative.code, 1);
  await assert.rejects(startController({dataDir: dir, host: '0.0.0.0'}), /listen_options/);
});
