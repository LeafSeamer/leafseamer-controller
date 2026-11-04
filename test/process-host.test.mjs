import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import Database from 'better-sqlite3';
import {startProcessHost, initializeProcessHost} from '../dist/process-host.mjs';
import {initializeStorage} from '../dist/storage.mjs';

const windows = process.platform === 'win32', options = {skip: !windows, timeout: 20000};
const dist = fileURLToPath(new URL('../dist/', import.meta.url));
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer process '));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  return dir;
}
function collector() {
  let pending = ''; const frames = [];
  return {frames, write(chunk) { pending += chunk.toString();
    while (pending.includes('\n')) { const i = pending.indexOf('\n'); const text = pending.slice(0, i); pending = pending.slice(i + 1); frames.push(JSON.parse(text)); }
  }};
}
async function until(fn) {
  const end = performance.now() + 7000;
  while (!fn()) { assert(performance.now() < end, '等待实际进程状态超时'); await delay(20); }
  return fn();
}
const gone = pid => { try { process.kill(pid, 0); return false; } catch (e) { if (e.code === 'ESRCH') return true; throw e; } };
async function tree(t) {
  const dir = temporary(t); await initializeProcessHost(dir);
  const status = collector(), core = collector();
  const child = spawn(path.join(dist, 'native/leafseamer_process_host.exe'), [dir, process.execPath,
    fileURLToPath(new URL('./fixtures/process-tree.mjs', import.meta.url))], {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
  const closed = once(child, 'close'); child.stdout.on('data', x => status.write(x)); child.stderr.on('data', x => core.write(x)); child.stdin.on('error', () => {});
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill(); await closed; });
  await until(() => core.frames.some(f => f.event === 'leaf_running'));
  const parent = core.frames.find(f => f.event === 'tree_running'), leaf = core.frames.find(f => f.event === 'leaf_running');
  assert.equal(parent.leaf_pid, leaf.pid); assert.equal(status.frames[0].core_pid, parent.pid);
  return {child, closed, status, parent, leaf};
}

test('真实原生宿主启动Controller，停止后库正常关闭并确认空组', options, async t => {
  const dir = temporary(t); initializeStorage(dir); await initializeProcessHost(dir); const core = collector();
  const app = await startProcessHost({dataDir: dir, onCoreOutput: x => core.write(x)});
  t.after(() => app.close());
  assert.equal(app.containment.runtime_admitted, false);
  const listening = await until(() => core.frames.find(f => f.event === 'listening'));
  const ready = await fetch(`http://127.0.0.1:${listening.port}/health/ready`);
  assert.equal(ready.status, 503);
  const result = await app.close();
  assert.equal(result.exitCode, 0); assert.equal(result.forced, false); assert.equal(result.active_processes, 0);
  assert.equal(result.containment_id, app.containment.containment_id); assert.equal(result.runtime_admitted, false);
  assert(core.frames.some(f => f.event === 'stopped')); assert(gone(app.containment.core_pid));
  const db = new Database(path.join(dir, 'controller.sqlite'), {fileMustExist: true});
  try { assert.equal(db.prepare('SELECT state FROM service_boot').pluck().get(), 'stopped'); } finally { db.close(); }
});

test('核心启动失败仍回收整组，不建立缺失业务库', options, async t => {
  const dir = temporary(t), output = collector(); await initializeProcessHost(dir);
  const app = await startProcessHost({dataDir: dir, onCoreOutput: x => output.write(x)});
  const result = await app.exited;
  assert.equal(result.exitCode, 1); assert.equal(result.active_processes, 0);
  assert(output.frames.some(f => f.error === 'database_unavailable'));
  assert.equal(fs.existsSync(path.join(dir, 'controller.sqlite')), false);
});

test('核心退出后残留的detached后代仍被整组终止', options, async t => {
  const run = await tree(t); run.child.stdin.end('stop\n');
  const [code] = await run.closed; assert.equal(code, 1);
  const result = run.status.frames.at(-1);
  assert.equal(result.event, 'process_group_empty'); assert.equal(result.core_exit_code, 0); assert.equal(result.forced, true);
  assert(gone(run.parent.pid)); assert(gone(run.leaf.pid));
});

test('宿主被强制终止时Job句柄关闭，核心和后代退出', options, async t => {
  const run = await tree(t); run.child.kill(); await run.closed;
  await until(() => gone(run.parent.pid) && gone(run.leaf.pid));
  assert.equal(run.status.frames.some(f => f.event === 'process_group_empty'), false);
});

test('核心崩溃触发原生宿主回收全部后代', options, async t => {
  const run = await tree(t); process.kill(run.parent.pid); await run.closed;
  assert.equal(run.status.frames.at(-1).event, 'process_group_empty');
  assert(gone(run.parent.pid)); assert(gone(run.leaf.pid));
});

test('实际supervise CLI消失后，控制管道关闭使宿主和核心退出', options, async t => {
  const dir = temporary(t); initializeStorage(dir); await initializeProcessHost(dir); const status = collector(), output = collector();
  const child = spawn(process.execPath, [path.join(dist, 'cli.mjs'), 'supervise', '--data-dir', dir], {stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true});
  const closed = once(child, 'close'); child.stdout.on('data', x => status.write(x)); child.stderr.on('data', x => output.write(x));
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill(); await closed; });
  await until(() => output.frames.some(f => f.event === 'listening'));
  const frame = status.frames.find(f => f.event === 'process_contained'); assert(frame);
  child.kill(); await closed;
  await until(() => gone(frame.supervisor_pid) && gone(frame.core_pid));
});

test('控制管道失效或畸形输入停止整组，不恢复创建', options, async t => {
  for (const malformed of [false, true]) {
    const run = await tree(t); run.child.stdin.end(malformed ? 'invalid\n' : undefined);
    const [code] = await run.closed; assert.equal(code, 1);
    assert.equal(run.status.frames.at(-1).event, 'process_group_empty');
    assert(gone(run.parent.pid)); assert(gone(run.leaf.pid));
  }
});

test('安装包资产漂移在创建进程前拒绝', options, async t => {
  const dir = temporary(t), copy = path.join(dir, 'dist'); fs.cpSync(dist, copy, {recursive: true});
  fs.appendFileSync(path.join(copy, 'cli.mjs'), '\n// synthetic drift\n');
  const module = await import(pathToFileURL(path.join(copy, 'process-host.mjs')));
  await assert.rejects(module.startProcessHost({dataDir: dir}), e => e.code === 'process_host_artifact');
});

test('非Windows平台拒绝用其它进程机制伪装已实现的Job宿主', {skip: windows}, async () => {
  await assert.rejects(startProcessHost({dataDir: '/tmp/controller'}), e => e.code === 'process_host_platform');
});

function journal(dir, read) {
  const db = new Database(path.join(dir, 'supervisor-journal.db'), {fileMustExist: true});
  try { return read(db); } finally { db.close(); }
}

test('日志必须显式安装，重复初始化不覆盖；正常两次启动保留不同尝试和退出原件', options, async t => {
  const dir = temporary(t); initializeStorage(dir);
  await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_journal_missing');
  assert.equal(fs.existsSync(path.join(dir, 'supervisor-journal.db')), false);
  await initializeProcessHost(dir); const original = fs.readFileSync(path.join(dir, 'supervisor-journal.db'));
  await assert.rejects(initializeProcessHost(dir), e => e.code === 'process_journal_exists');
  assert.deepEqual(fs.readFileSync(path.join(dir, 'supervisor-journal.db')), original);
  const ids = [];
  for (let i = 0; i < 2; ++i) {
    const core = collector(), app = await startProcessHost({dataDir: dir, onCoreOutput: x => core.write(x)});
    t.after(() => app.close()); await until(() => core.frames.some(f => f.event === 'listening'));
    ids.push(app.containment.containment_id); assert.equal((await app.close()).exitCode, 0);
  }
  assert.notEqual(...ids);
  journal(dir, db => {
    assert.equal(db.pragma('journal_mode', {simple: true}), 'delete');
    for (const table of ['core_attempt','core_observation','core_exit']) assert.equal(db.prepare(`SELECT count(*) FROM ${table}`).pluck().get(), 2);
    assert.equal(db.prepare('SELECT active_processes FROM core_exit LIMIT 1').pluck().get(), 0);
    assert.throws(() => db.exec('DELETE FROM core_exit'));
    assert.throws(() => db.exec('UPDATE core_attempt SET supervisor_pid=1'));
  });
});

test('同目录及junction别名不能在已运行核心前创建第二组', options, async t => {
  const root = temporary(t), dir = path.join(root, 'data'), alias = path.join(root, 'alias');
  fs.mkdirSync(dir); fs.symlinkSync(dir, alias, 'junction'); initializeStorage(dir); await initializeProcessHost(dir);
  const core = collector(), app = await startProcessHost({dataDir: dir, onCoreOutput: x => core.write(x)});
  t.after(() => app.close()); await until(() => core.frames.some(f => f.event === 'listening'));
  for (const dataDir of [dir, alias]) await assert.rejects(startProcessHost({dataDir}), e => e.code === 'instance_in_use');
  assert.equal((await app.close()).exitCode, 0);
  assert.equal(journal(dir, db => db.prepare('SELECT count(*) FROM core_attempt').pluck().get()), 1);
});

test('宿主崩溃保留未结束尝试，即使旧PID已退出也不能自动接替', options, async t => {
  const dir = temporary(t); initializeStorage(dir); await initializeProcessHost(dir);
  const core = collector(), app = await startProcessHost({dataDir: dir, onCoreOutput: x => core.write(x)});
  await until(() => core.frames.some(f => f.event === 'listening'));
  process.kill(app.containment.supervisor_pid);
  await assert.rejects(app.exited, e => e.code === 'process_host_exit_unproven');
  await until(() => gone(app.containment.core_pid));
  await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_recovery_required');
  journal(dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM core_attempt').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 0);
  });
});

test('复制目录、损坏日志及DDL漂移均不能作为健康新宿主启动', options, async t => {
  const dir = temporary(t); initializeStorage(dir); await initializeProcessHost(dir);
  const copied = temporary(t); fs.copyFileSync(path.join(dir, 'supervisor-journal.db'), path.join(copied, 'supervisor-journal.db'));
  await assert.rejects(startProcessHost({dataDir: copied}), e => e.code === 'process_journal_identity');
  journal(dir, db => db.exec('DROP TRIGGER attempt_no_delete'));
  await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_journal_schema');
  const broken = temporary(t); fs.writeFileSync(path.join(broken, 'supervisor-journal.db'), 'synthetic invalid database');
  await assert.rejects(startProcessHost({dataDir: broken}), e => e instanceof Error);
  assert.equal(fs.readFileSync(path.join(broken, 'supervisor-journal.db'), 'utf8'), 'synthetic invalid database');
});

test('OS创建失败仍保留已消耗尝试，不允许重新运行该目录', options, async t => {
  const dir = temporary(t); await initializeProcessHost(dir); const status = collector();
  const child = spawn(path.join(dist, 'native/leafseamer_process_host.exe'), [dir, path.join(dir, 'missing-node.exe'),
    path.join(dist, 'cli.mjs'), 'contained-core'], {stdio: ['pipe','pipe','pipe'], windowsHide: true});
  const closed = once(child, 'close'); child.stdout.on('data', x => status.write(x)); child.stderr.resume(); child.stdin.end();
  assert.equal((await closed)[0], 1); assert.equal(status.frames[0].code, 'process_create_failed');
  await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_recovery_required');
  journal(dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM core_attempt').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM core_observation').pluck().get(), 0);
  });
});
