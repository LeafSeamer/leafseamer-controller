import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import canonicalize from 'canonicalize';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage} from '../dist/storage.mjs';
import {initializeProcessHost, startProcessHost, installedCoreDigest} from '../dist/process-host.mjs';
import {connectCoreSupervisor} from '../dist/supervisor-control.mjs';
const options = {skip: process.platform !== 'win32', timeout: 60000};
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-control-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); }); return dir;
}
function collect() {
  let buffer = ''; const frames = [];
  return {frames, write(chunk) { buffer += chunk; while (buffer.includes('\n')) { const end = buffer.indexOf('\n'); frames.push(JSON.parse(buffer.slice(0, end))); buffer = buffer.slice(end + 1); } }};
}
async function until(fn) {
  const deadline = performance.now() + 10000;
  while (!fn()) { assert(performance.now() < deadline, '等待真实进程事件超时'); await delay(20); } return fn();
}
function policyFor(identity) {
  return {format: 'leafseamer-core-bootstrap-policy/1', service_id: identity.service_id, database_instance_id: identity.database_instance_id,
    artifact_manifest_ref: {manifest_id: 'local-integration', revision: '1', digest: installedCoreDigest()},
    platform_profile_ref: {profile_id: 'synthetic-windows-profile', revision: '1'}, policy_revision: '1', bootstrap_timeout_ms: 10000, clock_backend_revision: '1'};
}
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'supervisor-journal.db'), {fileMustExist: true}); try { fn(db); } finally { db.close(); }
}
async function raw(t, mode) {
  const dir = temporary(t), identity = initializeStorage(dir); await initializeProcessHost(dir);
  const output = collect(), status = collect();
  const child = spawn(fileURLToPath(new URL('../dist/native/leafseamer_process_host.exe', import.meta.url)),
    [dir, process.execPath, fileURLToPath(new URL('./fixtures/control-core.mjs', import.meta.url)), 'contained-core-auth', '--bootstrap-policy', canonicalize(policyFor(identity)), '--mode', mode],
    {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
  const closed = once(child, 'close'); child.stdin.on('error', () => {}); child.stdout.on('data', status.write); child.stderr.on('data', output.write);
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill(); await closed; });
  return {dir, child, closed, status, output};
}
test('真实核心持续查询已提交回执，超过单次等待窗口仍可服务且不重签准入', options, async t => {
  const dir = temporary(t), identity = initializeStorage(dir); await migrateStorage(dir); await initializeProcessHost(dir); const output = collect();
  const app = await startProcessHost({dataDir: dir, bootstrapPolicy: policyFor(identity), onCoreOutput: output.write}); t.after(() => app.close());
  const listening = await until(() => output.frames.find(f => f.event === 'listening'));
  await delay(2600); assert.equal((await fetch(`http://127.0.0.1:${listening.port}/health/live`)).status, 200);
  const exit = await app.close(); assert.equal(exit.exitCode, 0); assert.equal(exit.control_failed, false);
  inspect(dir, db => { assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 1); assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1); });
});
test('真实管道从原生SQLite查回完整原件，未知键与同ID异摘要分别返回null和冲突', options, async t => {
  for (const mode of ['normal', 'missing', 'conflict']) {
    const run = await raw(t, mode), response = await until(() => run.output.frames.find(f => f.event === 'response'));
    assert.equal(response.sequence, '1'); assert.equal(response.reply_to, 'first');
    if (mode === 'missing') assert.equal(response.payload.record, null);
    else if (mode === 'conflict') assert.equal(response.payload.code, 'identity_conflict');
    else assert.equal(response.payload.record.gate_state, 'closed');
    run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
    inspect(run.dir, db => {
      if (mode === 'normal') assert.deepEqual(JSON.parse(db.prepare('SELECT receipt_jcs FROM core_admission').pluck().get()), response.payload.record.admission_receipt);
      assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 1);
    });
  }
});
test('错范围、通道、序号、方向、重复键和重放关闭实际进程组并保存退出原件', options, async t => {
  for (const mode of ['scope', 'channel', 'sequence', 'reply', 'direction', 'duplicate-key', 'replay', 'disconnect', 'silent']) {
    const run = await raw(t, mode); assert.equal((await run.closed)[0], 1);
    const result = run.status.frames.at(-1); assert.equal(result.event, 'process_group_empty', mode); assert.equal(result.control_failed, true, mode);
    assert.equal(result.active_processes, 0); assert.equal(result.runtime_admitted, false);
    inspect(run.dir, db => { assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 1); assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1); });
  }
});
test('同一Job中的后代也不能冒充已准入核心连接控制管道', options, async t => {
  const run = await raw(t, 'peer'); assert.equal((await run.closed)[0], 1);
  assert.equal(run.status.frames.at(-1).control_failed, true);
  for (const frame of run.output.frames) if (frame.pid) assert.throws(() => process.kill(frame.pid, 0), {code: 'ESRCH'});
});

function syntheticBinding() {
  const digest = 'sha256:' + '1'.repeat(64), domain = {clock_domain_id: 'clock_' + '1'.repeat(64), descriptor_digest: digest};
  const receipt = {receipt_id: 'receipt', bootstrap_id: 'bootstrap', launch_id: 'launch', launch_intent_digest: digest, member_id: 'member', member_boot_id: 'boot',
    role: 'core', artifact_manifest_ref: {manifest_id: 'artifact', revision: '1', digest}, channel_binding_id: 'bootstrap-channel', domain_ref: domain,
    containment_ref: {group_id: 'group', generation: 'generation', backend: 'windows_job'}, os_observation_ref: 'observation', admitted_tick_ns: '1', gate_state: 'closed'};
  return {binding: {descriptor: {supervisor_instance_id: 'supervisor'}, receipt}, policy: {service_id: 'service', database_instance_id: 'database'}};
}
test('核心消费者拒绝错误响应绑定，断线及迟到回执不能恢复已关闭来源', options, async t => {
  // 这里仅用合成服务端验证消费者；原生对端PID检查由上述真实宿主用例覆盖。
  for (const mode of ['reply', 'scope', 'sequence', 'receipt', 'disconnect', 'late']) {
    const channelId = crypto.randomBytes(16).toString('hex'), pipe = '\\\\.\\pipe\\LeafSeamer.Control.' + channelId;
    const fixture = syntheticBinding(); let peer = null, count = 0; const timers = [];
    const server = net.createServer(socket => {
      peer = socket; let buffer = ''; socket.on('error', () => {});
      socket.on('data', chunk => {
        buffer += chunk; if (!buffer.endsWith('\n')) return;
        const request = JSON.parse(buffer); buffer = ''; count++;
        const receipt = {...fixture.binding.receipt};
        const response = {...request, type: 'LAUNCH_RESULT', message_id: 'response-' + count, reply_to: request.message_id,
          payload: {key: request.payload, record: {key: request.payload, supervisor_instance_id: 'supervisor', state: 'admitted_closed', creation_attempted: true,
            admission_receipt: receipt, retirement_evidence: null, gate_state: 'closed'}}};
        if (count > 1) {
          if (mode === 'reply') response.reply_to = 'other';
          if (mode === 'scope') response.scope = {...response.scope, service_id: 'other'};
          if (mode === 'sequence') response.sequence = '1';
          if (mode === 'receipt') receipt.member_boot_id = 'other';
          if (mode === 'disconnect') { socket.destroy(); return; }
          if (mode === 'late') { timers.push(setTimeout(() => { if (!socket.destroyed) socket.write(canonicalize(response) + '\n'); }, 2300)); return; }
        }
        socket.write(canonicalize(response) + '\n');
      });
    });
    await new Promise(resolve => server.listen(pipe, resolve));
    let source;
    try {
      source = await connectCoreSupervisor({pipe, channelId, ...fixture}); assert.equal(source.current().payload.record.gate_state, 'closed');
      await new Promise(resolve => source.onLost(resolve)); assert.throws(() => source.current());
      assert.equal(count, 2); await delay(20); assert.throws(() => source.assertCurrent());
    } finally { source?.close(); peer?.destroy(); timers.forEach(clearTimeout); await new Promise(resolve => server.close(resolve)); }
  }
});
