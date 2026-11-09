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
async function raw(t, mode, setup) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-control-')), identity = initializeStorage(dir); await initializeProcessHost(dir);
  if (setup) inspect(dir, setup);
  const output = collect(), status = collect();
  const child = spawn(fileURLToPath(new URL('../dist/native/leafseamer_process_host.exe', import.meta.url)),
    [dir, process.execPath, fileURLToPath(new URL('./fixtures/control-core.mjs', import.meta.url)), 'contained-core-auth', '--bootstrap-policy', canonicalize(policyFor(identity)), '--mode', mode],
    {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
  const closed = once(child, 'close'); child.stdin.on('error', () => {}); child.stdout.on('data', status.write); child.stderr.on('data', output.write);
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill(); await closed;
    assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  return {dir, child, closed, status, output};
}

test('主动核心观察取得本次请求后的真实回复，并发合并不延长旧观察且关闭后拒绝',options,async t=>{
 const run=await raw(t,'core-refresh'),done=await until(()=>run.output.frames.find(f=>f.event==='core-refresh-done'));
 assert.equal(done.fresh,true);assert.equal(done.unchanged,true);
 assert.equal(done.oldError,'supervisor_core_observation');assert.equal(done.closedError,'supervisor_unavailable');
 assert.equal((await run.closed)[0],1);
 const stopped=run.status.frames.at(-1);assert.equal(stopped.event,'process_group_empty');
 assert.equal(stopped.control_failed,true);assert.equal(stopped.active_processes,0);
});

test('真实核心提交完整启动快照，原生持久ACK且拒绝历史deny复活与修订重放', options, async t => {
  const run = await raw(t, 'fence');
  const done = await until(() => run.output.frames.find(f => f.event === 'fence-done')); assert.equal(done.current, 'closed');
  const acknowledgments = run.output.frames.filter(f => f.event === 'fence');
  assert.equal(acknowledgments.length, 5, JSON.stringify(run.output.frames.filter(f => f.event === 'fence-error')));
  assert.deepEqual(run.output.frames.filter(f => f.event === 'fence-error').map(f => f.code),
    ['supervisor_stale_fence', 'supervisor_identity_conflict', 'supervisor_identity_conflict', 'supervisor_identity_conflict']);
  assert(Buffer.byteLength(canonicalize(acknowledgments[0].body)) > 65536);
  run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
  inspect(run.dir, db => {
    const rows = db.prepare('SELECT snapshot_jcs FROM launch_fence ORDER BY revision').pluck().all().map(JSON.parse);
    assert.deepEqual(rows, [acknowledgments[0].body, acknowledgments[2].body, acknowledgments[3].body]);
    assert.equal(db.prepare('SELECT revision FROM launch_fence_current').pluck().get(), '9007199254740995');
    assert.equal(db.prepare("SELECT count(*) FROM launch_fence_item WHERE disposition='deny'").pluck().get(), 256);
    assert.equal(db.prepare('SELECT count(*) FROM core_observation').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1);
    assert.throws(() => db.exec('DELETE FROM launch_fence_item'), /immutable/);
    assert.throws(() => db.exec("UPDATE launch_fence_current SET revision='9007199254740994'"), /fence_revision/);
  });
});

test('真实worker登记保存完整新意图且不创建进程，遗漏快照和撤权后不能再取得登记许可', options, async t => {
  const run = await raw(t, 'worker-register');
  const result = await until(() => run.output.frames.find(f => f.event === 'worker-result'));
  assert.equal(result.first.state, 'registered'); assert.equal(result.first.creation_attempted, false); assert.equal(result.first.admission_receipt, null);
  assert.deepEqual(result.first, result.repeated); assert.deepEqual(result.first, result.queried); assert.deepEqual(result.first, result.final);
  assert.deepEqual(result.errors, {expired: 'supervisor_expired', future: 'supervisor_expired', domain: 'supervisor_unauthorized', permissions: 'supervisor_unauthorized',
    approval: 'supervisor_unauthorized', omission: 'supervisor_invalid_binding', unsynchronized: 'supervisor_stale_fence', denied: 'supervisor_unauthorized',
    changed: 'supervisor_identity_conflict', query_conflict: 'supervisor_identity_conflict', reallow: 'supervisor_identity_conflict'});
  run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
  inspect(run.dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM worker_launch').pluck().get(), 1);
    assert.deepEqual(JSON.parse(db.prepare('SELECT intent_jcs FROM worker_launch').pluck().get()), result.intent);
    assert.deepEqual(JSON.parse(db.prepare('SELECT authorization_jcs FROM worker_launch').pluck().get()), result.grant);
    assert.equal(db.prepare('SELECT state FROM worker_state').pluck().get(), 'registered');
    assert.equal(db.prepare('SELECT count(*) FROM core_observation').pluck().get(), 1);
    assert.equal(db.prepare('SELECT revision FROM launch_fence_current').pluck().get(), '2');
    assert.throws(() => db.exec('DELETE FROM worker_launch'), /immutable/);
    assert.throws(() => db.exec("UPDATE worker_state SET state='admitted_closed',creation_attempted=1"), /worker_state_transition|worker_observation_evidence/);
  });
});

test('CREATE重新核授权及当前栅栏，未知安装凭据不能消耗创建权，拒绝后仍可查询原件', options, async t => {
  const run = await raw(t, 'worker-create');
  const result = await until(() => run.output.frames.find(f => f.event === 'worker-result'));
  const expected = {digest: 'unauthorized', missing: 'not_found', expired: 'expired', future: 'expired', domain: 'unauthorized', permissions: 'unauthorized',
    approval: 'unauthorized', installation: 'unauthorized', role: 'unauthorized', authority: 'unauthorized', revision: 'stale_fence',
    conflict: 'identity_conflict', unresolved: 'invalid_binding', repeated: 'invalid_binding', unsynchronized: 'stale_fence', denied: 'unauthorized'};
  assert.deepEqual(Object.fromEntries(Object.entries(result.errors).filter(([key]) => key.startsWith('create_'))),
    Object.fromEntries(Object.entries(expected).map(([key, value]) => ['create_' + key, 'supervisor_' + value])));
  assert.deepEqual(result.first, result.final);
  run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
  assert.equal(run.status.frames.at(-1).active_processes, 0);
  inspect(run.dir, db => {
    assert.deepEqual(db.prepare('SELECT state,creation_attempted,admission_receipt FROM worker_state').raw().get(),
      ['registered', 0, null]);
    assert.deepEqual(JSON.parse(db.prepare('SELECT authorization_jcs FROM worker_launch').pluck().get()), result.grant);
    assert.equal(db.prepare('SELECT count(*) FROM core_observation').pluck().get(), 1);
  });
});

test('已登记worker在撤权及fence失步后按实际独占Job退役，原件持久且终态不能复活', options, async t => {
  const run = await raw(t, 'worker-retire');
  const result = await until(() => run.output.frames.find(f => f.event === 'worker-result'));
  assert.equal(result.retirement.result, 'confirmed_empty'); assert.equal(result.retirement.launch_intake_closed, true);
  assert.deepEqual(result.retirement, result.repeatedRetirement);
  assert.equal(result.final.state, 'retired'); assert.equal(result.final.creation_attempted, false);
  assert.deepEqual(result.final.retirement_evidence, result.retirement);
  assert.equal(result.replacement.state, 'registered');
  assert.deepEqual(Object.fromEntries(Object.entries(result.errors).filter(([key]) => key.startsWith('retire_'))), {
    retire_conflict: 'supervisor_identity_conflict', retire_missing: 'supervisor_not_found', retire_reregister: 'supervisor_stale_fence',
    retire_reregister_synced: 'supervisor_invalid_binding',
    retire_create: 'supervisor_invalid_binding', retire_reallow: 'supervisor_invalid_binding'});
  run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
  inspect(run.dir, db => {
    const row = db.prepare('SELECT request_jcs,observation_jcs,evidence_jcs FROM worker_retirement').raw().get();
    assert.equal(JSON.parse(row[0]).reason, 'revoked');
    assert.deepEqual(JSON.parse(row[2]), result.retirement);
    const observation = JSON.parse(row[1]);
    assert.equal(observation.active_processes, 0); assert.equal(observation.total_processes, 0);
    assert.equal(observation.observation_id, result.retirement.os_observation_refs[0]);
    assert.equal(observation.observed_tick_ns, result.retirement.observed_tick_ns);
    assert.equal(observation.object_name, db.prepare('SELECT object_name FROM worker_group WHERE launch_id=?').pluck().get(result.intent.launch_id));
    const reservation = JSON.parse(db.prepare('SELECT reservation_jcs FROM worker_group WHERE launch_id=?').pluck().get(result.intent.launch_id));
    assert.equal(reservation.object_name, observation.object_name); assert.equal(reservation.group_id, result.intent.containment_ref.group_id);
    assert.equal(db.prepare("SELECT count(*) FROM worker_state WHERE state NOT IN('retired','rejected')").pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM worker_group').pluck().get(), 2);
    assert.throws(() => db.exec('DELETE FROM worker_retirement'), /immutable/);
    assert.throws(() => db.exec('DELETE FROM worker_group'), /immutable/);
    assert.throws(() => db.exec("UPDATE worker_state SET state='registered' WHERE state='retired'"), /worker_state_transition|worker_observation_evidence/);
    assert.throws(() => db.exec("UPDATE worker_state SET retirement_evidence='{}' WHERE state='retired'"), /worker_retirement_evidence|worker_state_transition/);
    // 观察原件与终态须一起提交，不能只插入一条孤立证据。
    db.exec("BEGIN; UPDATE worker_state SET state='retiring' WHERE launch_id='worker.next'");
    db.prepare('INSERT INTO worker_retirement SELECT attempt_id,?,?,?,request_jcs,observation_jcs,? FROM worker_retirement LIMIT 1')
      .run('worker.next', 'unpaired.evidence', 'unpaired.observation', '{}');
    assert.throws(() => db.exec('COMMIT'), /FOREIGN KEY/); db.exec('ROLLBACK');
  });
});

test('重算摘要也不能绕过快照范围、全量容量、排序、核心隔离和封闭字段', options, async t => {
  for (const fault of ['scope', 'order', 'duplicate', 'core', 'capacity', 'revision', 'id', 'extra', 'digest']) {
    const run = await raw(t, 'fence-bad-' + fault); assert.equal((await run.closed)[0], 1, fault);
    assert.equal(run.status.frames.at(-1).control_failed, true, fault);
    assert.equal(run.status.frames.at(-1).active_processes, 0, fault);
    inspect(run.dir, db => {
      assert.equal(db.prepare('SELECT count(*) FROM launch_fence').pluck().get(), 0, fault);
      assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1, fault);
    });
  }
});

test('监督日志DDL被额外触发器修改时在创建核心前拒绝', options, async t => {
  const run = await raw(t, 'fence-failure', db => db.exec("CREATE TRIGGER fail_fence BEFORE INSERT ON launch_fence_item BEGIN SELECT RAISE(ABORT,'synthetic_fence_write'); END"));
  // 修改正式DDL会在宿主启动核验时被拒绝；不把此结果当作已进入事务故障测试。
  assert.equal((await run.closed)[0], 1);
  assert.equal(run.output.frames.filter(f => f.event === 'fence').length, 0);
  assert.equal(run.status.frames.at(-1).code, 'process_journal_schema');
  inspect(run.dir, db => { assert.equal(db.prepare('SELECT count(*) FROM launch_fence').pluck().get(), 0); });
});
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

test('核心消费者拒绝借用其它成员、组或观察域的退役结果', options, async () => {
  const hash = value => 'sha256:' + crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
  for (const fault of ['member', 'group', 'domain']) {
    const fixture = syntheticBinding(); fixture.binding.descriptor.runtime_generation = 'generation';
    const ref = kind => ({kind, authority_service_id: 'service', database_instance_id: 'database', object_id: kind, revision: '1', digest: hash(kind)});
    const intent = {launch_id: 'worker', service_id: 'service', supervisor_instance_id: 'supervisor', runtime_generation: 'generation', member_id: 'worker.member',
      role: 'worker', artifact_manifest_ref: fixture.binding.receipt.artifact_manifest_ref, containment_ref: {group_id: 'worker.group', generation: 'generation', backend: 'windows_job'},
      object_scope: {kind: 'devices', device_ids: ['device']}, policy_revision: '1', extension_binding: {
        installation_ref: ref('installation'), approval_ref: ref('approval'), review_ref: ref('review'), role_resolution_ref: ref('role_resolution'),
        configuration_ref: ref('configuration'), intake_ref: ref('intake'), platform_profile_ref: ref('platform_profile'), host_installation_id: 'host', host_trust_epoch: '1',
        manifest_digest: hash('manifest'), artifact_set_digest: hash('artifacts'), entry_id: 'simulator', permissions_digest: hash('permissions')}};
    const channelId = crypto.randomBytes(16).toString('hex'), pipe = '\\\\.\\pipe\\LeafSeamer.Control.' + channelId;
    let peer;
    const server = net.createServer(socket => {
      peer = socket; let buffer = ''; socket.on('error', () => {});
      socket.on('data', chunk => {
        buffer += chunk; if (!buffer.endsWith('\n')) return;
        const request = JSON.parse(buffer); buffer = '';
        const response = {...request, message_id: 'response-' + request.sequence, reply_to: request.message_id};
        if (request.type === 'LAUNCH_QUERY') {
          response.type = 'LAUNCH_RESULT'; response.payload = {key: request.payload, record: {key: request.payload, supervisor_instance_id: 'supervisor',
            state: 'admitted_closed', creation_attempted: true, gate_state: 'closed', retirement_evidence: null, admission_receipt: fixture.binding.receipt}};
        } else {
          response.type = 'RETIRE_RESULT'; response.payload = {evidence_id: 'evidence', service_id: 'service', old_domain_ref: request.scope.domain_ref,
            target_scope: 'member_group', target_member_ids: [intent.member_id], containment_ref: {...intent.containment_ref}, launch_intake_closed: true,
            os_observation_refs: ['observation'], result: 'confirmed_empty', evaluator_domain_ref: request.scope.domain_ref, observed_tick_ns: '1'};
          if (fault === 'member') response.payload.target_member_ids = ['another.member'];
          if (fault === 'group') response.payload.containment_ref.group_id = 'another.group';
          if (fault === 'domain') response.payload.evaluator_domain_ref = {...request.scope.domain_ref, descriptor_digest: hash('another.domain')};
        }
        socket.write(canonicalize(response) + '\n');
      });
    });
    await new Promise(resolve => server.listen(pipe, resolve)); let source;
    try {
      source = await connectCoreSupervisor({pipe, channelId, ...fixture});
      await assert.rejects(source.retireWorker(intent, 'revoked'), e => e.code === 'supervisor_retirement_binding');
      assert.throws(() => source.assertCurrent(), e => e.code === 'supervisor_retirement_binding');
    } finally { source?.close(); peer?.destroy(); await new Promise(resolve => server.close(resolve)); }
  }
});

test('核心核快照ACK原修订和摘要，拒绝结果不冒充监督连接失效', options, async () => {
  for (const mode of ['revision', 'digest', 'reject']) {
    const channelId = crypto.randomBytes(16).toString('hex'), pipe = '\\\\.\\pipe\\LeafSeamer.Control.' + channelId;
    const fixture = syntheticBinding(); let peer;
    const server = net.createServer(socket => {
      peer = socket; let buffer = ''; socket.on('error', () => {});
      socket.on('data', chunk => {
        buffer += chunk; if (!buffer.endsWith('\n')) return;
        const request = JSON.parse(buffer); buffer = '';
        const response = {...request, message_id: 'response-' + request.sequence, reply_to: request.message_id};
        if (request.type === 'LAUNCH_QUERY') {
          response.type = 'LAUNCH_RESULT'; response.payload = {key: request.payload, record: {key: request.payload,
            supervisor_instance_id: 'supervisor', state: 'admitted_closed', creation_attempted: true,
            admission_receipt: fixture.binding.receipt, retirement_evidence: null, gate_state: 'closed'}};
        } else {
          response.type = 'FENCE_RESULT'; response.payload = {revision: request.payload.revision, snapshot_digest: request.payload.digest, journal_committed: true};
          if (mode === 'revision') response.payload.revision = '2';
          if (mode === 'digest') response.payload.snapshot_digest = 'sha256:' + '0'.repeat(64);
          if (mode === 'reject') { response.type = 'ERROR'; response.payload = {code: 'stale_fence', retry_action: 'query_only'}; }
        }
        socket.write(canonicalize(response) + '\n');
      });
    });
    await new Promise(resolve => server.listen(pipe, resolve)); let source;
    try {
      source = await connectCoreSupervisor({pipe, channelId, ...fixture});
      const body = {scope: source.scope, revision: '1', items: []};
      const snapshot = {...body, digest: 'sha256:' + crypto.createHash('sha256').update(canonicalize(body)).digest('hex')};
      await assert.rejects(source.putFence(snapshot), e => e.code === (mode === 'reject' ? 'supervisor_stale_fence' : 'supervisor_fence_binding'));
      if (mode === 'reject') { await delay(550); assert.equal(source.current().payload.record.gate_state, 'closed'); }
      else assert.throws(() => source.assertCurrent(), e => e.code === 'supervisor_fence_binding');
    } finally { source?.close(); peer?.destroy(); await new Promise(resolve => server.close(resolve)); }
  }
});
test('核心物化消费者拒绝同消息内错启动键或观察请求ID，并锁存连接失败', options, async () => {
  for(const fault of ['key','request']){
    const channelId=crypto.randomBytes(16).toString('hex'),pipe='\\\\.\\pipe\\LeafSeamer.Control.'+channelId,fixture=syntheticBinding();let peer,source;
    const server=net.createServer(socket=>{peer=socket;let buffer='';socket.on('error',()=>{});socket.on('data',chunk=>{
      buffer+=chunk;if(!buffer.endsWith('\n'))return;const request=JSON.parse(buffer);buffer='';
      const response={...request,message_id:'response-'+request.sequence,reply_to:request.message_id};
      if(request.type==='LAUNCH_QUERY'){
        response.type='LAUNCH_RESULT';response.payload={key:request.payload,record:{key:request.payload,supervisor_instance_id:'supervisor',state:'admitted_closed',
          creation_attempted:true,admission_receipt:fixture.binding.receipt,retirement_evidence:null,gate_state:'closed'}};
      }else{
        response.type='MATERIALIZATION_RESULT';response.payload={...request.payload,status:'pending',observation:null};
        if(fault==='key')response.payload.key={...request.payload.key,launch_id:'another'};else response.payload.observation_request_id='another';
      }
      socket.write(canonicalize(response)+'\n');
    });});
    await new Promise(resolve=>server.listen(pipe,resolve));
    try{
      source=await connectCoreSupervisor({pipe,channelId,...fixture});
      await assert.rejects(source.prepareWorkerMaterialization({launch_id:'worker',launch_intent_digest:'sha256:'+'1'.repeat(64)}),{code:'supervisor_materialization_binding'});
      assert.throws(()=>source.assertCurrent(),{code:'supervisor_materialization_binding'});
    }finally{source?.close();peer?.destroy();await new Promise(resolve=>server.close(resolve));}
  }
});

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
