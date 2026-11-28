import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import crypto from 'node:crypto';
import https from 'node:https';
import net from 'node:net';
import canonicalize from 'canonicalize';
import {setTimeout as delay} from 'node:timers/promises';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {verifyCoreAdmission} from '../dist/core-bootstrap.mjs';
import {openNativeClock} from '../dist/native-clock.mjs';
import {canonical, digest, ref, seal} from '../dist/auth-clock-value.mjs';
import {fixture as clockFixture} from './auth-clock-fixture.mjs';
import {peerCertificates} from './fixtures/peer-certificates.mjs';
import {startProcessHost, initializeProcessHost, upgradeProcessHost, upgradeTimeProviderJournal,
  installedCoreDigest, installedTimeProviderDigest, readProcessRecoveryRetirement, fenceProcessRecoveryStartup} from '../dist/process-host.mjs';

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
function timeProviderPolicyFor(bootstrapPolicy) {
  return {...bootstrapPolicy, format: 'leafseamer-time-provider-bootstrap-policy/1',
    artifact_manifest_ref: {manifest_id: 'reference-time-integration', revision: '1', digest: installedTimeProviderDigest()}};
}

test('受信配对配置在实际监督核心内核验时钟域，开启 HTTPS 和配对监听', {...options, timeout: 90000}, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-controller-profile-'));
  const children = new Map();
  t.after(async () => {
    for (const [child, exited] of children) {
      if (child.exitCode === null && child.signalCode === null) child.kill();
      await exited;
    }
    assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir()));
    fs.rmSync(dir, {recursive: true, force: true, maxRetries: 5, retryDelay: 100});
  });
  const identity = initializeStorage(dir);
  await migrateStorage(dir, 93);
  const store = openStorage(dir);
  const login = {login: 'profile.test', password: 'Synthetic-profile-password-123'};
  let issuer;
  try {
    const enrollment = store.enrollment.begin();
    await store.enrollment.complete({token_id: enrollment.token_id, secret: enrollment.secret, ...login, mode: 'standalone'});
    issuer = store.enrollment.summary();
  } finally { store.close(); }
  await initializeProcessHost(dir);
  const bootstrap = policyFor(identity), source = openNativeClock();
  const {ca, leaves: [site, local, peer]} = peerCertificates(), caBytes = new crypto.X509Certificate(ca).raw;
  const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
  const evidenceFile = path.join(dir, 'clock-evidence.json');
  const issued = clockFixture({service_id: identity.service_id, service_boot_id: crypto.randomUUID()}, {source}, {
    sampleWindowPolicy: 'authentication-clock-sample/2'
  }).evidence;
  const ports = [];
  try {
    for (let i = 0; i < 3; i++) {
      const server = net.createServer();
      await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
      ports.push(server);
    }
  } catch (error) { for (const server of ports) server.close(); throw error; }
  const [sitePort, localPort, peerPort] = ports.map(server => server.address().port);
  await Promise.all(ports.map(server => new Promise(resolve => server.close(resolve))));
  const file = (name, bytes) => {const output = path.join(dir, name); fs.writeFileSync(output, bytes); return output;};
  const origin = `https://127.0.0.1:${sitePort}`;
  const profile = file('pairing.json', canonical({format: 'leafseamer.controller-pairing-profile/1', bootstrap,
    https: {origin, certificate_file: file('site.pem', site.cert), private_key_file: file('site-key.pem', site.key)},
    local: {credential_id: crypto.randomUUID(), host: '127.0.0.1', port: localPort,
      certificate_file: file('local.pem', local.cert), private_key_file: file('local-key.pem', local.key), ca_files: [file('ca.pem', ca)]},
    seamer: {identity: {service_id: crypto.randomUUID(), database_instance_id: crypto.randomUUID(), service_kind: 'seamer',
      issuer_id: issuer.issuer_id, issuer_epoch: issuer.issuer_epoch, credential_id: crypto.randomUUID()},
      origin: `https://127.0.0.1:${peerPort}`, server_name: '127.0.0.1', certificate_file: file('peer.pem', peer.cert),
      trust_bundle_digest: digest(['sha256:' + crypto.createHash('sha256').update(caBytes).digest('hex')])},
    clock: {policy_digest: issued.policy.digest, evidence_file: evidenceFile,
      public_key_file: file('clock.pem', publicKey.export({type: 'spki', format: 'pem'}))}}));
  const cli = fileURLToPath(new URL('../dist/cli.mjs', import.meta.url));
  async function boot({wrongDomain = false} = {}) {
    const child = spawn(process.execPath, ['--disallow-code-generation-from-strings', cli, 'supervise',
      '--data-dir', dir, '--port', String(sitePort), '--pairing-profile', profile], {stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true});
    let output = '', errors = '';
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { errors += chunk; });
    const exited = once(child, 'close');
    const frames = bytes => bytes.split('\n').slice(0, -1).map(line => JSON.parse(line));
    children.set(child, exited);
    const challenge = await until(() => frames(errors).find(frame => frame.event === 'authentication_clock_challenge'));
    assert.equal(challenge.database_instance_id, identity.database_instance_id);
    assert.equal(challenge.native_binary_digest, source.artifactDigest);
    const expiry = String(BigInt(challenge.tick_ns) + 90000000000n);
    const {digest: _oldRuntime, ...runtimeBody} = issued.runtime, {digest: _oldHealth, ...healthBody} = issued.health;
    const runtime = seal({...runtimeBody, id: crypto.randomUUID(), service_boot_id: challenge.service_boot_id,
      clock_domain_id: wrongDomain ? crypto.randomUUID() : challenge.clock_domain_id, descriptor_digest: challenge.descriptor_digest,
      continuity: challenge.continuity, valid_before_tick_ns: expiry});
    const health = seal({...healthBody, id: crypto.randomUUID(), service_boot_id: challenge.service_boot_id,
      clock_domain_id: runtime.clock_domain_id, runtime_ref: ref(runtime), valid_before_tick_ns: expiry});
    const format = 'leafseamer.authentication-clock-evidence/1', evidence = {policy: issued.policy, runtime, health};
    const signature = crypto.sign(null, Buffer.from(format + '\0' + canonical(evidence)), privateKey).toString('base64url');
    fs.renameSync(file('clock-next.json', canonical({format, evidence, signature})), evidenceFile);
    return {child, exited, output: () => frames(output), errors: () => frames(errors)};
  }
  const rejected = await boot({wrongDomain: true});
  assert.notEqual((await rejected.exited)[0], 0);
  assert.ok(rejected.errors().some(frame => frame.event === 'authentication_clock_rejected' && frame.reason === 'pairing_clock_domain'),
    JSON.stringify(rejected.errors()));
  assert.ok(!rejected.errors().some(frame => frame.event === 'listening'));
  assert.ok(rejected.output().some(frame => frame.event === 'process_group_empty' && frame.active_processes === 0));
  const active = await boot(), listening = await until(() => active.errors().find(frame => frame.event === 'listening'));
  assert.equal(listening.pairing_origin, `https://127.0.0.1:${localPort}`);
  assert.ok(active.output().some(frame => frame.event === 'process_contained' && frame.bootstrap_authenticated));
  const health = await new Promise((resolve, reject) => {
    https.get(origin + '/health/ready', {ca}, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({status: res.statusCode, body: JSON.parse(body)}));
    }).on('error', reject);
  });
  assert.deepEqual(health, {status: 503, body: {ready: false, reason: 'business_incomplete'}});
  assert.ok(!/private_key|challenge_nonce|"proof"/.test(JSON.stringify(active.errors())));
  active.child.kill();
  await active.exited;
  await until(() => {
    try { const ready = openStorage(dir); ready.close(); return true; }
    catch { return false; }
  });
});

test('监督日志显式增加时间提供者记录并保留原库身份', options, async t => {
  const dir = temporary(t);
  await initializeProcessHost(dir);
  const original = inspect(dir, 'supervisor-journal.db', db => row(db, 'SELECT * FROM host_meta'));
  assert.equal((await upgradeTimeProviderJournal(dir)).schema_revision, '6');
  assert.equal((await upgradeTimeProviderJournal(dir)).changed, false);
  const backups = fs.readdirSync(dir).filter(name => name.startsWith('supervisor-before-v6-'));
  assert.equal(backups.length, 1);
  assert.equal(inspect(dir, backups[0], db => db.pragma('user_version', {simple: true})), 5);
  inspect(dir, 'supervisor-journal.db', db => {
    assert.equal(db.pragma('user_version', {simple: true}), 6);
    assert.deepEqual(row(db, 'SELECT * FROM host_meta'), original);
    assert.deepEqual(db.pragma('foreign_key_check'), []);
    assert.equal(db.prepare('SELECT count(*) FROM time_provider_attempt').pluck().get(), 0);
  });
});

const installedProvider = fs.existsSync(new URL('../dist/runtime/reference-time-provider.exe', import.meta.url));
test('Windows 监督器在共享时钟域创建、准入并清理固定时间提供者', {
  ...options, timeout:60000, skip: options.skip || !installedProvider,
}, async t => {
  const dir = temporary(t), identity = initializeStorage(dir);
  await migrateStorage(dir,80);
  const previous=inspect(dir,'controller.sqlite',db=>db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all());
  await migrateStorage(dir,81);
  inspect(dir,'controller.sqlite',db=>{
    assert.deepEqual(db.prepare("SELECT * FROM schema_migration WHERE to_revision<>'81' ORDER BY CAST(to_revision AS INTEGER)").raw().all(),previous);
    assert.equal(row(db,'SELECT * FROM service_state').service_id,identity.service_id);
    assert.equal(row(db,'SELECT * FROM service_state').database_instance_id,identity.database_instance_id);
    assert.deepEqual(db.pragma('foreign_key_check'),[]);
  });
  await initializeProcessHost(dir);
  const bootstrapPolicy = policyFor(identity);
  const timeProviderPolicy = timeProviderPolicyFor(bootstrapPolicy);
  await assert.rejects(startProcessHost({dataDir: dir, bootstrapPolicy, timeProviderPolicy}), {code: 'time_provider_journal_required'});
  await upgradeTimeProviderJournal(dir);
  await assert.rejects(startProcessHost({dataDir: dir, bootstrapPolicy,
    timeProviderPolicy: {...timeProviderPolicy, database_instance_id: 'another-database'}}), {code: 'time_provider_scope'});
  await assert.rejects(startProcessHost({dataDir: dir, bootstrapPolicy,
    timeProviderPolicy: {...timeProviderPolicy, artifact_manifest_ref: {...timeProviderPolicy.artifact_manifest_ref, digest: 'sha256:' + '0'.repeat(64)}}}),
  {code: 'time_provider_artifact'});
  let output = '';
  const app = await startProcessHost({dataDir: dir, bootstrapPolicy, timeProviderPolicy, onCoreOutput: chunk => { output += chunk; }})
    .catch(error => { throw new Error(output || error.code, {cause: error}); });
  t.after(() => app.close());
  assert.notEqual(app.containment.time_provider_pid, app.containment.core_pid);
  const listening = await until(() => output.split('\n').filter(Boolean).map(line => JSON.parse(line)).find(frame => frame.event === 'listening'));
  assert.equal((await fetch(`http://127.0.0.1:${listening.port}/health/ready`)).status, 503);
  const result = await app.close();
  assert.equal(result.exitCode, 0);
  assert.equal(result.time_provider_exit_code, 0);
  assert.equal(result.forced, false);
  assert.equal(result.active_processes, 0);
  const native=inspect(dir, 'supervisor-journal.db', db => {
    const attempt = row(db, 'SELECT * FROM time_provider_attempt');
    const observation = row(db, 'SELECT * FROM time_provider_observation');
    const core = JSON.parse(row(db, 'SELECT * FROM core_admission').receipt_jcs);
    const receipt = JSON.parse(row(db, 'SELECT * FROM time_provider_admission').receipt_jcs);
    const intent = JSON.parse(attempt.intent_jcs);
    assert.equal(attempt.core_attempt_id, app.containment.containment_id);
    assert.equal(observation.provider_pid, app.containment.time_provider_pid);
    assert.equal(intent.role, 'time_provider');
    assert.deepEqual(intent.device_ids, []);
    assert.deepEqual(receipt.artifact_manifest_ref, timeProviderPolicy.artifact_manifest_ref);
    assert.deepEqual(receipt.domain_ref, core.domain_ref);
    assert.notEqual(receipt.containment_ref.group_id, core.containment_ref.group_id);
    assert.equal(receipt.gate_state, 'closed');
    assert(BigInt(receipt.admitted_tick_ns) >= BigInt(observation.observed_tick_ns));
    assert.deepEqual(row(db, 'SELECT * FROM time_provider_exit'), {launch_id: intent.launch_id, exit_code: 0, active_processes: 0, forced: 0});
    assert.throws(() => db.prepare('DELETE FROM time_provider_admission').run(), /immutable/);
    assert.deepEqual(db.pragma('foreign_key_check'), []);
    return {intent,receipt,observation,core};
  });
  const stored=inspect(dir,'controller.sqlite',db=>{
    const value=row(db,'SELECT * FROM time_provider_runtime_binding'),body=JSON.parse(value.body_jcs);
    assert.equal(value.service_boot_id,listening.service_boot_id);
    assert.equal(body.core_receipt_id,native.core.receipt_id);
    assert.deepEqual(body.launch_intent,native.intent);
    assert.deepEqual(body.admission_receipt,native.receipt);
    assert.deepEqual(body.process_observation,{observation_id:native.observation.launch_id,provider_pid:native.observation.provider_pid,
      creation_time_filetime:native.observation.creation_time,image_id:native.observation.image_id,observed_tick_ns:native.observation.observed_tick_ns});
    assert.equal(body.clock_domain_descriptor.descriptor_digest,native.core.domain_ref.descriptor_digest);
    assert.throws(()=>db.prepare('DELETE FROM time_provider_runtime_binding').run(),/immutable/);
    return value;
  });
  const reopened=openStorage(dir),newBoot=reopened.serviceBootId;
  reopened.close();
  assert.notEqual(newBoot,stored.service_boot_id);
  inspect(dir,'controller.sqlite',db=>{
    assert.deepEqual(row(db,'SELECT * FROM time_provider_runtime_binding'),stored);
    assert.equal(db.prepare('SELECT count(*) FROM time_provider_runtime_binding WHERE service_boot_id=?').pluck().get(newBoot),0);
  });
  const runtimeGeneration=native.core.containment_ref.generation;
  const fence=await fenceProcessRecoveryStartup({dataDir:dir,runtimeGeneration,serviceId:identity.service_id,
    databaseInstanceId:identity.database_instance_id,planDigest:digest('provider recovery plan'),retirementId:crypto.randomUUID()});
  assert.equal(fence.active_processes,0);
  inspect(dir,'supervisor-journal.db',db=>{
    assert.equal(db.pragma('user_version',{simple:true}),7);
    assert.deepEqual(row(db,'SELECT * FROM time_provider_observation'),native.observation);
    assert.deepEqual(JSON.parse(row(db,'SELECT * FROM time_provider_admission').receipt_jcs),native.receipt);
  });
  assert(!/secret|challenge_nonce|"proof"/.test(output));
});

test('时间提供者意外退出后原监督连接和核心服务一并关闭', {
  ...options, timeout:60000, skip: options.skip || !installedProvider,
}, async t => {
  const dir = temporary(t), identity = initializeStorage(dir);
  await migrateStorage(dir,81);
  await initializeProcessHost(dir);
  await upgradeTimeProviderJournal(dir);
  const bootstrapPolicy = policyFor(identity);
  const timeProviderPolicy = timeProviderPolicyFor(bootstrapPolicy);
  let output = '';
  const app = await startProcessHost({dataDir: dir, bootstrapPolicy, timeProviderPolicy, onCoreOutput: chunk => { output += chunk; }});
  t.after(() => app.close());
  const listening = await until(() => output.split('\n').filter(Boolean).map(line => JSON.parse(line)).find(frame => frame.event === 'listening'));
  process.kill(app.containment.time_provider_pid);
  const result = await app.exited;
  assert.equal(result.control_failed, true);
  assert.equal(result.active_processes, 0);
  assert.notEqual(result.exitCode, 0);
  assert.notEqual(result.time_provider_exit_code, 0);
  await assert.rejects(fetch(`http://127.0.0.1:${listening.port}/health/live`));
  inspect(dir, 'supervisor-journal.db', db => {
    assert.equal(db.prepare('SELECT active_processes FROM time_provider_exit').pluck().get(), 0);
    assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM time_provider_admission').pluck().get(), 1);
  });
});

test('时间提供者业务绑定漏写时核心绑定同事务回滚', {
  ...options, timeout:60000, skip: options.skip || !installedProvider,
}, async t => {
  const dir=temporary(t),identity=initializeStorage(dir);
  await migrateStorage(dir,81);
  await initializeProcessHost(dir);
  await upgradeTimeProviderJournal(dir);
  inspect(dir,'controller.sqlite',db=>db.exec(
    "CREATE TRIGGER omit_time_binding BEFORE INSERT ON time_provider_runtime_binding BEGIN SELECT RAISE(IGNORE); END"));
  const bootstrapPolicy=policyFor(identity),timeProviderPolicy=timeProviderPolicyFor(bootstrapPolicy);
  let output='';
  const app=await startProcessHost({dataDir:dir,bootstrapPolicy,timeProviderPolicy,onCoreOutput:chunk=>{output+=chunk;}});
  const closed=await app.exited;
  assert.notEqual(closed.exitCode,0);
  assert(!output.includes('"event":"listening"'));
  inspect(dir,'supervisor-journal.db',db=>assert.equal(db.prepare('SELECT count(*) FROM time_provider_admission').pluck().get(),1));
  inspect(dir,'controller.sqlite',db=>{
    assert.equal(db.prepare('SELECT count(*) FROM core_runtime_binding').pluck().get(),0);
    assert.equal(db.prepare('SELECT count(*) FROM time_provider_runtime_binding').pluck().get(),0);
  });
});

test('真实CNG挑战、Node证明、双库回执与监听形成闭环，设备闸门保持关闭', options, async t => {
  const dir = temporary(t), identity = initializeStorage(dir);
  const migration = await migrateStorage(dir, 48); assert.equal(migration.schema_revision, '48');
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

test('按当前运行代查回原生 Job 退役证据，并拒绝活跃或过时的记录',{...options,timeout:60000},async t=>{
  const dir=temporary(t),identity=initializeStorage(dir);
  await migrateStorage(dir,48);
  await initializeProcessHost(dir);
  const lookup={dataDir:dir,serviceId:identity.service_id,databaseInstanceId:identity.database_instance_id};
  const recovery={planDigest:digest('approved recovery plan'),retirementId:crypto.randomUUID()};
  const journalPath=path.join(dir,'supervisor-journal.db');
  await assert.rejects(readProcessRecoveryRetirement({...lookup,runtimeGeneration:'f'.repeat(32)}),
    {code:'process_retirement_unproven'});
  async function launch(){
    let output='';
    const app=await startProcessHost({dataDir:dir,bootstrapPolicy:policyFor(identity),onCoreOutput:chunk=>{output+=chunk;}});
    t.after(()=>app.close());
    await until(()=>output.split('\n').filter(Boolean).map(line=>JSON.parse(line)).find(frame=>frame.event==='listening'));
    return app;
  }
  function runtime(){
    return inspect(dir,'supervisor-journal.db',db=>db.prepare(
      "SELECT json_extract(descriptor_jcs,'$.runtime_generation') AS id FROM core_bootstrap ORDER BY rowid DESC LIMIT 1").pluck().get());
  }
  const first=await launch();
  await assert.rejects(readProcessRecoveryRetirement({...lookup,runtimeGeneration:'f'.repeat(32)}),{code:'instance_in_use'});
  await assert.rejects(fenceProcessRecoveryStartup({...lookup,...recovery,runtimeGeneration:'f'.repeat(32)}),{code:'instance_in_use'});
  assert.equal((await first.close()).exitCode,0);
  const retiredRequest={...lookup,runtimeGeneration:runtime()};
  const original=fs.readFileSync(journalPath);
  const retired=await readProcessRecoveryRetirement(retiredRequest);
  assert.equal(retired.format,'leafseamer-windows-process-retirement/1');
  assert.equal(retired.containment_id,first.containment.containment_id);
  assert.equal(retired.active_processes,0);
  assert.match(retired.retirement_digest,/^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(await readProcessRecoveryRetirement(retiredRequest),retired);
  assert.deepEqual(fs.readFileSync(journalPath),original);
  await assert.rejects(readProcessRecoveryRetirement({...retiredRequest,databaseInstanceId:crypto.randomUUID()}),
    {code:'process_retirement_unproven'});
  const next=await launch();
  assert.equal((await next.close()).exitCode,0);
  await assert.rejects(readProcessRecoveryRetirement(retiredRequest),{code:'process_retirement_unproven'});
  await assert.rejects(fenceProcessRecoveryStartup({...retiredRequest,...recovery}),{code:'process_retirement_unproven'});
  const request={...lookup,...recovery,runtimeGeneration:runtime()};
  const prior=await readProcessRecoveryRetirement(request);
  assert.equal(prior.containment_id,next.containment.containment_id);
  await assert.rejects(fenceProcessRecoveryStartup({...request,databaseInstanceId:crypto.randomUUID()}),{code:'process_retirement_unproven'});

  // 固定宿主直接收到错误操作标识时，INSERT 约束必须和版本变动一起回滚。
  const executable=fileURLToPath(new URL('../dist/native/leafseamer_process_host.exe',import.meta.url));
  const invalid=spawn(executable,['--fence-recovery-startup',dir,request.runtimeGeneration,request.serviceId,
    request.databaseInstanceId,request.planDigest,'invalid'],{windowsHide:true,signal:AbortSignal.timeout(10000)});
  invalid.stdin.end();invalid.stdout.resume();invalid.stderr.resume();
  assert.deepEqual(await once(invalid,'close'),[1,null]);
  inspect(dir,'supervisor-journal.db',db=>{
    assert.equal(db.pragma('user_version',{simple:true}),5);
    assert.equal(db.prepare("SELECT 1 FROM sqlite_schema WHERE name='recovery_startup_fence'").get(),undefined);
  });
  assert.deepEqual(await readProcessRecoveryRetirement(request),prior);

  const storageOriginal=fs.readFileSync(path.join(dir,'controller.sqlite'));
  const fenced=await fenceProcessRecoveryStartup(request);
  assert.deepEqual(fenced,{...prior,startup_fence:{plan_digest:recovery.planDigest,retirement_id:recovery.retirementId}});
  assert.deepEqual(await fenceProcessRecoveryStartup(request),fenced);
  await assert.rejects(fenceProcessRecoveryStartup({...request,planDigest:digest('other plan')}),{code:'process_recovery_fence_conflict'});
  await assert.rejects(fenceProcessRecoveryStartup({...request,retirementId:crypto.randomUUID()}),{code:'process_recovery_fence_conflict'});
  await assert.rejects(startProcessHost({dataDir:dir,bootstrapPolicy:policyFor(identity)}),{code:'process_recovery_startup_fenced'});
  await assert.rejects(startProcessHost({dataDir:dir}),{code:'process_recovery_startup_fenced'});
  await assert.rejects(upgradeProcessHost(dir),{code:'process_recovery_startup_fenced'});
  await assert.rejects(upgradeTimeProviderJournal(dir),{code:'process_recovery_startup_fenced'});
  assert.deepEqual(await readProcessRecoveryRetirement(request),fenced);
  assert.deepEqual(fs.readFileSync(path.join(dir,'controller.sqlite')),storageOriginal);
  inspect(dir,'supervisor-journal.db',db=>{
    assert.equal(db.pragma('user_version',{simple:true}),7);
    assert.equal(db.prepare('SELECT count(*) FROM core_attempt').pluck().get(),2);
    assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(),2);
    assert.throws(()=>db.prepare('DELETE FROM recovery_startup_fence').run(),/immutable/);
    assert.deepEqual(db.pragma('foreign_key_check'),[]);
  });
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

function dropWorkerCreation(db){
  db.exec('DROP TRIGGER worker_creating_evidence; DROP TRIGGER worker_observed_evidence; DROP TABLE worker_observation; DROP TABLE worker_creation');
}
test('监督日志v1必须显式备份迁移，保留历史且重复升级幂等', options, async t => {
  const dir = temporary(t); await initializeProcessHost(dir);
  inspect(dir, 'supervisor-journal.db', db => {
    dropWorkerCreation(db);
    for (const name of ['worker_retirement', 'worker_group', 'worker_state', 'worker_launch', 'launch_fence_current', 'launch_fence_item', 'launch_fence', 'core_admission', 'core_bootstrap']) db.exec('DROP TABLE ' + name);
    db.pragma('user_version = 1');
    db.prepare('INSERT INTO core_attempt VALUES(?,?,?)').run('a'.repeat(32), 'old-job', '1');
    db.prepare('INSERT INTO core_observation VALUES(?,?,?,?)').run('a'.repeat(32), 1, '1', 'synthetic-image');
    db.prepare('INSERT INTO core_exit VALUES(?,?,0,?)').run('a'.repeat(32), '0', '0');
  });
  await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_journal_migration_required');
  assert.equal((await upgradeProcessHost(dir)).changed, true);
  const backups = fs.readdirSync(dir).filter(n => n.startsWith('supervisor-before-v5-')); assert.equal(backups.length, 1);
  inspect(dir, backups[0], db => { assert.equal(db.pragma('user_version', {simple: true}), 1); assert.equal(db.prepare('SELECT attempt_id FROM core_attempt').pluck().get(), 'a'.repeat(32)); });
  assert.equal((await upgradeProcessHost(dir)).changed, false);
  inspect(dir, 'supervisor-journal.db', db => { assert.equal(db.pragma('user_version', {simple: true}), 5); assert.equal(db.prepare('SELECT attempt_id FROM core_exit').pluck().get(), 'a'.repeat(32)); });
});

test('监督日志v2显式迁移到启动快照布局，保留原准入表与备份', options, async t => {
  const dir = temporary(t); await initializeProcessHost(dir);
  inspect(dir, 'supervisor-journal.db', db => {
    dropWorkerCreation(db);
    for (const name of ['worker_retirement', 'worker_group', 'worker_state', 'worker_launch', 'launch_fence_current', 'launch_fence_item', 'launch_fence']) db.exec('DROP TABLE ' + name);
    db.pragma('user_version = 2');
  });
  await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_journal_migration_required');
  assert.equal((await upgradeProcessHost(dir)).schema_revision, '5');
  const backups = fs.readdirSync(dir).filter(n => n.startsWith('supervisor-before-v5-')); assert.equal(backups.length, 1);
  inspect(dir, backups[0], db => assert.equal(db.pragma('user_version', {simple: true}), 2));
  inspect(dir, 'supervisor-journal.db', db => {
    assert.equal(db.pragma('user_version', {simple: true}), 5);
    assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 0);
    assert.equal(db.prepare('SELECT count(*) FROM launch_fence').pluck().get(), 0);
  });
  assert.equal((await upgradeProcessHost(dir)).changed, false);
});

test('监督日志v3显式升级增加组观察及退役原件，保留备份且不隐式迁移', options, async t => {
  const dir = temporary(t); await initializeProcessHost(dir);
  inspect(dir, 'supervisor-journal.db', db => {
    dropWorkerCreation(db);
    db.exec('DROP TRIGGER worker_retired_evidence; DROP TABLE worker_retirement; DROP TABLE worker_group; DROP INDEX worker_state_retirement_key');
    db.pragma('user_version = 3');
  });
  await assert.rejects(startProcessHost({dataDir: dir}), e => e.code === 'process_journal_migration_required');
  assert.equal((await upgradeProcessHost(dir)).schema_revision, '5');
  const backups = fs.readdirSync(dir).filter(n => n.startsWith('supervisor-before-v5-')); assert.equal(backups.length, 1);
  inspect(dir, backups[0], db => assert.equal(db.pragma('user_version', {simple: true}), 3));
  inspect(dir, 'supervisor-journal.db', db => {
    assert.equal(db.pragma('user_version', {simple: true}), 5);
    assert.equal(db.prepare('SELECT count(*) FROM worker_retirement').pluck().get(), 0);
  });
  assert.equal((await upgradeProcessHost(dir)).changed, false);
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


test('监督日志v4显式升级到一次创建证据布局，保留原日志且不补造创建记录',options,async t=>{
  const dir=temporary(t);await initializeProcessHost(dir);
  inspect(dir,'supervisor-journal.db',db=>{dropWorkerCreation(db);db.pragma('user_version=4');});
  await assert.rejects(startProcessHost({dataDir:dir}),e=>e.code==='process_journal_migration_required');
  assert.equal((await upgradeProcessHost(dir)).schema_revision,'5');
  const backups=fs.readdirSync(dir).filter(n=>n.startsWith('supervisor-before-v5-'));assert.equal(backups.length,1);
  inspect(dir,backups[0],db=>assert.equal(db.pragma('user_version',{simple:true}),4));
  inspect(dir,'supervisor-journal.db',db=>{assert.equal(db.pragma('user_version',{simple:true}),5);
    for(const name of ['worker_creation','worker_observation'])assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);});
  assert.equal((await upgradeProcessHost(dir)).changed,false);
});
