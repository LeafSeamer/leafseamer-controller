import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import canonicalize from 'canonicalize';
import {openNativeClock} from '../dist/native-clock.mjs';
import {bootstrapVersion} from '../dist/sdk/bootstrap.mjs';

const options = {skip: process.platform !== 'win32', timeout: 30000};
const hash = value => 'sha256:' + crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const digest = 'sha256:' + '1'.repeat(64);
const ref = kind => ({kind, authority_service_id: 'service', database_instance_id: 'database', object_id: kind, revision: '1', digest});
function configuration() {
  const body = {descriptor_version: 'clock-domain/1', domain_kind: 'supervised_runtime', authority_service_id: 'service',
    runtime_generation: 'generation', supervisor_instance_id: 'supervisor', clock_backend_id: 'windows_interrupt_precise',
    clock_backend_revision: '1', tick_unit: 'ns', suspend_accounting: 'included', namespace_identity: 'windows-global',
    os_boot_identity: {status: 'unavailable'}, platform_profile_id: 'platform_profile', platform_profile_revision: '1'};
  const descriptor_digest = hash(body);
  return {identity: {service_id: 'service', database_instance_id: 'database'}, timeoutMs: 5000,
    descriptor: {...body, descriptor_digest, clock_domain_id: 'clock_' + descriptor_digest.slice(7)},
    intent: {launch_id: 'worker', service_id: 'service', supervisor_instance_id: 'supervisor', runtime_generation: 'generation',
      member_id: 'member', role: 'worker', artifact_manifest_ref: {manifest_id: 'bundle', revision: '1', digest},
      containment_ref: {group_id: 'worker-group', generation: 'generation', backend: 'windows_job'},
      object_scope: {kind: 'devices', device_ids: ['device.a', 'device.b']}, policy_revision: '1',
      extension_binding: {installation_ref: ref('installation'), approval_ref: ref('approval'), review_ref: ref('review'),
        role_resolution_ref: ref('role_resolution'), configuration_ref: ref('configuration'), intake_ref: ref('intake'),
        platform_profile_ref: ref('platform_profile'), host_installation_id: 'host', host_trust_epoch: '1', manifest_digest: digest,
        artifact_set_digest: digest, entry_id: 'simulator', permissions_digest: digest}}};
}
function collect(stream) {
  const frames = []; let pending = '';
  stream.on('data', chunk => {
    pending += chunk;
    while (pending.includes('\n')) { const end = pending.indexOf('\n'); frames.push(JSON.parse(pending.slice(0, end))); pending = pending.slice(end + 1); }
  });
  return frames;
}
async function until(fn) {
  const deadline = performance.now() + 10000;
  while (!fn()) { assert(performance.now() < deadline, '等待worker结果超时'); await delay(10); }
  return fn();
}
async function start(t, change = () => {}) {
  const config = configuration(); change(config);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-worker-bootstrap-')), filename = path.join(root, 'config.json');
  fs.writeFileSync(filename, canonicalize(config));
  const child = spawn(process.execPath, ['--disallow-code-generation-from-strings', fileURLToPath(new URL('./fixtures/device-worker-bootstrap.mjs', import.meta.url)), filename],
    {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
  const closed = once(child, 'close'); child.stdin.on('error', () => {});
  const proofs = collect(child.stdout), events = collect(child.stderr);
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill(); await closed;
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); fs.rmSync(root, {recursive: true, force: true});
  });
  await until(() => events.some(event => event.event === 'waiting'));
  const start = openNativeClock().tick();
  const assignment = {bootstrap_version: bootstrapVersion, bootstrap_id: 'bootstrap', launch_id: config.intent.launch_id,
    launch_intent_digest: hash(config.intent), member_id: config.intent.member_id, member_boot_id: 'member-boot', role: 'worker',
    artifact_manifest_ref: config.intent.artifact_manifest_ref, channel_binding_id: 'channel', challenge_id: 'challenge',
    clock_domain_descriptor: config.descriptor, challenge_nonce: crypto.randomBytes(32).toString('base64url'),
    secret: crypto.randomBytes(32).toString('base64url'), issued_tick_ns: String(start), expires_tick_ns: String(start + BigInt(config.timeoutMs) * 1000000n)};
  const send = (type, payload) => child.stdin.write(canonicalize({version: bootstrapVersion, type, payload}) + '\n');
  const receipt = () => {
    const {bootstrap_version, challenge_id, clock_domain_descriptor, secret, challenge_nonce, issued_tick_ns, expires_tick_ns, ...common} = assignment;
    return {...common, receipt_id: 'receipt', os_observation_ref: 'observation', containment_ref: config.intent.containment_ref, gate_state: 'closed',
      domain_ref: {clock_domain_id: config.descriptor.clock_domain_id, descriptor_digest: config.descriptor.descriptor_digest},
      admitted_tick_ns: String(openNativeClock().tick())};
  };
  return {config, assignment, child, closed, proofs, events, send, receipt};
}

test('真实worker管道挑战绑定完整意图，使用原生tick并返回深冻结closed原件且不返回秘密', options, async t => {
  const run = await start(t, config => { config.mutate = true; });
  run.send('ASSIGNMENT', run.assignment);
  const proof = await until(() => run.proofs[0]);
  assert.equal(proof.type, 'PROOF'); assert.equal(proof.payload.role, 'worker');
  const {secret, clock_domain_descriptor, ...projection} = run.assignment;
  Object.assign(projection, {clock_domain_id: clock_domain_descriptor.clock_domain_id, descriptor_digest: clock_domain_descriptor.descriptor_digest});
  const expected = crypto.createHmac('sha256', Buffer.from(secret, 'base64url')).update('leafseamer-bootstrap-proof/v1\0').update(canonicalize(projection)).digest('base64url');
  assert.equal(proof.payload.proof, expected);
  const receipt = run.receipt(); run.send('ADMISSION', receipt);
  assert.equal((await run.closed)[0], 0, JSON.stringify(run.events));
  const result = run.events.find(event => event.event === 'closed'); assert(result); assert.equal(result.frozen, true);
  assert.deepEqual(result.result, {intent: run.config.intent, descriptor: run.config.descriptor, receipt, gate_state: 'closed'});
  assert(!JSON.stringify(result).includes(secret)); assert(!JSON.stringify(result).includes(run.assignment.challenge_nonce));
  assert.equal(run.proofs.length, 1);
});

test('错意图、域、profile、角色和过期Assignment在发proof前拒绝', options, async t => {
  const cases = [
    [run => { run.assignment.launch_intent_digest = digest; }, 'bootstrap_intent_binding'],
    [run => { run.assignment.role = 'core'; }, 'bootstrap_intent_binding'],
    [run => { run.assignment.clock_domain_descriptor = {...run.config.descriptor, runtime_generation: 'other'}; }, 'bootstrap_descriptor_binding'],
    [run => { run.assignment.expires_tick_ns = '5000000001'; run.assignment.issued_tick_ns = '1'; }, 'bootstrap_expired']
  ];
  for (const [change, code] of cases) {
    const run = await start(t); change(run); run.send('ASSIGNMENT', run.assignment);
    assert.equal((await run.closed)[0], 1); assert.deepEqual(run.proofs, []);
    assert.equal(run.events.at(-1).code, code);
  }
  const run = await start(t, config => { config.intent.extension_binding.platform_profile_ref.object_id = 'different-profile'; });
  run.send('ASSIGNMENT', run.assignment); assert.equal((await run.closed)[0], 1);
  assert.equal(run.events.at(-1).code, 'bootstrap_profile'); assert.deepEqual(run.proofs, []);
});

test('worker拒绝错组、错成员boot、错端点、未来准入tick及重复帧', options, async t => {
  for (const [change, code] of [
    [value => { value.containment_ref = {...value.containment_ref, group_id: 'other'}; }, 'bootstrap_receipt_binding'],
    [value => { value.member_boot_id = 'other'; }, 'bootstrap_receipt_binding'],
    [value => { value.channel_binding_id = 'other'; }, 'bootstrap_receipt_binding'],
    [value => { value.admitted_tick_ns = String(openNativeClock().tick() + 4000000000n); }, 'bootstrap_receipt_expired']
  ]) {
    const run = await start(t); run.send('ASSIGNMENT', run.assignment); await until(() => run.proofs[0]);
    const receipt = run.receipt(); change(receipt); run.send('ADMISSION', receipt);
    assert.equal((await run.closed)[0], 1); assert.equal(run.events.at(-1).code, code);
  }
  const run = await start(t); run.send('ASSIGNMENT', run.assignment); await until(() => run.proofs[0]);
  const frame = canonicalize({version: bootstrapVersion, type: 'ADMISSION', payload: run.receipt()}) + '\n';
  run.child.stdin.write(frame + frame); assert.equal((await run.closed)[0], 1);
  assert.equal(run.events.at(-1).code, 'bootstrap_frame');
});

test('worker在等待ADMISSION期间失联不会返回closed准入', options, async t => {
  const run = await start(t); run.send('ASSIGNMENT', run.assignment); await until(() => run.proofs[0]); run.child.stdin.end();
  assert.equal((await run.closed)[0], 1); assert.equal(run.events.at(-1).code, 'bootstrap_channel_closed');
  assert(!run.events.some(event => event.event === 'closed'));
});

test('发proof不延长Assignment的原生绝对截止，迟到ADMISSION不能采用', options, async t => {
  const run = await start(t), now = openNativeClock().tick();
  run.assignment.issued_tick_ns = String(now - 4000000000n);
  run.assignment.expires_tick_ns = String(now + 1000000000n);
  run.send('ASSIGNMENT', run.assignment); await until(() => run.proofs[0]);
  const receipt = run.receipt(); await delay(1200); run.send('ADMISSION', receipt);
  assert.equal((await run.closed)[0], 1); assert.equal(run.events.at(-1).code, 'bootstrap_expired');
  assert(!run.events.some(event => event.event === 'closed'));
});
