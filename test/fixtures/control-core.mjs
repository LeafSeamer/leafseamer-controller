import net from 'node:net';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import canonicalize from 'canonicalize';
import crypto from 'node:crypto';
import {connectCoreSupervisor} from '../../dist/supervisor-control.mjs';
import {openNativeClock} from '../../dist/native-clock.mjs';
import {createCoreBootstrapChannel} from '../../dist/core-bootstrap.mjs';
import {decodeWorkerControl as decodeSupervisorControl, workerControlVersion as supervisorControlVersion} from '../../dist/sdk/worker-runtime.mjs';
const args = process.argv.slice(3), options = Object.fromEntries(Array.from({length: args.length / 2}, (_, i) => [args[i * 2], args[i * 2 + 1]]));
const bootstrap = createCoreBootstrapChannel(process.stdin, process.stdout, {timeoutMs: 10000});
const assignment = await bootstrap.assignment(), receipt = await bootstrap.proveAndReceive(assignment); bootstrap.release();
const policy = JSON.parse(options['--bootstrap-policy']), mode = options['--mode'];
process.stderr.write(JSON.stringify({event: 'bootstrapped', pid: process.pid}) + '\n');
if (mode === 'worker-register' || mode === 'worker-create' || mode === 'worker-retire') {
  const source = await connectCoreSupervisor({pipe: options['--supervisor-pipe'], channelId: options['--supervisor-channel'], policy,
    binding: {descriptor: assignment.clock_domain_descriptor, receipt}});
  const clock = openNativeClock(), hash = value => 'sha256:' + crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
  const ref = kind => ({kind, authority_service_id: policy.service_id, database_instance_id: policy.database_instance_id, object_id: kind, revision: '1', digest: hash(kind)});
  const intent = {launch_id: 'worker.launch', service_id: policy.service_id, supervisor_instance_id: source.scope.supervisor_instance_id,
    runtime_generation: assignment.clock_domain_descriptor.runtime_generation, member_id: 'worker.member', role: 'worker', artifact_manifest_ref: policy.artifact_manifest_ref,
    containment_ref: {group_id: 'worker.group', generation: 'worker.generation', backend: 'windows_job'}, object_scope: {kind: 'devices', device_ids: ['device.a']}, policy_revision: policy.policy_revision,
    extension_binding: {installation_ref: ref('installation'), approval_ref: ref('approval'), review_ref: ref('review'), role_resolution_ref: ref('role_resolution'),
      configuration_ref: ref('configuration'), intake_ref: ref('intake'), platform_profile_ref: {...ref('platform_profile'), object_id:policy.platform_profile_ref.profile_id, revision:policy.platform_profile_ref.revision}, host_installation_id: 'host', host_trust_epoch: '1',
      manifest_digest: hash('manifest'), artifact_set_digest: hash('artifacts'), entry_id: 'simulator', permissions_digest: hash('permissions')}};
  const key = {launch_id: intent.launch_id, launch_intent_digest: hash(intent)};
  const seal=grant=>{const {authorization_ref,...body}=grant;return {...body,authorization_ref:{...authorization_ref,digest:hash(body)}};};
  const authorization = (revision = '1', target = intent) => {
    const now = clock.tick();
    return seal({authorization_ref: ref('launch_authorization'), launch_id: target.launch_id, launch_intent_digest: hash(target), installation_ref: target.extension_binding.installation_ref,
      approval_ref: target.extension_binding.approval_ref, role_resolution_ref: target.extension_binding.role_resolution_ref, permissions_digest: target.extension_binding.permissions_digest,
      supervisor_instance_id: source.scope.supervisor_instance_id, fence_revision: revision, lifetime: {clock: source.scope.domain_ref, issued_tick: String(now), deadline_tick: String(now + 2000000000n)}});
  };
  const fence = (revision, items) => { const body = {scope: source.scope, revision, items}; return {...body, digest: hash(body)}; };
  const allow = {...key, disposition: 'allow'}, deny = {...key, disposition: 'deny'};
  await source.putFence(fence('1', [allow]));
  const errors = {};
  const create = async (name, grant = authorization(), requested = key) => {
    try { await source.createWorker({key: requested, authorization: name==='create_digest'?{...grant,authorization_ref:{...grant.authorization_ref,digest:hash('wrong')}}:seal(grant), load_id: 'unresolved.load', materialization_evidence_id: 'unresolved.evidence', materialization_challenge_id: 'unresolved.challenge'});
      errors[name] = 'unexpected_success'; } catch (error) { errors[name] = error.code; }
  };
  if (mode === 'worker-create') await create('create_missing');
  for (const kind of ['expired', 'future', 'domain', 'permissions', 'approval']) {
    const grant = authorization();
    if (kind === 'expired') { grant.lifetime.issued_tick = '0'; grant.lifetime.deadline_tick = '1'; }
    if (kind === 'future') { grant.lifetime.issued_tick = String(clock.tick() + 1000000000n); grant.lifetime.deadline_tick = String(BigInt(grant.lifetime.issued_tick) + 1000000000n); }
    if (kind === 'domain') grant.lifetime.clock = {...grant.lifetime.clock, descriptor_digest: hash('other')};
    if (kind === 'permissions') grant.permissions_digest = hash('other');
    if (kind === 'approval') grant.approval_ref = {...grant.approval_ref, object_id: 'other'};
    try { await source.registerWorker(intent, seal(grant)); errors[kind] = 'unexpected_success'; } catch (error) { errors[kind] = error.code; }
  }
  const grant = authorization(), first = await source.registerWorker(intent, seal(grant)), repeated = await source.registerWorker(intent, authorization());
  const queried = await source.queryLaunch(key);
  if (mode === 'worker-create') {
    await create('create_digest');
    for (const kind of ['expired', 'future', 'domain', 'permissions', 'approval', 'installation', 'role', 'authority', 'revision']) {
      const grant = authorization();
      if (kind === 'expired') { grant.lifetime.issued_tick = '0'; grant.lifetime.deadline_tick = '1'; }
      if (kind === 'future') { grant.lifetime.issued_tick = String(clock.tick() + 1000000000n); grant.lifetime.deadline_tick = String(BigInt(grant.lifetime.issued_tick) + 1000000000n); }
      if (kind === 'domain') grant.lifetime.clock = {...grant.lifetime.clock, descriptor_digest: hash('other')};
      if (kind === 'permissions') grant.permissions_digest = hash('other');
      if (kind === 'approval') grant.approval_ref = {...grant.approval_ref, object_id: 'other'};
      if (kind === 'installation') grant.installation_ref = {...grant.installation_ref, digest: hash('other')};
      if (kind === 'role') grant.role_resolution_ref = {...grant.role_resolution_ref, revision: '2'};
      if (kind === 'authority') grant.authorization_ref = {...grant.authorization_ref, database_instance_id: 'other'};
      if (kind === 'revision') grant.fence_revision = '0';
      await create('create_' + kind, grant);
    }
    const changed = {...intent, object_scope: {kind: 'devices', device_ids: ['device.b']}};
    await create('create_conflict', authorization('1', changed), {...key, launch_intent_digest: hash(changed)});
    await create('create_unresolved'); await create('create_repeated');
    source.assertCurrent();
  }
  try { await source.putFence(fence('2', [])); } catch (error) { errors.omission = error.code; }
  try { await source.registerWorker(intent, authorization()); } catch (error) { errors.unsynchronized = error.code; }
  if (mode === 'worker-create') await create('create_unsynchronized');
  await source.putFence(fence('1', [allow]));
  await source.putFence(fence('2', [deny]));
  if (mode === 'worker-create') await create('create_denied', authorization('2'));
  try { await source.registerWorker(intent, authorization('2')); } catch (error) { errors.denied = error.code; }
  const changed = {...intent, object_scope: {kind: 'devices', device_ids: ['device.b']}};
  try { await source.registerWorker(changed, authorization('2', changed)); } catch (error) { errors.changed = error.code; }
  try { await source.queryLaunch({launch_id: intent.launch_id, launch_intent_digest: hash(changed)}); } catch (error) { errors.query_conflict = error.code; }
  try { await source.putFence(fence('3', [allow])); } catch (error) { errors.reallow = error.code; }
  let retirement = null, repeatedRetirement = null, replacement = null;
  if (mode === 'worker-retire') {
    try { await source.retireWorker(changed, 'revoked'); } catch (error) { errors.retire_conflict = error.code; }
    const missing = {...intent, launch_id: 'worker.missing'};
    try { await source.retireWorker(missing, 'revoked'); } catch (error) { errors.retire_missing = error.code; }
    // 上一次reallow失败已关闭fence同步；保护退役仍可进行，不要求重新取得启动授权。
    retirement = await source.retireWorker(intent, 'revoked');
    repeatedRetirement = await source.retireWorker(intent, 'shutdown');
    try { await source.registerWorker(intent, authorization('2')); } catch (error) { errors.retire_reregister = error.code; }
    await create('retire_create', authorization('2'));
    const nextIntent = {...intent, launch_id: 'worker.next', member_id: 'worker.next.member',
      containment_ref: {...intent.containment_ref, group_id: 'worker.next.group'}};
    await source.putFence(fence('3', [{launch_id: nextIntent.launch_id, launch_intent_digest: hash(nextIntent), disposition: 'allow'}]));
    replacement = await source.registerWorker(nextIntent, authorization('3', nextIntent));
    try { await source.registerWorker(intent, authorization('3')); } catch (error) { errors.retire_reregister_synced = error.code; }
    try { await source.putFence(fence('4', [allow, {launch_id: nextIntent.launch_id, launch_intent_digest: hash(nextIntent), disposition: 'allow'}])); }
    catch (error) { errors.retire_reallow = error.code; }
  }
  const final = await source.queryLaunch(key);
  process.stderr.write(JSON.stringify({event: 'worker-result', intent, grant, first, repeated, queried, final, errors, retirement, repeatedRetirement, replacement}) + '\n');
  process.stdin.setEncoding('utf8').on('data', data => { if (data === 'stop\n') { source.close(); process.stdin.destroy(); } }); process.stdin.resume();
} else if (mode === 'fence' || mode === 'fence-failure') {
  const source = await connectCoreSupervisor({pipe: options['--supervisor-pipe'], channelId: options['--supervisor-channel'], policy,
    binding: {descriptor: assignment.clock_domain_descriptor, receipt}});
  const items = Array.from({length: 256}, (_, i) => ({launch_id: 'worker' + String(i).padStart(3, '0') + 'x'.repeat(115),
    launch_intent_digest: 'sha256:' + '2'.repeat(64), disposition: 'allow'}));
  const snapshot = (revision, list) => {
    const body = {scope: source.scope, revision, items: list};
    return {...body, digest: 'sha256:' + crypto.createHash('sha256').update(canonicalize(body)).digest('hex')};
  };
  const send = async (revision, list) => {
    const body = snapshot(revision, list);
    try { const result = await source.putFence(body); process.stderr.write(JSON.stringify({event: 'fence', body, result}) + '\n'); }
    catch (error) { process.stderr.write(JSON.stringify({event: 'fence-error', code: error.code}) + '\n'); }
  };
  await send('9007199254740993', items);
  if (mode === 'fence') {
    await send('9007199254740993', items);
    await send('9007199254740992', items);
    await send('9007199254740993', []);
    const denied = items.map(item => ({...item, disposition: 'deny'}));
    await send('9007199254740994', denied);
    await send('9007199254740995', []);
    await send('9007199254740996', items);
    await send('9007199254740996', [{...items[0], launch_intent_digest: 'sha256:' + '3'.repeat(64), disposition: 'deny'}]);
    await send('9007199254740995', []);
    process.stderr.write(JSON.stringify({event: 'fence-done', current: source.current().payload.record.gate_state}) + '\n');
  }
  process.stdin.setEncoding('utf8').on('data', data => { if (data === 'stop\n') { source.close(); process.stdin.destroy(); } });
  process.stdin.resume();
} else if (mode === 'peer') {
  const child = spawn(process.execPath, [fileURLToPath(new URL('./control-intruder.mjs', import.meta.url)), options['--supervisor-pipe']], {stdio: 'ignore', windowsHide: true});
  process.stderr.write(JSON.stringify({event: 'intruder', pid: child.pid}) + '\n');
  setInterval(() => {}, 1000);
} else {
  const socket = net.createConnection(options['--supervisor-pipe']);
  socket.on('error', () => {});
  const frame = {version: supervisorControlVersion, type: 'LAUNCH_QUERY',
    scope: {service_id: policy.service_id, database_instance_id: policy.database_instance_id, supervisor_instance_id: assignment.clock_domain_descriptor.supervisor_instance_id, domain_ref: receipt.domain_ref},
    channel_id: options['--supervisor-channel'], sequence: '1', message_id: 'first', reply_to: null,
    payload: {launch_id: receipt.launch_id, launch_intent_digest: receipt.launch_intent_digest}};
  if (mode === 'scope') frame.scope.database_instance_id = 'other';
  if (mode === 'channel') frame.channel_id = 'other';
  if (mode === 'sequence') frame.sequence = '2';
  if (mode === 'reply') frame.reply_to = 'unsolicited';
  if (mode === 'direction') frame.type = 'LAUNCH_RESULT';
  if (mode === 'conflict') frame.payload.launch_intent_digest = 'sha256:' + '0'.repeat(64);
  if (mode === 'missing') frame.payload.launch_id = 'missing';
  if (mode.startsWith('fence-bad-')) {
    frame.type = 'FENCE_PUT';
    const item = {launch_id: 'worker', launch_intent_digest: 'sha256:' + '2'.repeat(64), disposition: 'allow'};
    const body = {scope: frame.scope, revision: '1', items: [item]};
    if (mode === 'fence-bad-scope') body.scope = {...frame.scope, database_instance_id: 'another'};
    if (mode === 'fence-bad-order') body.items = [{...item, launch_id: 'z'}, {...item, launch_id: 'a'}];
    if (mode === 'fence-bad-duplicate') body.items = [item, {...item, disposition: 'deny'}];
    if (mode === 'fence-bad-core') body.items = [{...item, launch_id: receipt.launch_id}];
    if (mode === 'fence-bad-capacity') body.items = Array.from({length: 257}, (_, i) => ({...item, launch_id: 'w' + String(i).padStart(3, '0')}));
    if (mode === 'fence-bad-revision') body.revision = '01';
    if (mode === 'fence-bad-id') body.items = [{...item, launch_id: '/worker'}];
    if (mode === 'fence-bad-extra') body.items = [{...item, authorized: true}];
    frame.payload = {...body, digest: 'sha256:' + crypto.createHash('sha256').update(canonicalize(body)).digest('hex')};
    if (mode === 'fence-bad-digest') frame.payload.digest = 'sha256:' + '0'.repeat(64);
  }
  const line = canonicalize(frame) + '\n';
  socket.once('connect', () => {
    if (mode === 'disconnect') { socket.destroy(); return; }
    if (mode === 'silent') return;
    socket.write(mode === 'duplicate-key' ? line.replace('"type":', '"type":"LAUNCH_QUERY","type":') : line);
  });
  let buffer = '';
  socket.on('data', async bytes => {
    buffer += bytes; if (!buffer.endsWith('\n')) return;
    const response = await decodeSupervisorControl(Buffer.from(buffer.slice(0, -1)), mode === 'conflict' ? 'ERROR' : 'LAUNCH_RESULT'); buffer = '';
    process.stderr.write(JSON.stringify({event: 'response', sequence: response.sequence, reply_to: response.reply_to, payload: response.payload}) + '\n');
    if (mode === 'replay') socket.write(line);
  });
  process.stdin.setEncoding('utf8').on('data', data => { if (data === 'stop\n') { socket.destroy(); process.stdin.destroy(); } });
  process.stdin.resume();
}
