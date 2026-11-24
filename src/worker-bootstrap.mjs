import crypto from 'node:crypto';
import fs from 'node:fs';
import canonicalize from './runtime/canonicalize.mjs';
import {decodeWorkerIntent} from './sdk/worker-runtime.mjs';
import {BootstrapError, createBootstrapChannel} from './core-bootstrap.mjs';
import {openNativeClock} from './native-clock.mjs';

const check = (ok, code) => { if (!ok) throw new BootstrapError(code); };
const same = (a, b) => canonicalize(a) === canonicalize(b);
const digest = value => 'sha256:' + crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;

function assertLinuxWorker(intent, domain, clock) {
  check(domain.clock_backend_id === 'linux_boottime' && intent.containment_ref.backend === 'linux_cgroup_v2' &&
    uuid.test(intent.runtime_generation) && uuid.test(intent.launch_id) && fs.statfsSync('/proc').type === 0x9fa0,
  'bootstrap_containment');
  const boot = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
  check(uuid.test(boot) && same(domain.os_boot_identity,
    {status:'verified',source:'linux-proc-boot-id',value:boot,evidence_ref:boot}), 'bootstrap_linux_boot');
  const sample = clock.capture();
  check(domain.namespace_identity === 'linux_' + sample.raw.namespace_after.replace(':', '_'), 'bootstrap_clock_backend');
  const root = '/leafseamer_' + intent.runtime_generation.replaceAll('-', '') + '_controller';
  const leaf = '/worker_' + intent.launch_id.replaceAll('-', '');
  const membership = fs.readFileSync('/proc/self/cgroup', 'utf8');
  const groupPath = [root + leaf, root + '.slice' + leaf].find(candidate => membership === '0::' + candidate + '\n');
  check(groupPath, 'bootstrap_containment');
  const filename = '/sys/fs/cgroup' + groupPath;
  const status = fs.lstatSync(filename, {bigint:true});
  check(status.isDirectory() && status.nlink > 0n && fs.realpathSync.native(filename) === filename &&
    fs.statfsSync(filename).type === 0x63677270, 'bootstrap_containment');
  const group = {device:String(status.dev),inode:String(status.ino)};
  check(intent.containment_ref.group_id === 'group_' + digest({boot_id:boot,group_path:groupPath,group}).slice(7), 'bootstrap_containment');
}

// 仅供已固定制品的Controller设备worker装配调用。intent与descriptor来自可信启动装配，
// 不得从Assignment自证；通道必须是监督器定向继承端点。此入口不创建进程或开放业务闸门。
export async function bootstrapDeviceWorker({input, output, intentBytes, identity, descriptor, timeoutMs}) {
  const linux = process.platform === 'linux';
  check((linux || process.platform === 'win32') && process.arch === 'x64', 'bootstrap_platform');
  check(Buffer.isBuffer(intentBytes) && intentBytes.length <= 262144, 'bootstrap_intent');
  check(Number.isInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 60000, 'bootstrap_timeout');
  check(identity && Object.keys(identity).sort().join(',') === 'database_instance_id,service_id', 'bootstrap_scope');
  // 在首次await之前固定调用者输入，后续变更不能改变已选启动意图或预期域。
  const bytes = Buffer.from(intentBytes), scope = {...identity}, expectedDomain = canonicalize(descriptor);
  check(typeof expectedDomain === 'string', 'bootstrap_descriptor');
  const clock = openNativeClock({linuxWithoutSystemSleep:linux});
  const intent = await decodeWorkerIntent(bytes, {authority: 'controller', ...scope});
  if (!linux) check(intent.containment_ref.backend === 'windows_job', 'bootstrap_containment');
  const channel = createBootstrapChannel(input, output, {timeoutMs});
  try {
    const assignment = await channel.assignment(), domain = assignment.clock_domain_descriptor;
    check(canonicalize(domain) === expectedDomain && domain.authority_service_id === scope.service_id &&
      domain.supervisor_instance_id === intent.supervisor_instance_id && domain.runtime_generation === intent.runtime_generation,
      'bootstrap_descriptor_binding');
    check(domain.tick_unit === 'ns' && domain.suspend_accounting === 'included', 'bootstrap_clock_backend');
    if (!linux) check(domain.clock_backend_id === 'windows_interrupt_precise' && domain.namespace_identity === 'windows-global', 'bootstrap_clock_backend');
    const {clock_domain_id, descriptor_digest, ...domainBody} = domain;
    check(digest(domainBody) === descriptor_digest && clock_domain_id === 'clock_' + descriptor_digest.slice(7), 'bootstrap_descriptor');
    const profile = intent.extension_binding.platform_profile_ref;
    check(profile.object_id === domain.platform_profile_id && profile.revision === domain.platform_profile_revision, 'bootstrap_profile');
    check(assignment.role === 'worker' && assignment.launch_id === intent.launch_id && assignment.member_id === intent.member_id &&
      assignment.launch_intent_digest === digest(intent) && same(assignment.artifact_manifest_ref, intent.artifact_manifest_ref), 'bootstrap_intent_binding');
    const start = BigInt(assignment.issued_tick_ns), end = BigInt(assignment.expires_tick_ns);
    check(end > start && end - start === BigInt(timeoutMs) * 1000000n, 'bootstrap_window');
    const current = () => {
      if (linux) assertLinuxWorker(intent, domain, clock);
      const tick = clock.tick();
      check(tick >= start && tick < end, 'bootstrap_expired');
      return tick;
    };
    current();
    const receipt = await channel.proveAndReceive(assignment), now = current();
    for (const key of ['bootstrap_id', 'launch_id', 'launch_intent_digest', 'member_id', 'member_boot_id', 'role', 'artifact_manifest_ref', 'channel_binding_id']) {
      check(same(receipt[key], assignment[key]), 'bootstrap_receipt_binding');
    }
    check(receipt.gate_state === 'closed' && same(receipt.containment_ref, intent.containment_ref) &&
      same(receipt.domain_ref, {clock_domain_id, descriptor_digest}), 'bootstrap_receipt_binding');
    const admitted = BigInt(receipt.admitted_tick_ns);
    check(admitted >= start && admitted < end && admitted <= now, 'bootstrap_receipt_expired');
    channel.release();
    // SDK已深冻结解析原件；不返回Assignment、secret或挑战nonce，不创建RuntimeBinding。
    return Object.freeze({intent, descriptor: domain, receipt, gate_state: 'closed'});
  } catch (error) {
    channel.close(); throw error;
  }
}
