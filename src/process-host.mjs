import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import canonicalize from 'canonicalize';
import {validateBootstrapPolicy} from './core-bootstrap.mjs';
import {bootstrapVersion,decodeBootstrap,decodeProtectedLaunchIntent} from './sdk/bootstrap.mjs';

export class ProcessHostError extends Error { constructor(code) { super(code); this.name = 'ProcessHostError'; this.code = code; } }
const check = (condition, code) => { if (!condition) throw new ProcessHostError(code); };
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const digest = value => 'sha256:' + hash(canonicalize(value));
const same = (left,right) => canonicalize(left) === canonicalize(right);
const identifier = /^[0-9a-f]{32}(?![\s\S])/;
const fileIdentity = /^[0-9a-f]{48}(?![\s\S])/;

function prepareProcessHost() {
  check(process.platform === 'win32' && process.arch === 'x64', 'process_host_platform');
  const root = fileURLToPath(new URL('./', import.meta.url));
  const executable = path.join(root, 'native/leafseamer_process_host.exe');
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'native/process-host-manifest.json')));
    check(manifest.format === 'leafseamer-process-host/1' && manifest.platform === process.platform && manifest.arch === process.arch &&
      hash(fs.readFileSync(executable)) === manifest.binary_sha256, 'process_host_artifact');
    const build = JSON.parse(fs.readFileSync(path.join(root, 'build-manifest.json')));
    // 清单校验安装内容；正式发行签名、加载期间防替换及 profile 批准仍由安装层提供。
    check(build.format === 'leafseamer-controller-build/1', 'process_host_artifact');
    for (const [name, expected] of Object.entries(build.artifacts)) {
      check(/^[A-Za-z0-9/_.-]+$/.test(name) && !name.startsWith('/') && !name.split('/').some(p => !p || p === '.' || p === '..'), 'process_host_artifact');
      check(hash(fs.readFileSync(path.join(root, name))) === expected, 'process_host_artifact');
    }
  } catch (error) { if (error instanceof ProcessHostError) throw error; throw new ProcessHostError('process_host_artifact'); }
  // 不继承 Node 预加载、调试或动态库搜索设置；精确入口及参数不经 shell。
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => ['SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'].includes(key.toUpperCase())));
  return {root, executable, env};
}

// 显式本机开发安装，不覆盖已有日志；不产生生产宿主或运行域批准。
export async function initializeProcessHost(dataDir) { return configureJournal(dataDir, false); }
export async function upgradeProcessHost(dataDir) { return configureJournal(dataDir, true); }
export async function upgradeTimeProviderJournal(dataDir) { return configureJournal(dataDir, true, true); }
async function configureJournal(dataDir, upgrade, timeProvider = false) {
  const mode = timeProvider ? '--upgrade-time-provider' : upgrade ? '--upgrade' : '--initialize';
  const frame = await journalCommand(dataDir, mode);
  check(frame.event === (upgrade ? 'process_journal_upgraded' : 'process_journal_initialized') && frame.runtime_admitted === false &&
    (!upgrade || ((timeProvider ? frame.schema_revision === '6' : ['5','6'].includes(frame.schema_revision)) &&
      typeof frame.changed === 'boolean')), 'process_host_protocol');
  return Object.freeze(frame);
}

function journalCommand(dataDir, mode, args = [], maxBytes = 4096) {
  const {executable, env} = prepareProcessHost();
  check(typeof dataDir === 'string' && path.isAbsolute(dataDir), 'process_host_options');
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [mode, dataDir, ...args], {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env});
    let output = '', failed = null;
    const timer = setTimeout(() => { failed = 'process_host_startup_timeout'; child.kill(); }, 10000);
    child.stdin.on('error', () => {}); child.stdin.end(); child.stderr.resume();
    child.stdout.setEncoding('utf8').on('data', chunk => { output += chunk; if (Buffer.byteLength(output) > maxBytes) { failed = 'process_host_protocol'; child.kill(); } });
    child.once('error', () => { failed = 'process_host_spawn'; });
    child.once('close', code => {
      clearTimeout(timer);
      try {
        if (failed) throw new ProcessHostError(failed);
        const frame = JSON.parse(output);
        if (code !== 0) throw new ProcessHostError(typeof frame.code === 'string' && /^[a-z_]{1,64}$/.test(frame.code) ? frame.code : 'process_host_failed');
        resolve(frame);
      } catch (error) { reject(error instanceof ProcessHostError ? error : new ProcessHostError('process_host_protocol')); }
    });
  });
}

export async function readProcessRecoveryRetirement({dataDir,runtimeGeneration,serviceId,databaseInstanceId} = {}) {
  const code = 'process_retirement_unproven';
  check(typeof runtimeGeneration === 'string' && identifier.test(runtimeGeneration), 'process_retirement_generation');
  const frame = await journalCommand(dataDir, '--query-recovery-retirement', [runtimeGeneration], 65536);
  check(frame.event === 'process_recovery_retirement' && frame.runtime_admitted === false && frame.evidence,code);
  try {
    const evidence = frame.evidence, attempt = evidence.attempt_id;
    const {receipt,descriptor} = evidence;
    const policy = validateBootstrapPolicy(evidence.policy);
    const intent = await decodeProtectedLaunchIntent(Buffer.from(canonicalize(evidence.intent)));
    await decodeBootstrap(Buffer.from(canonicalize({version:bootstrapVersion,type:'ADMISSION',payload:receipt})),'ADMISSION');
    const {clock_domain_id,descriptor_digest,...domain} = descriptor;
    const group = {backend:'windows_job',group_id:attempt,generation:runtimeGeneration};
    check(identifier.test(evidence.journal_incarnation) && fileIdentity.test(evidence.directory_id) &&
      identifier.test(attempt) && evidence.job_name === 'Global\\LeafSeamer.Core.'+attempt &&
      Number.isInteger(evidence.supervisor_pid) && evidence.supervisor_pid > 0 &&
      Number.isInteger(evidence.core_pid) && evidence.core_pid > 0 && evidence.core_pid !== evidence.supervisor_pid &&
      /^[1-9][0-9]{0,19}(?![\s\S])/.test(evidence.creation_filetime) && fileIdentity.test(evidence.image_file_id) &&
      evidence.active_processes === 0 && Number.isInteger(evidence.exit_code) && evidence.exit_code >= 0 &&
      evidence.exit_code <= 0xffffffff && [0,1].includes(evidence.forced) &&
      [evidence.worker_launches,evidence.time_provider_launches].every(count=>Number.isSafeInteger(count)&&count>=0),code);
    check(policy.service_id === serviceId && policy.database_instance_id === databaseInstanceId &&
      domain.descriptor_version === 'clock-domain/1' && domain.domain_kind === 'supervised_runtime' &&
      domain.authority_service_id === serviceId && domain.runtime_generation === runtimeGeneration &&
      domain.clock_backend_id === 'windows_interrupt_precise' && domain.clock_backend_revision === policy.clock_backend_revision &&
      domain.namespace_identity === 'windows-global' && domain.tick_unit === 'ns' && domain.suspend_accounting === 'included' &&
      domain.platform_profile_id === policy.platform_profile_ref.profile_id &&
      domain.platform_profile_revision === policy.platform_profile_ref.revision &&
      digest(domain) === descriptor_digest && clock_domain_id === 'clock_'+descriptor_digest.slice(7),code);
    check(intent.launch_id === attempt && intent.role === 'core' && intent.service_id === serviceId &&
      intent.supervisor_instance_id === domain.supervisor_instance_id && intent.runtime_generation === runtimeGeneration &&
      intent.policy_revision === policy.policy_revision && same(intent.containment_ref,group) &&
      same(intent.artifact_manifest_ref,policy.artifact_manifest_ref) && receipt.receipt_id === evidence.receipt_id &&
      receipt.role === 'core' && receipt.launch_id === attempt && receipt.os_observation_ref === attempt &&
      receipt.member_id === intent.member_id && receipt.launch_intent_digest === digest(intent) &&
      same(receipt.artifact_manifest_ref,intent.artifact_manifest_ref) && same(receipt.containment_ref,group) &&
      same(receipt.domain_ref,{clock_domain_id,descriptor_digest}) && receipt.gate_state === 'closed',code);
    return Object.freeze({format:'leafseamer-windows-process-retirement/1',runtime_generation:runtimeGeneration,
      service_id:serviceId,database_instance_id:databaseInstanceId,containment_id:attempt,receipt_id:receipt.receipt_id,
      directory_id:evidence.directory_id,journal_incarnation:evidence.journal_incarnation,active_processes:evidence.active_processes,
      exit_code:evidence.exit_code,forced:Boolean(evidence.forced),retirement_digest:digest(evidence)});
  } catch(error) {
    throw error instanceof ProcessHostError ? error : new ProcessHostError(code);
  }
}

// 安装内容的局部摘要；发行签名与加载防替换仍由安装层提供。
export function installedCoreDigest() {
  const {root} = prepareProcessHost();
  return 'sha256:' + hash(canonicalize({controller_build_sha256: hash(fs.readFileSync(path.join(root, 'build-manifest.json'))),
    node_sha256: hash(fs.readFileSync(path.join(root, 'runtime/node.exe')))}));
}

export function installedTimeProviderDigest() {
  const {root} = prepareProcessHost();
  const build = JSON.parse(fs.readFileSync(path.join(root, 'build-manifest.json')));
  const digest = build.artifacts['runtime/reference-time-provider.exe'];
  check(typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest), 'time_provider_artifact');
  return 'sha256:' + digest;
}

// bootstrapPolicy仅由可信本机装配选择；状态帧不替代持久化AdmissionReceipt或生产profile批准。
export async function startProcessHost({dataDir, host = '127.0.0.1', port = 0, onCoreOutput = () => {}, bootstrapPolicy = null,installationPeer=null,timeProviderPolicy=null,pairingProfile=null,standaloneProfile=null} = {}) {
  const {root, executable, env} = prepareProcessHost();
  const policy = bootstrapPolicy === null ? null : validateBootstrapPolicy(bootstrapPolicy);
  if (policy) check(policy.artifact_manifest_ref.digest === installedCoreDigest(), 'bootstrap_artifact');
  check(typeof dataDir === 'string' && path.isAbsolute(dataDir) && ['127.0.0.1', '::1'].includes(host) &&
    Number.isInteger(port) && port >= 0 && port <= 65535 && typeof onCoreOutput === 'function', 'process_host_options');
  const args = [dataDir, fs.realpathSync(process.execPath), path.join(root, 'cli.mjs'), policy ? 'contained-core-auth' : 'contained-core',
    '--host', host, '--port', String(port)];
  if (policy) args.push('--bootstrap-policy', canonicalize(policy));
  if (pairingProfile !== null) {
    check(policy && typeof pairingProfile === 'string' && path.isAbsolute(pairingProfile), 'pairing_profile_path');
    args.push('--pairing-profile', pairingProfile);
  }
  if(standaloneProfile!==null){
    check(policy&&pairingProfile===null&&typeof standaloneProfile==='string'&&path.isAbsolute(standaloneProfile),'standalone_profile_path');
    args.push('--standalone-profile',standaloneProfile);
  }
  if (timeProviderPolicy !== null) {
    const format = 'leafseamer-time-provider-bootstrap-policy/1';
    check(policy && timeProviderPolicy?.format === format, 'time_provider_policy');
    const checked = validateBootstrapPolicy({...timeProviderPolicy, format: policy.format});
    check(checked.service_id === policy.service_id && checked.database_instance_id === policy.database_instance_id &&
      checked.clock_backend_revision === policy.clock_backend_revision &&
      canonicalize(checked.platform_profile_ref) === canonicalize(policy.platform_profile_ref), 'time_provider_scope');
    check(checked.artifact_manifest_ref.digest === installedTimeProviderDigest(), 'time_provider_artifact');
    args.push('--time-provider-policy', canonicalize({...checked, format}));
  }
  if(installationPeer!==null){check(policy&&typeof installationPeer==='object','process_host_options');const config=canonicalize(installationPeer);
    check(Buffer.byteLength(config)<=8192,'process_host_options');args.push('--installation-peer',config);}
  const child = spawn(executable, args, {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env});
  let first, last, buffer = '', protocolError = null, closing = false;
  let startedResolve, startedReject, exitResolve, exitReject;
  const started = new Promise((resolve, reject) => { startedResolve = resolve; startedReject = reject; });
  const exited = new Promise((resolve, reject) => { exitResolve = resolve; exitReject = reject; });
  // 启动失败时 exited 仍可被调用方读取，且不会形成未处理拒绝。
  exited.catch(() => {});
  const stop = () => { if (!closing) { closing = true; child.stdin.end('stop\n'); } return exited; };
  const fail = code => { protocolError ??= new ProcessHostError(code); child.kill(); };
  child.stdin.on('error', () => {});
  child.stderr.on('data', chunk => { try { onCoreOutput(chunk); } catch { fail('process_host_output'); } });
  child.stdout.setEncoding('utf8').on('data', chunk => {
    buffer += chunk;
    if (buffer.length > 4096) { fail('process_host_protocol'); return; }
    while (buffer.includes('\n')) {
      const end = buffer.indexOf('\n'), text = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      try {
        const frame = JSON.parse(text);
        check(frame.runtime_admitted === false, 'process_host_protocol');
        if (frame.event === 'process_host_failed') throw new ProcessHostError(typeof frame.code === 'string' && /^[a-z_]{1,64}$/.test(frame.code) ? frame.code : 'process_host_failed');
        if (!first) {
          check(frame.event === 'process_contained' && /^[0-9a-f]{32}$/.test(frame.containment_id) && frame.supervisor_pid === child.pid &&
            Number.isInteger(frame.core_pid) && frame.core_pid > 0 && frame.bootstrap_authenticated === Boolean(policy), 'process_host_protocol');
          check(timeProviderPolicy === null ? frame.time_provider_pid === undefined :
            Number.isInteger(frame.time_provider_pid) && frame.time_provider_pid > 0 && frame.time_provider_pid !== frame.core_pid,
          'process_host_protocol');
          first = Object.freeze(frame); clearTimeout(startupTimer); startedResolve(first);
        } else {
          check(!last && frame.event === 'process_group_empty' && frame.containment_id === first.containment_id && frame.active_processes === 0 &&
            Number.isInteger(frame.core_exit_code) && typeof frame.stop_requested === 'boolean' && typeof frame.forced === 'boolean' && typeof frame.control_failed === 'boolean', 'process_host_protocol');
          check(timeProviderPolicy === null ? frame.time_provider_exit_code === undefined :
            Number.isInteger(frame.time_provider_exit_code) && frame.time_provider_exit_code >= 0, 'process_host_protocol');
          last = Object.freeze(frame);
        }
      } catch (error) { fail(error instanceof ProcessHostError ? error.code : 'process_host_protocol'); }
    }
  });
  const startupTimer = setTimeout(() => fail('process_host_startup_timeout'), 10000 + (policy?.bootstrap_timeout_ms ?? 0));
  child.once('error', () => { protocolError ??= new ProcessHostError('process_host_spawn'); });
  child.once('close', (code, signal) => {
    clearTimeout(startupTimer);
    const error = protocolError ?? ((!first || !last || buffer || signal) ? new ProcessHostError('process_host_exit_unproven') : null);
    if (!first) startedReject(error ?? new ProcessHostError('process_host_failed'));
    if (error) exitReject(error); else exitResolve(Object.freeze({exitCode: code, ...last}));
  });
  const containment = await started;
  return Object.freeze({containment, exited, close: stop});
}
