import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export class ProcessHostError extends Error { constructor(code) { super(code); this.name = 'ProcessHostError'; this.code = code; } }
const check = (condition, code) => { if (!condition) throw new ProcessHostError(code); };
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

// 本机装配入口；输出仅是本次 OS 进程组事实，不是 DF02 AdmissionReceipt。
export async function startProcessHost({dataDir, host = '127.0.0.1', port = 0, onCoreOutput = () => {}} = {}) {
  check(process.platform === 'win32' && process.arch === 'x64', 'process_host_platform');
  check(typeof dataDir === 'string' && path.isAbsolute(dataDir) && ['127.0.0.1', '::1'].includes(host) &&
    Number.isInteger(port) && port >= 0 && port <= 65535 && typeof onCoreOutput === 'function', 'process_host_options');
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
  const child = spawn(executable, [fs.realpathSync(process.execPath), path.join(root, 'cli.mjs'), 'contained-core',
    '--data-dir', dataDir, '--host', host, '--port', String(port)], {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env});
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
            Number.isInteger(frame.core_pid) && frame.core_pid > 0, 'process_host_protocol');
          first = Object.freeze(frame); clearTimeout(startupTimer); startedResolve(first);
        } else {
          check(!last && frame.event === 'process_group_empty' && frame.containment_id === first.containment_id && frame.active_processes === 0 &&
            Number.isInteger(frame.core_exit_code) && typeof frame.stop_requested === 'boolean' && typeof frame.forced === 'boolean', 'process_host_protocol');
          last = Object.freeze(frame);
        }
      } catch (error) { fail(error instanceof ProcessHostError ? error.code : 'process_host_protocol'); }
    }
  });
  const startupTimer = setTimeout(() => fail('process_host_startup_timeout'), 10000);
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
