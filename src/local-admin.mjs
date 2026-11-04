import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {IdentityError} from './identity-crypto.mjs';

// 安装管理入口要求OS管理员；没有测试绕过、环境开关或在线角色替代。
export function requireLocalAdministrator() {
  if (process.platform === 'linux' && process.geteuid() === 0) return;
  if (process.platform === 'win32') {
    // 固定首期标准Windows安装profile，不从PATH或调用者配置找可执行文件。
    const executable = 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe';
    const script = '$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { [Console]::Write("admin") }';
    try {
      const result = execFileSync(executable, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
        {encoding: 'utf8', timeout: 5000, windowsHide: true, maxBuffer: 128, stdio: ['ignore', 'pipe', 'pipe']});
      if (result === 'admin') return;
    } catch { /* 无法取得当前OS身份时拒绝。 */ }
  }
  throw new IdentityError('local_administrator_required');
}
export function requirePrivatePipes() {
  // 固定Windows工具链的isFIFO未报告继承管道；实测mode使用S_IFIFO。
  const isPipe = fd => (fs.fstatSync(fd).mode & 0o170000) === 0o010000;
  if (!isPipe(0) || !isPipe(1)) throw new IdentityError('private_pipes_required');
}
export function readEnrollmentInput() {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    const finish = (error, value) => {
      clearTimeout(timer); process.stdin.pause();
      process.stdin.removeListener('data', data); process.stdin.removeListener('end', end); process.stdin.removeListener('error', failed);
      for (const chunk of chunks) chunk.fill(0);
      if (error) reject(error); else resolve(value);
    };
    const failed = () => finish(new IdentityError('initialization_input'));
    const data = chunk => {
      size += chunk.length;
      if (size > 65536) { chunk.fill(0); failed(); return; }
      chunks.push(chunk);
    };
    const end = () => {
      const bytes = Buffer.concat(chunks);
      try { finish(null, JSON.parse(new TextDecoder('utf8', {fatal: true}).decode(bytes))); }
      catch { failed(); }
      finally { bytes.fill(0); }
    };
    const timer = setTimeout(() => finish(new IdentityError('initialization_expired')), 600000);
    process.stdin.on('data', data).once('end', end).once('error', failed);
  });
}
