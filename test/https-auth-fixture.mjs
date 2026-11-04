import {spawnSync} from 'node:child_process';
import https from 'node:https';
import {seal, ref} from '../dist/auth-clock-value.mjs';
import {fixture} from './auth-clock-fixture.mjs';

// 临时证书仅在内存生成，客户端明确以此证书验证TLS；不写系统证书库或关闭校验。
export function certificate() {
  const script = `$ErrorActionPreference='Stop'
    $rsa=[System.Security.Cryptography.RSA]::Create(2048)
    $request=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost',$rsa,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $san=[System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName('localhost');$san.AddIpAddress([System.Net.IPAddress]::Parse('127.0.0.1'))
    $request.CertificateExtensions.Add($san.Build())
    $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddDays(1))
    @{key=$rsa.ExportPkcs8PrivateKeyPem();cert=$cert.ExportCertificatePem()}|ConvertTo-Json -Compress
    $cert.Dispose();$rsa.Dispose()`;
  const child = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', script], {encoding: 'utf8', windowsHide: true});
  if (child.status !== 0) throw new Error('test_certificate_generation');
  return JSON.parse(child.stdout);
}

// 使用产品实际原生采样器；仅环境误差批准和监督引用为隔离测试构造，不作为平台批准。
export function supervisedFixture() {
  const state = {failed: false};
  return {state, provider({scope, source}) {
    const template = fixture(scope).evidence;
    const {digest: _p, ...pb} = template.policy;
    const policy = seal({...pb, max_system_error_ns: '1000000000'});
    const {digest: _r, ...rb} = template.runtime;
    const runtime = seal({...rb, policy_ref: ref(policy), native_binary_digest: source.artifactDigest,
      continuity: source.capture().continuity, valid_before_tick_ns: String(source.tick() + 120000000000n)});
    const {digest: _h, ...hb} = template.health;
    const health = seal({...hb, runtime_ref: ref(runtime), policy_ref: ref(policy), valid_before_tick_ns: runtime.valid_before_tick_ns});
    return {read() { if (state.failed) throw new Error('synthetic_provider_failure'); return {policy, runtime, health}; }};
  }};
}

// 模拟浏览器同源Cookie容器；网络由实际HTTPS收发，证书和主机名正常验证。
export function browserFetch(cert) {
  const state = {cookie: null, cookies: [], requests: [], replies: [], held: null};
  const fetchImpl = (url, options) => new Promise((resolve, reject) => {
    const target = new URL(url), headers = Object.fromEntries(options.headers.entries());
    if (state.cookie && target.pathname.startsWith('/auth/')) headers.cookie = state.cookie;
    state.requests.push({target: target.pathname, headers: {...headers}});
    const request = https.request(target, {method: options.method, headers, ca: cert, rejectUnauthorized: true, signal: options.signal, agent: false}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk)); response.on('error', reject);
      response.on('end', () => {
        const pairs = [];
        for (let i = 0; i < response.rawHeaders.length; i += 2) pairs.push([response.rawHeaders[i], response.rawHeaders[i + 1]]);
        for (const cookie of response.headers['set-cookie'] ?? []) {
          state.cookies.push(cookie); state.cookie = /Max-Age=0/.test(cookie) ? null : cookie.split(';')[0];
        }
        const value = new Response(Buffer.concat(chunks), {status: response.statusCode, headers: pairs});
        state.replies.push({status: response.statusCode, headers: pairs});
        if (state.held) state.held(() => resolve(value)); else resolve(value);
      });
    });
    request.on('error', reject); request.end(options.body);
  });
  return {state, fetchImpl};
}
