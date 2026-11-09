// 仅供隔离浏览器验收：真实HTTPS、SQLite和原生采样器；环境批准、账户和设备均为合成输入。
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';
import {startController} from '../dist/server.mjs';
import {localIdentityPermissions} from '../dist/local-permission-store.mjs';
import {seal, ref} from '../dist/auth-clock-value.mjs';
import {fixture} from './auth-clock-fixture.mjs';
import {certificate} from './https-auth-fixture.mjs';

export async function startGuiFixture(guiRoot, {readPermissions = true, commandPermissions = false} = {}) {
  guiRoot = path.resolve(guiRoot);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-gui-'));
  let app, closed = false;
  const cleanup = async () => { if (closed) return; closed = true; await app?.close();
    if (path.dirname(path.resolve(directory)) !== path.resolve(os.tmpdir())) throw new Error('fixture_cleanup_path');
    fs.rmSync(directory, {recursive: true, force: true}); };
  try {
    initializeStorage(directory); await migrateStorage(directory);
    const storage = openStorage(directory), identity = storage.identity;
    const login = {login: '测试管理员', password: 'synthetic-gui-password-012345'};
    try {
      const capability = storage.enrollment.begin();
      await storage.enrollment.complete({...login, mode: 'standalone', token_id: capability.token_id, secret: capability.secret});
      const f = fixture(storage.authenticationClock.scope), clock = startAuthenticationClock(f.source, storage.authenticationClock, f.provider, {schedule: false});
      try {
        const sessions = storage.sessions(clock), logged = await sessions.login(login), input = {credential_id: logged.credential_id, secret: logged.secret, csrf: logged.csrf};
        sessions.replaceLocalPermissions(input, {request_id: crypto.randomUUID(), principal_id: logged.session.principal_id, expected_revision: '1',
          permissions: [...localIdentityPermissions, ...(readPermissions ? ['device.read', 'control.read'] : []), ...(commandPermissions ? ['command.read', 'command.evidence.read'] : [])]}); sessions.logout(input);
      } finally { clock.stop(); }
      storage.registerDevice({request_id: crypto.randomUUID(), device_kind: 'synthetic-device', display_name: '测试设备'});
    } finally { storage.close(); }
    const config = path.join(directory, 'gui-site.json');
    fs.writeFileSync(config, JSON.stringify({site_label: '本机 Controller', service_id: identity.service_id, database_instance_id: identity.database_instance_id}));
    const build = spawnSync(process.execPath, ['scripts/build.mjs', '--config', config], {cwd: guiRoot, encoding: 'utf8', windowsHide: true});
    if (build.status !== 0) throw new Error('gui_fixture_build: ' + build.stderr);
    const socket = net.createServer(); await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
    const port = socket.address().port; await new Promise(resolve => socket.close(resolve));
    const material = certificate(), origin = 'https://127.0.0.1:' + port, state = {failed: false};
    const provider = ({scope, source}) => {
      const template = fixture(scope).evidence;
      const {digest: _p, ...pb} = template.policy, {digest: _r, ...rb} = template.runtime, {digest: _h, ...hb} = template.health;
      const policy = seal({...pb, max_system_error_ns: '1000000000'});
      const runtime = seal({...rb, policy_ref: ref(policy), native_binary_digest: source.artifactDigest, continuity: source.capture().continuity,
        valid_before_tick_ns: String(source.tick() + 1800000000000n)});
      const health = seal({...hb, runtime_ref: ref(runtime), policy_ref: ref(policy), valid_before_tick_ns: runtime.valid_before_tick_ns});
      return {read() { if (state.failed) throw new Error('synthetic_provider_failure'); return {policy, runtime, health}; }};
    };
    app = await startController({dataDir: directory, port, tls: {...material, origin}, authenticationProvider: provider, guiDirectory: path.join(guiRoot, 'dist')});
    const spki = crypto.createHash('sha256').update(new crypto.X509Certificate(material.cert).publicKey.export({type: 'spki', format: 'der'})).digest('base64');
    return {origin, spki, certificate: material.cert, login, identity, state, close: cleanup};
  } catch (error) { await cleanup(); throw error; }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('gui_directory_argument');
  const fixture = await startGuiFixture(process.argv[2]);
  console.log(JSON.stringify({origin: fixture.origin, spki: fixture.spki, synthetic: true}));
  process.stdin.setEncoding('utf8'); process.stdin.on('data', value => { if (value.trim() === 'fail') fixture.state.failed = true; });
  process.on('SIGINT', () => { void fixture.close(); process.stdin.destroy(); });
  const timeout = setTimeout(() => { void fixture.close(); process.stdin.destroy(); }, 1800000); timeout.unref();
}
