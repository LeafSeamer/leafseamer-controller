import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const names = ['supervisor-control.mjs', 'core-bootstrap.mjs', 'core-runtime.sql', 'cli.mjs', 'server.mjs', 'storage.mjs', 'storage.sql', 'identity.sql', 'identity-crypto.mjs', 'identity-store.mjs', 'local-admin.mjs', 'native-clock.mjs', 'clock-monitor.mjs', 'clock.sql', 'auth-clock.sql', 'auth-clock.mjs', 'auth-clock-value.mjs', 'auth-clock-store.mjs', 'session-store.mjs', 'session.sql', 'access-token-store.mjs', 'access-token.sql'];
const files = await Promise.all(names.map(async name => [name, await fs.readFile(path.join(root, 'src', name))]));
files.push(['process-host.mjs', await fs.readFile(path.join(root, 'src/process-host.mjs'))]);
files.push(['auth-http.mjs', await fs.readFile(path.join(root, 'src/auth-http.mjs'))]);
files.push(['gui-assets.mjs', await fs.readFile(path.join(root, 'src/gui-assets.mjs'))]);
for (const name of ['local-permission-store.mjs', 'local-permission.sql']) files.push([name, await fs.readFile(path.join(root, 'src', name))]);
for (const name of ['device-registry-store.mjs', 'device-registry.sql', 'command-admission-store.mjs', 'request-context-store.mjs', 'command-admission.sql', 'request-context.sql']) files.push([name, await fs.readFile(path.join(root, 'src', name))]);
// SDK是构建输入；发行包内含经锁定清单核验的完整运行资产，不依赖邻仓路径。
const sdkRoot = new URL('./', import.meta.resolve('@leafseamer/sdk'));
const sdkLock = JSON.parse(await fs.readFile(path.join(root, 'sdk-runtime.json'), 'utf8'));
const sdkManifestBytes = await fs.readFile(new URL('build-manifest.json', sdkRoot));
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
if (digest(sdkManifestBytes) !== sdkLock.manifest_sha256) throw new Error('sdk_manifest_drift');
const sdkManifest = JSON.parse(sdkManifestBytes);
if (JSON.stringify(sdkManifest.selection) !== JSON.stringify(sdkLock.selection)) throw new Error('sdk_selection_drift');
for (const [name, expected] of Object.entries(sdkManifest.artifacts)) {
  if (!/^[a-zA-Z0-9/_.-]+$/.test(name) || name.split('/').some(p => !p || p === '.' || p === '..') || name.startsWith('/')) throw new Error('sdk_artifact_path');
  const bytes = await fs.readFile(new URL(name, sdkRoot));
  if (digest(bytes) !== expected) throw new Error('sdk_artifact_drift');
  files.push(['sdk/' + name, bytes]);
}
const sdkLicense = await fs.readFile(new URL('../LICENSE', sdkRoot));
if (digest(sdkLicense) !== sdkLock.license_sha256) throw new Error('sdk_license_drift');
files.push(['sdk/build-manifest.json', sdkManifestBytes], ['sdk/LICENSE', sdkLicense]);
const nativeDir = path.join(root, 'logs/native-clock/artifacts', process.platform + '-' + process.arch);
const nativeManifest = await fs.readFile(path.join(nativeDir, 'manifest.json'));
const native = JSON.parse(nativeManifest), binary = await fs.readFile(path.join(nativeDir, 'leafseamer_clock.node'));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
if (native.platform !== process.platform || native.arch !== process.arch || native.binary_sha256 !== hash(binary) ||
    native.source_sha256 !== hash(await fs.readFile(path.join(root, 'native/clock.cc'))) ||
    native.cmake_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/CMakeLists.txt'))) ||
    native.inputs_sha256 !== hash(await fs.readFile(path.join(root, 'native-inputs.json')))) throw new Error('native_build_drift');
files.push(['native/leafseamer_clock.node', binary], ['native/manifest.json', nativeManifest]);
if (process.platform === 'win32') {
  const hostManifest = await fs.readFile(path.join(nativeDir, 'process-host-manifest.json'));
  const host = JSON.parse(hostManifest), hostBinary = await fs.readFile(path.join(nativeDir, 'leafseamer_process_host.exe'));
  if (host.format !== 'leafseamer-process-host/1' || host.platform !== process.platform || host.arch !== process.arch ||
      host.binary_sha256 !== hash(hostBinary) || host.source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-host.cc'))) ||
      host.control_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-control.h'))) ||
      host.bootstrap_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-bootstrap.h'))) ||
      host.journal_v1_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-v1.sql'))) ||
      host.journal_upgrade_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-upgrade.sql'))) ||
      host.journal_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal.h'))) ||
      host.journal_sql_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal.sql'))) ||
      host.inputs_sha256 !== hash(await fs.readFile(path.join(root, 'native-inputs.json'))) ||
      host.cmake_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/CMakeLists.txt')))) throw new Error('process_host_build_drift');
  files.push(['native/leafseamer_process_host.exe', hostBinary], ['native/process-host-manifest.json', hostManifest]);
}
const output = path.resolve(root, 'dist');
if (path.dirname(output) !== path.resolve(root)) throw new Error('output_path');
await fs.rm(output, {recursive: true, force: true}); await fs.mkdir(path.join(output, 'native'), {recursive: true});
for (const [name, bytes] of files) {
  await fs.mkdir(path.dirname(path.join(output, name)), {recursive: true});
  await fs.writeFile(path.join(output, name), bytes);
}
await fs.chmod(path.join(output, 'cli.mjs'), 0o755);
await fs.writeFile(path.join(output, 'build-manifest.json'), JSON.stringify({format: 'leafseamer-controller-build/1',
  artifacts: Object.fromEntries(files.map(([n, b]) => [n, crypto.createHash('sha256').update(b).digest('hex')]))}, null, 2) + '\n');
console.log(JSON.stringify({artifacts: files.length, mode: 'protected'}));
