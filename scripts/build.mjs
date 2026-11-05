import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const names = ['supervisor-control.mjs', 'core-bootstrap.mjs', 'core-runtime.sql', 'cli.mjs', 'server.mjs', 'storage.mjs', 'storage.sql', 'identity.sql', 'identity-crypto.mjs', 'identity-store.mjs', 'local-admin.mjs', 'native-clock.mjs', 'clock-monitor.mjs', 'clock.sql', 'auth-clock.sql', 'auth-clock.mjs', 'auth-clock-value.mjs', 'auth-clock-store.mjs', 'session-store.mjs', 'session.sql', 'access-token-store.mjs', 'access-token.sql'];
const files = await Promise.all(names.map(async name => [name, await fs.readFile(path.join(root, 'src', name))]));
files.push(['process-host.mjs', await fs.readFile(path.join(root, 'src/process-host.mjs'))]);
files.push(['worker-bootstrap.mjs', await fs.readFile(path.join(root, 'src/worker-bootstrap.mjs'))]);
for (const name of ['worker-launch-store.mjs','worker-launch.sql','worker-runtime-store.mjs','worker-runtime.sql','worker-dependencies.mjs','worker-dependencies.sql','extension-plan-store.mjs','extension-plan.sql','extension-activation-store.mjs','extension-activation.sql','worker-authorization-store.mjs','worker-authorization.sql']) files.push([name,await fs.readFile(path.join(root,'src',name))]);
for (const name of ['extension-installation-store.mjs','extension-installation.sql']) files.push([name,await fs.readFile(path.join(root,'src',name))]);
for (const name of ['configuration-validator.mjs','configuration-worker.mjs','configuration-schema.mjs']) files.push([name,await fs.readFile(path.join(root,'src',name))]);
for (const name of ['extension-configuration-store.mjs','extension-configuration.sql','extension-role-store.mjs','extension-role-resolution.mjs','extension-role.sql','extension-review-store.mjs','extension-review-permissions.mjs','extension-review.sql','extension-approval-store.mjs','extension-approval.sql','extension-capabilities.mjs','extension-capabilities.sql','extension-approval-state.mjs','extension-launch-binding.mjs','launch-content.mjs']) files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['device-worker-entry.mjs',await fs.readFile(path.join(root,'src/device-worker-entry.mjs'))]);
for(const name of ['device-module-channel.mjs','device-module-client.mjs','device-module-host.mjs','device-module-store.mjs','device-module.sql','device-catalog.sql','device-catalog-store.mjs','simulator-module.mjs','simulator-policy.json'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['materialized-content.mjs', await fs.readFile(path.join(root, 'src/materialized-content.mjs'))]);
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
// 复用SDK已锁定的原始JSON扫描器，只替换Schema注册模块，不维护第二份解析算法。
const configurationWire=files.find(([name])=>name==='sdk/runtime/panel-wire/preview/wire.mjs')?.[1].toString();
if(!configurationWire||configurationWire.split("'./registry.mjs'").length!==3)throw new Error('configuration_wire_input');
files.push(['configuration-wire.mjs',Buffer.from(configurationWire.replaceAll("'./registry.mjs'","'./configuration-schema.mjs'"))]);
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
  const materializationManifest = await fs.readFile(path.join(nativeDir, 'materialization-manifest.json'));
  const materialization = JSON.parse(materializationManifest), materializationBinary = await fs.readFile(path.join(nativeDir, 'leafseamer_materialization.node'));
  if (materialization.format !== 'leafseamer-materialization-artifact/1' || materialization.platform !== process.platform || materialization.arch !== process.arch ||
      materialization.napi_version !== 8 || materialization.binary_sha256 !== hash(materializationBinary) ||
      materialization.source_sha256 !== hash(await fs.readFile(path.join(root, 'native/materialization.cc'))) ||
      materialization.content_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/content-root.h'))) ||
      materialization.inputs_sha256 !== hash(await fs.readFile(path.join(root, 'native-inputs.json'))) ||
      materialization.cmake_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/CMakeLists.txt')))) throw new Error('materialization_build_drift');
  files.push(['native/leafseamer_materialization.node', materializationBinary], ['native/materialization-manifest.json', materializationManifest]);
  const hostManifest = await fs.readFile(path.join(nativeDir, 'process-host-manifest.json'));
  const host = JSON.parse(hostManifest), hostBinary = await fs.readFile(path.join(nativeDir, 'leafseamer_process_host.exe'));
  if (host.format !== 'leafseamer-process-host/1' || host.platform !== process.platform || host.arch !== process.arch ||
      host.binary_sha256 !== hash(hostBinary) || host.source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-host.cc'))) ||
      host.worker_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-worker.h'))) ||
      host.creation_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-creation.h'))) ||
      host.module_link_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-module-link.h'))) ||
      host.journal_creation_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-creation.sql'))) ||
      host.journal_v4_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-v4.sql'))) ||
      host.runtime_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-runtime.h'))) ||
      host.loading_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-loading.h'))) ||
      host.content_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/content-root.h'))) ||
      host.installation_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-installation.h'))) ||
      host.control_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-control.h'))) ||
      host.bootstrap_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-bootstrap.h'))) ||
      host.journal_v2_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-v2.sql'))) ||
      host.journal_v3_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-v3.sql'))) ||
      host.journal_retirement_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-retirement.sql'))) ||
      host.journal_fence_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-fence.sql'))) ||
      host.journal_v1_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-v1.sql'))) ||
      host.journal_upgrade_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-upgrade.sql'))) ||
      host.journal_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal.h'))) ||
      host.journal_sql_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal.sql'))) ||
      host.inputs_sha256 !== hash(await fs.readFile(path.join(root, 'native-inputs.json'))) ||
      host.cmake_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/CMakeLists.txt')))) throw new Error('process_host_build_drift');
  files.push(['native/leafseamer_process_host.exe', hostBinary], ['native/process-host-manifest.json', hostManifest]);
}
const runtimeLockBytes=await fs.readFile(path.join(root,'worker-runtime-inputs.json'));
const runtimeLock=JSON.parse(runtimeLockBytes),runtimeHash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const canonicalSource=await fs.readFile(new URL(import.meta.resolve('canonicalize')));
const canonicalLicense=await fs.readFile(new URL('../LICENSE',new URL(import.meta.resolve('canonicalize'))));
if(runtimeLock.format!=='leafseamer-worker-runtime-inputs/1'||runtimeHash(canonicalSource)!==runtimeLock.canonicalize_sha256||
  runtimeHash(canonicalLicense)!==runtimeLock.canonicalize_license_sha256)throw new Error('worker_runtime_inputs');
files.push(['runtime/canonicalize.mjs',canonicalSource],['runtime/CANONICALIZE_LICENSE',canonicalLicense],['runtime/inputs.json',runtimeLockBytes]);
if(process.platform==='win32'){
 const executable=await fs.realpath(process.execPath),node=await fs.readFile(executable),license=await fs.readFile(path.join(path.dirname(executable),'LICENSE'));
 if(process.versions.node!==runtimeLock.node_version||process.arch!==runtimeLock.arch||runtimeLock.platform!==process.platform||
   runtimeHash(node)!==runtimeLock.node_sha256||runtimeHash(license)!==runtimeLock.node_license_sha256)throw new Error('worker_runtime_node');
 files.push(['runtime/node.exe',node],['runtime/NODE_LICENSE',license]);
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
