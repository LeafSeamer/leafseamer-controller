import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const buildOptions = process.argv.slice(2);
const referenceTimeProvider = buildOptions[0] === '--reference-time-provider' ? buildOptions[1] : null;
if (buildOptions.length && (buildOptions.length !== 2 || !referenceTimeProvider || !path.isAbsolute(referenceTimeProvider) ||
    process.platform !== 'win32' || process.arch !== 'x64')) throw new Error('controller_build_arguments');
const names = ['authority-source-window.mjs', 'supervisor-control.mjs', 'core-bootstrap.mjs', 'core-runtime.sql', 'cli.mjs', 'server.mjs', 'storage.mjs', 'storage.sql', 'identity.sql', 'identity-crypto.mjs', 'identity-store.mjs', 'local-admin.mjs', 'native-clock.mjs', 'clock-monitor.mjs', 'clock.sql', 'auth-clock.sql', 'auth-clock.mjs', 'auth-clock-value.mjs', 'auth-clock-store.mjs', 'session-store.mjs', 'session.sql', 'access-token-store.mjs', 'access-token.sql'];
names.push('trusted-pairing-profile.mjs', 'local-pairing-admin.mjs', 'clock-evidence.mjs');
names.push('storage-revision.mjs');
names.push('command-dispatch-interruption.sql', 'command-dispatch-interruption.mjs');
names.push('command-unsent-recovery.sql', 'command-unsent-recovery.mjs');
const files = await Promise.all(names.map(async name => [name, await fs.readFile(path.join(root, 'src', name))]));
for(const name of ['device-event-source.sql','device-event-source.mjs','device-source-time.sql','device-event-qualification.mjs','simulator-event-review.json'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for (const name of ['time-provider-runtime.sql', 'time-provider-link.mjs', 'time-provider-polls.sql', 'time-provider-polls.mjs',
  'time-provider-capture.sql', 'time-provider-capture.mjs', 'time-provider-poll-release.sql', 'time-provider-source-recovery.sql',
  'time-provider-poll-control.sql', 'reference-time-anchor.sql', 'reference-time-anchor.mjs', 'reference-time-bundle.mjs', 'reference-time-scheduler.mjs',
  'command-reference-acceptance.sql', 'reference-time-invalidation.sql', 'reference-time-invalidation.mjs',
  'reference-time-exits.sql', 'reference-time-exits.mjs', 'reference-time-exit-recovery.sql',
  'command-issue-order.sql', 'command-issue-order.mjs']) {
  files.push([name, await fs.readFile(path.join(root, 'src', name))]);
}
for(const name of ['first-pairing-authorization.mjs','first-pairing-issue.sql'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['peer-action-admission.mjs','peer-action-binding.mjs'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['automation-command-adjudication.mjs','automation-command-adjudication.sql','peer-automation-command.mjs','automatic-device-gate.sql','automation-command-encoding.sql'])
 files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['peer-device-events.mjs',await fs.readFile(path.join(root,'src/peer-device-events.mjs'))]);
files.push(['service-snapshot-context.mjs',await fs.readFile(path.join(root,'src/service-snapshot-context.mjs'))]);
files.push(['service-consumer-scope.mjs',await fs.readFile(path.join(root,'src/service-consumer-scope.mjs'))]);
for(const name of ['device-event-scope.mjs','device-event-scope.sql'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['service-subscription-delivery.sql','service-subscription-reconcile.mjs','service-snapshot-baseline.sql','service-subscription-channel.mjs','service-subscription-channel.sql','service-event-channel.mjs','peer-event-websocket.mjs','service-snapshot-content.mjs','service-snapshot-store.mjs','service-snapshot.sql','device-source-projection.mjs','device-source-projection.sql','database-owner.mjs'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['service-subscription-store.mjs','service-subscription-http.mjs','service-subscription.sql'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['device-footprint-qualification.mjs','simulator-control-footprint.json','simulator-control-footprint-v1.json','simulator-control-bindings-v1.json','simulator-control-footprint-v2.json','simulator-control-bindings-v2.json'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['device-automation-binding.mjs','simulator-control-bindings.json'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['device-module-events.sql','session-denial.sql','session-denial-store.mjs','session-denial-delivery.mjs','peer-session-denial.mjs'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['issuer-authorization-watermark.sql','token-introspection.mjs','introspection-http.mjs','remote-permission.sql','remote-permission-store.mjs','peer-pairing.sql','peer-pairing-store.mjs','peer-pairing-value.mjs','peer-pairing-transport.mjs','peer-device-bindings.mjs','identity-error.mjs','opaque-secret.mjs'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['peer-automation-approval.mjs',await fs.readFile(path.join(root,'src/peer-automation-approval.mjs'))]);
files.push(['peer-run-approval-proposal.mjs',await fs.readFile(path.join(root,'src/peer-run-approval-proposal.mjs'))]);
files.push(['peer-run-approval-endorsement.mjs',await fs.readFile(path.join(root,'src/peer-run-approval-endorsement.mjs'))]);
files.push(['peer-run-approval.mjs',await fs.readFile(path.join(root,'src/peer-run-approval.mjs'))]);
files.push(['peer-run-initiator.mjs',await fs.readFile(path.join(root,'src/peer-run-initiator.mjs'))]);
files.push(['peer-run-arm-plan.mjs',await fs.readFile(path.join(root,'src/peer-run-arm-plan.mjs'))]);
files.push(['peer-run-preparation.mjs',await fs.readFile(path.join(root,'src/peer-run-preparation.mjs'))]);
files.push(['peer-run-approval-protection.mjs',await fs.readFile(path.join(root,'src/peer-run-approval-protection.mjs'))]);
for(const name of ['run-endorsement-policy.mjs','run-endorsement-policy.sql','run-endorsement-scope.mjs'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['run-approval-endorsement.mjs','run-approval-endorsement.sql'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['run-approval-rejection.sql',await fs.readFile(path.join(root,'src/run-approval-rejection.sql'))]);
files.push(['run-endorsement-revocation.sql',await fs.readFile(path.join(root,'src/run-endorsement-revocation.sql'))]);
files.push(['run-endorsement-revocation-receipt.sql',await fs.readFile(path.join(root,'src/run-endorsement-revocation-receipt.sql'))]);
for(const name of ['run-preparation-store.mjs','run-preparation.sql','run-generation-denial.mjs','run-generation-denial.sql','execution-run-fence.mjs','execution-run-fence.sql','run-protection-exits.mjs',
 'run-approval-protection-completion.mjs','run-approval-protection-completion.sql'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['process-host.mjs', await fs.readFile(path.join(root, 'src/process-host.mjs'))]);
files.push(['worker-bootstrap.mjs', await fs.readFile(path.join(root, 'src/worker-bootstrap.mjs'))]);
for (const name of ['worker-launch-store.mjs','worker-launch.sql','worker-runtime-store.mjs','worker-runtime.sql','worker-dependencies.mjs','worker-dependencies.sql','extension-plan-store.mjs','extension-plan.sql','extension-activation-store.mjs','extension-activation.sql','worker-authorization-store.mjs','worker-authorization.sql']) files.push([name,await fs.readFile(path.join(root,'src',name))]);
for (const name of ['extension-installation-store.mjs','extension-installation.sql']) files.push([name,await fs.readFile(path.join(root,'src',name))]);
for (const name of ['configuration-validator.mjs','configuration-worker.mjs','configuration-schema.mjs']) files.push([name,await fs.readFile(path.join(root,'src',name))]);
for (const name of ['extension-configuration-store.mjs','extension-configuration.sql','extension-role-store.mjs','extension-role-resolution.mjs','extension-role.sql','extension-review-store.mjs','extension-review-permissions.mjs','extension-review.sql','extension-approval-store.mjs','extension-approval.sql','extension-capabilities.mjs','extension-capabilities.sql','extension-approval-state.mjs','extension-launch-binding.mjs','launch-content.mjs']) files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['device-worker-entry.mjs',await fs.readFile(path.join(root,'src/device-worker-entry.mjs'))]);
files.push(['device-execution-channel.mjs',await fs.readFile(path.join(root,'src/device-execution-channel.mjs'))]);
for(const name of ['command-record-store.mjs','command-record.sql','command-lifecycle.mjs','command-lifecycle.sql','command-encoding-source.mjs','command-encoding-store.mjs','command-encoding.sql','command-final-admission.sql','command-final-admission.mjs','command-guard.mjs','command-guard.sql','command-dispatch.mjs','command-dispatch.sql','command-settlement.mjs','command-settlement.sql','command-preparation-cleanup.mjs','command-preparation-cleanup.sql','command-retired-history.mjs','device-resource-successor.sql','control-command-cut.mjs','control-command-cut.sql'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['execution-read-view.mjs',await fs.readFile(path.join(root,'src/execution-read-view.mjs'))]);
files.push(['device-capability-view.mjs',await fs.readFile(path.join(root,'src/device-capability-view.mjs'))]);
files.push(['verified-document-cache.mjs',await fs.readFile(path.join(root,'src/verified-document-cache.mjs'))]);
files.push(['execution-qualification-watch.mjs',await fs.readFile(path.join(root,'src/execution-qualification-watch.mjs'))]);
files.push(['sqlite-rows.mjs',await fs.readFile(path.join(root,'src/sqlite-rows.mjs'))]);
files.push(['device-execution-client.mjs',await fs.readFile(path.join(root,'src/device-execution-client.mjs'))]);
for(const name of ['device-execution-journal.mjs','device-execution.sql','device-execution-frames.mjs','device-execution-frames.sql','device-execution-binding.mjs','device-execution-binding.sql','device-execution-handshake.sql','device-execution-handshake.mjs','device-execution-control.mjs','device-execution-control.sql','device-control-source.sql','device-control-source.mjs','device-manual-authority.mjs','device-manual-authority.sql','device-authorization-state.mjs','device-authorization-state.sql','core-runtime-source.mjs','core-runtime-source.sql','service-identity-store.mjs','service-identity.sql','service-access-token-store.mjs','service-access-token.sql','device-evaluator-source.mjs','device-evaluator-source.sql','authentication-window.mjs','service-principal-revocation.sql','authorization-dependencies.mjs','device-authorization-recovery.mjs','device-authorization-recovery.sql','device-authorization-consumption.sql','device-manual-challenge.sql','device-authorization-evidence.mjs','device-authorization-evidence.sql','device-initial-resource.mjs','device-initial-resource.sql','device-initial-denials.mjs','device-initial-open.mjs','device-initial-open.sql','device-worker-binding.sql','device-worker-execution.mjs','device-execution-open.mjs','device-execution-open.sql','device-initial-ready.mjs','device-initial-ready.sql'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
files.push(['device-packet-preparation.mjs',await fs.readFile(path.join(root,'src/device-packet-preparation.mjs'))]);
files.push(['device-transmission-writer.mjs',await fs.readFile(path.join(root,'src/device-transmission-writer.mjs'))]);
files.push(['device-execution-gate.mjs',await fs.readFile(path.join(root,'src/device-execution-gate.mjs'))]);
files.push(['device-authorization-fence.mjs',await fs.readFile(path.join(root,'src/device-authorization-fence.mjs'))]);
files.push(['device-worker-session.mjs',await fs.readFile(path.join(root,'src/device-worker-session.mjs'))]);
for(const name of ['simulator-control-module.mjs','simulator-control-policy.json','simulator-control-capability.json'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['obs-discovery.mjs','obs-cut-packet.mjs','obs-device-module.mjs','obs-cut-device-module.mjs','obs-cut-module-policy.json','obs-cut-module-capability.json','obs-cut-execution.sql','obs-cut-initial-resource.sql','obs-cut-command.sql','obs-resource.mjs','obs-resource.sql','device-resource-ownership.sql','obs-scene-confirmation.mjs','obs-scene-confirmation.sql','secret-store.mjs',
 'obs-module-profile.mjs','obs-module-policy.json','obs-module-capability.json','windows-secret-files.mjs'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
for(const name of ['device-module-channel.mjs','device-module-client.mjs','device-module-host.mjs','device-module-store.mjs','device-module.sql','device-catalog.sql','device-control.sql','device-control-value.mjs','device-control-repository.mjs','device-control-store.mjs','device-control-barrier.mjs','device-catalog-store.mjs','simulator-module.mjs','simulator-policy.json'])files.push([name,await fs.readFile(path.join(root,'src',name))]);
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
      host.time_provider_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-time-provider.h'))) ||
      host.journal_time_provider_sha256 !== hash(await fs.readFile(path.join(root, 'native/process-journal-time-provider.sql'))) ||
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
  if (referenceTimeProvider !== null) {
    const provider = await fs.readFile(referenceTimeProvider);
    if (provider.length < 64 || provider.length > 16777216 || provider.toString('ascii',0,2) !== 'MZ') throw new Error('time_provider_artifact');
    // Win32 GUI subsystem keeps the inherited pipes without adding a console process to the provider Job.
    const pe = provider.readUInt32LE(60), optionalHeader = pe + 24;
    if (pe < 64 || optionalHeader + 70 > provider.length || provider.readUInt32LE(pe) !== 0x4550 ||
        provider.readUInt16LE(pe + 4) !== 0x8664 || provider.readUInt16LE(pe + 20) < 70 ||
        provider.readUInt16LE(optionalHeader) !== 0x20b || provider.readUInt16LE(optionalHeader + 68) !== 2) throw new Error('time_provider_artifact');
    files.push(['runtime/reference-time-provider.exe', provider]);
  }
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
