import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2), options = {};
if (args.length % 2) throw new Error('native_build_arguments');
for (let i = 0; i < args.length; i += 2) {
  const [name, value] = args.slice(i, i + 2);
  const valid = name === '--windows-generator' ? process.platform === 'win32' && value === 'NMake Makefiles' :
    ['--headers', '--node-library'].includes(name) && path.isAbsolute(value);
  if (!valid || Object.hasOwn(options, name)) throw new Error('native_build_arguments');
  options[name] = value;
}
if (!['win32', 'linux'].includes(process.platform) || process.arch !== 'x64') throw new Error('native_build_platform');
const lock = JSON.parse(fs.readFileSync(path.join(root, 'native-inputs.json'), 'utf8'));
if (process.versions.node !== lock.node_version || !options['--headers']) throw new Error('native_build_inputs');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
for (const [name, digest] of Object.entries(lock.headers)) if (hash(fs.readFileSync(path.join(options['--headers'], name))) !== digest) throw new Error('native_headers_mismatch');
if (process.platform === 'win32' && (!options['--node-library'] || hash(fs.readFileSync(options['--node-library'])) !== lock.windows_x64_node_lib)) throw new Error('native_library_mismatch');
const sqliteSource = path.join(root, 'node_modules/better-sqlite3/deps/sqlite3');
if (process.platform === 'win32') for (const [name, digest] of Object.entries(lock.sqlite_sources)) {
  if (hash(fs.readFileSync(path.join(sqliteSource, name))) !== digest) throw new Error('native_sqlite_mismatch');
}
const output = path.join(root, 'logs/native-clock/build', process.platform + '-' + process.arch);
const artifact = path.join(root, 'logs/native-clock/artifacts', process.platform + '-' + process.arch);
function run(args) {
  const result = spawnSync('cmake', args, {cwd: root, stdio: 'inherit', windowsHide: true});
  if (result.error) throw new Error('native_cmake_unavailable', {cause: result.error});
  if (result.status !== 0) throw new Error('native_build_failed');
}
const configure = ['--fresh', '-S', path.join(root, 'native'), '-B', output, '-DCMAKE_BUILD_TYPE=Release', '-DNODE_INCLUDE_DIR=' + options['--headers']];
const visualStudio = process.platform === 'win32' && !options['--windows-generator'];
if (process.platform === 'win32') {
  configure.push('-G', options['--windows-generator'] ?? 'Visual Studio 17 2022');
  if (visualStudio) configure.push('-A', 'x64');
  configure.push('-DNODE_LIBRARY=' + options['--node-library'], '-DSQLITE_SOURCE_DIR=' + sqliteSource);
}
run(configure); run(['--build', output, '--config', 'Release']);
const built = name => fs.readFileSync(path.join(output, visualStudio ? 'Release' : '', name));
const binary = built('leafseamer_clock.node');
fs.mkdirSync(artifact, {recursive: true});
fs.writeFileSync(path.join(artifact, 'leafseamer_clock.node'), binary);
fs.writeFileSync(path.join(artifact, 'manifest.json'), JSON.stringify({format: 'leafseamer-native-artifact/1', platform: process.platform, arch: process.arch,
  node_version: lock.node_version, napi_version: lock.napi_version, binary_sha256: hash(binary),
  inputs_sha256: hash(fs.readFileSync(path.join(root, 'native-inputs.json'))),
  source_sha256: hash(fs.readFileSync(path.join(root, 'native/clock.cc'))),
  cmake_source_sha256: hash(fs.readFileSync(path.join(root, 'native/CMakeLists.txt'))),
  compiler: JSON.parse(fs.readFileSync(path.join(output, 'compiler.json'), 'utf8'))}, null, 2) + '\n');
console.log(JSON.stringify({native_artifact: process.platform + '-' + process.arch, sha256: hash(binary)}));
if (process.platform === 'win32') {
  const materialization = built('leafseamer_materialization.node');
  fs.writeFileSync(path.join(artifact, 'leafseamer_materialization.node'), materialization);
  fs.writeFileSync(path.join(artifact, 'materialization-manifest.json'), JSON.stringify({format: 'leafseamer-materialization-artifact/1',
    platform: process.platform, arch: process.arch, node_version: lock.node_version, napi_version: lock.napi_version,
    binary_sha256: hash(materialization), source_sha256: hash(fs.readFileSync(path.join(root, 'native/materialization.cc'))),
    content_source_sha256: hash(fs.readFileSync(path.join(root, 'native/content-root.h'))),
    inputs_sha256: hash(fs.readFileSync(path.join(root, 'native-inputs.json'))),
    cmake_source_sha256: hash(fs.readFileSync(path.join(root, 'native/CMakeLists.txt')))}, null, 2) + '\n');
  const host = built('leafseamer_process_host.exe');
  fs.writeFileSync(path.join(artifact, 'leafseamer_process_host.exe'), host);
  fs.writeFileSync(path.join(artifact, 'process-host-manifest.json'), JSON.stringify({format: 'leafseamer-process-host/1',
    platform: process.platform, arch: process.arch, binary_sha256: hash(host),
    source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-host.cc'))),
    time_provider_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-time-provider.h'))),
    journal_time_provider_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-time-provider.sql'))),
    journal_recovery_startup_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-recovery-startup.sql'))),
    worker_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-worker.h'))),
    creation_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-creation.h'))),
    module_link_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-module-link.h'))),
    journal_creation_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-creation.sql'))),
    journal_v4_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-v4.sql'))),
    runtime_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-runtime.h'))),
    loading_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-loading.h'))),
    content_source_sha256: hash(fs.readFileSync(path.join(root, 'native/content-root.h'))),
    installation_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-installation.h'))),
    control_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-control.h'))),
    bootstrap_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-bootstrap.h'))),
    journal_v2_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-v2.sql'))),
    journal_v3_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-v3.sql'))),
    journal_retirement_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-retirement.sql'))),
    journal_fence_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-fence.sql'))),
    journal_v1_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-v1.sql'))),
    journal_upgrade_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal-upgrade.sql'))),
    journal_source_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal.h'))),
    journal_sql_sha256: hash(fs.readFileSync(path.join(root, 'native/process-journal.sql'))),
    inputs_sha256: hash(fs.readFileSync(path.join(root, 'native-inputs.json'))),
    cmake_source_sha256: hash(fs.readFileSync(path.join(root, 'native/CMakeLists.txt')))}, null, 2) + '\n');
}
