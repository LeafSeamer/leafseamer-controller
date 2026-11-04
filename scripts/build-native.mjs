import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2), options = {};
if (args.length % 2) throw new Error('native_build_arguments');
for (let i = 0; i < args.length; i += 2) {
  if (!['--headers', '--node-library'].includes(args[i]) || Object.hasOwn(options, args[i]) || !path.isAbsolute(args[i + 1])) throw new Error('native_build_arguments');
  options[args[i]] = args[i + 1];
}
if (!['win32', 'linux'].includes(process.platform) || process.arch !== 'x64') throw new Error('native_build_platform');
const lock = JSON.parse(fs.readFileSync(path.join(root, 'native-inputs.json'), 'utf8'));
if (process.versions.node !== lock.node_version || !options['--headers']) throw new Error('native_build_inputs');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
for (const [name, digest] of Object.entries(lock.headers)) if (hash(fs.readFileSync(path.join(options['--headers'], name))) !== digest) throw new Error('native_headers_mismatch');
if (process.platform === 'win32' && (!options['--node-library'] || hash(fs.readFileSync(options['--node-library'])) !== lock.windows_x64_node_lib)) throw new Error('native_library_mismatch');
const output = path.join(root, 'logs/native-clock/build', process.platform + '-' + process.arch);
const artifact = path.join(root, 'logs/native-clock/artifacts', process.platform + '-' + process.arch);
function run(args) {
  const result = spawnSync('cmake', args, {cwd: root, stdio: 'inherit', windowsHide: true});
  if (result.error || result.status !== 0) throw new Error('native_build_failed');
}
const configure = ['-S', path.join(root, 'native'), '-B', output, '-DCMAKE_BUILD_TYPE=Release', '-DNODE_INCLUDE_DIR=' + options['--headers']];
if (process.platform === 'win32') configure.push('-G', 'Visual Studio 17 2022', '-A', 'x64', '-DNODE_LIBRARY=' + options['--node-library']);
run(configure); run(['--build', output, '--config', 'Release']);
const binary = fs.readFileSync(path.join(output, process.platform === 'win32' ? 'Release' : '', 'leafseamer_clock.node'));
fs.mkdirSync(artifact, {recursive: true});
fs.writeFileSync(path.join(artifact, 'leafseamer_clock.node'), binary);
fs.writeFileSync(path.join(artifact, 'manifest.json'), JSON.stringify({format: 'leafseamer-native-artifact/1', platform: process.platform, arch: process.arch,
  node_version: lock.node_version, napi_version: lock.napi_version, binary_sha256: hash(binary),
  inputs_sha256: hash(fs.readFileSync(path.join(root, 'native-inputs.json'))),
  source_sha256: hash(fs.readFileSync(path.join(root, 'native/clock.cc'))),
  cmake_source_sha256: hash(fs.readFileSync(path.join(root, 'native/CMakeLists.txt'))),
  compiler: JSON.parse(fs.readFileSync(path.join(output, 'compiler.json'), 'utf8'))}, null, 2) + '\n');
console.log(JSON.stringify({native_artifact: process.platform + '-' + process.arch, sha256: hash(binary)}));
