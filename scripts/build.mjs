import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const names = ['cli.mjs', 'server.mjs', 'storage.mjs', 'storage.sql', 'identity.sql', 'identity-crypto.mjs', 'identity-store.mjs', 'local-admin.mjs', 'native-clock.mjs', 'clock-monitor.mjs', 'clock.sql'];
const files = await Promise.all(names.map(async name => [name, await fs.readFile(path.join(root, 'src', name))]));
const nativeDir = path.join(root, 'logs/native-clock/artifacts', process.platform + '-' + process.arch);
const nativeManifest = await fs.readFile(path.join(nativeDir, 'manifest.json'));
const native = JSON.parse(nativeManifest), binary = await fs.readFile(path.join(nativeDir, 'leafseamer_clock.node'));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
if (native.platform !== process.platform || native.arch !== process.arch || native.binary_sha256 !== hash(binary) ||
    native.source_sha256 !== hash(await fs.readFile(path.join(root, 'native/clock.cc'))) ||
    native.cmake_source_sha256 !== hash(await fs.readFile(path.join(root, 'native/CMakeLists.txt'))) ||
    native.inputs_sha256 !== hash(await fs.readFile(path.join(root, 'native-inputs.json')))) throw new Error('native_build_drift');
files.push(['native/leafseamer_clock.node', binary], ['native/manifest.json', nativeManifest]);
const output = path.resolve(root, 'dist');
if (path.dirname(output) !== path.resolve(root)) throw new Error('output_path');
await fs.rm(output, {recursive: true, force: true}); await fs.mkdir(path.join(output, 'native'), {recursive: true});
for (const [name, bytes] of files) await fs.writeFile(path.join(output, name), bytes);
await fs.chmod(path.join(output, 'cli.mjs'), 0o755);
await fs.writeFile(path.join(output, 'build-manifest.json'), JSON.stringify({format: 'leafseamer-controller-build/1',
  artifacts: Object.fromEntries(files.map(([n, b]) => [n, crypto.createHash('sha256').update(b).digest('hex')]))}, null, 2) + '\n');
console.log(JSON.stringify({artifacts: files.length, mode: 'protected'}));
