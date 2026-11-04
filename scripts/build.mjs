import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const names = ['cli.mjs', 'server.mjs', 'storage.mjs', 'storage.sql', 'identity.sql', 'identity-crypto.mjs', 'identity-store.mjs', 'local-admin.mjs'];
const files = await Promise.all(names.map(async name => [name, await fs.readFile(path.join(root, 'src', name))]));
const output = path.resolve(root, 'dist');
if (path.dirname(output) !== path.resolve(root)) throw new Error('output_path');
await fs.rm(output, {recursive: true, force: true}); await fs.mkdir(output);
for (const [name, bytes] of files) await fs.writeFile(path.join(output, name), bytes);
await fs.chmod(path.join(output, 'cli.mjs'), 0o755);
await fs.writeFile(path.join(output, 'build-manifest.json'), JSON.stringify({format: 'leafseamer-controller-build/1',
  artifacts: Object.fromEntries(files.map(([n, b]) => [n, crypto.createHash('sha256').update(b).digest('hex')]))}, null, 2) + '\n');
console.log(JSON.stringify({artifacts: files.length, mode: 'protected'}));
