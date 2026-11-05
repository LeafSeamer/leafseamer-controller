import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

export class ContentError extends Error {
  constructor(code) { super(code); this.name = 'ContentError'; this.code = code; }
}
const need = (value, code) => { if (!value) throw new ContentError(code); };
const fields = (value, keys) => {
  need(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys.sort().join(','), 'content_inventory');
};
const roles = new Set(['module', 'native_helper', 'panel', 'schema', 'license', 'dependency_lock', 'resource', 'policy']);
const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value) && !value.endsWith('\n');
function inventoryFiles(inventory) {
  fields(inventory, ['inventory_version', 'files']);
  need(inventory.inventory_version === 'extension-files/1' && Array.isArray(inventory.files) && inventory.files.length > 0 && inventory.files.length <= 65536, 'content_inventory');
  let previousId = '', total = 0n;
  return inventory.files.map(file => {
    fields(file, ['file_id', 'path', 'size_bytes', 'digest', 'role', 'executable']);
    need(id(file.file_id) && file.file_id > previousId && roles.has(file.role) && typeof file.executable === 'boolean', 'content_inventory'); previousId = file.file_id;
    need(typeof file.path === 'string' && file.path.length > 0 && file.path.length <= 240 && file.path.isWellFormed() && file.path === file.path.normalize('NFC'), 'content_path');
    need(typeof file.size_bytes === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(file.size_bytes) && file.size_bytes.trim() === file.size_bytes, 'content_size');
    const size = BigInt(file.size_bytes); total += size;
    need(size <= 268435456n && total <= 1073741824n, 'content_capacity');
    need(typeof file.digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(file.digest) && file.digest.length === 71, 'content_digest');
    return {path: file.path, size_bytes: file.size_bytes, digest: file.digest};
  });
}
function budget(value) { need(Number.isInteger(value) && value > 0 && value <= 5000, 'content_timeout_argument'); return value; }
function translate(error) {
  if (error instanceof ContentError) return error;
  return new ContentError(typeof error?.code === 'string' && /^content_[a-z_]+$/.test(error.code) ? error.code : 'content_unavailable');
}
// 仅提供库存字节与文件句柄；不产生发行信任、安装批准或启动凭据。
export function openMaterializedContent() {
  try {
    need(process.platform === 'win32' && process.arch === 'x64', 'content_platform');
    const manifest = JSON.parse(fs.readFileSync(new URL('./native/materialization-manifest.json', import.meta.url), 'utf8'));
    const filename = fileURLToPath(new URL('./native/leafseamer_materialization.node', import.meta.url));
    const digest = crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
    need(manifest.format === 'leafseamer-materialization-artifact/1' && manifest.platform === process.platform && manifest.arch === process.arch &&
      manifest.napi_version === 8 && manifest.binary_sha256 === digest, 'content_artifact');
    const native = createRequire(import.meta.url)(filename);
    return Object.freeze({artifactDigest: 'sha256:' + digest, pin(root, inventory, {timeoutMs = 5000} = {}) {
      let token;
      try {
        need(typeof root === 'string' && root.isWellFormed(), 'content_root_path');
        const start = process.hrtime.bigint(); const allowance = budget(timeoutMs);
        const files = inventoryFiles(inventory);
        const remaining = allowance - Number((process.hrtime.bigint() - start) / 1000000n);
        need(remaining > 0, 'content_timeout');
        token = native.pin(root, files, remaining);
        need(process.hrtime.bigint() - start < BigInt(allowance) * 1000000n, 'content_timeout');
        const description = native.describe(token); let closed = false;
        return Object.freeze({rootIdentity: description.rootIdentity,
          verify({timeoutMs: verifyMs = 5000} = {}) {
            need(!closed, 'content_pin_closed');
            try { native.verify(token, budget(verifyMs)); }
            catch (error) { closed = true; native.close(token); throw translate(error); }
          },
          close() { if (!closed) { closed = true; native.close(token); } }
        });
      } catch (error) { if (token) native.close(token); throw translate(error); }
    }});
  } catch (error) { throw translate(error); }
}
