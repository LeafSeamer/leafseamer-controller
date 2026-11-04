import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {contractSelection} from './sdk/index.mjs';

const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
const sameSelection = value => exact(value, 'contract_digest,contract_id') && value.contract_id === contractSelection.contract_id && value.contract_digest === contractSelection.contract_digest;
const types = {'.html': 'text/html; charset=utf-8', '.json': 'application/json', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.txt': 'text/plain; charset=utf-8'};
const csp = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

// 本地可信装配输入；启动时核验并固定字节，HTTP请求不能选择目录或改写站点身份。
export function loadGuiAssets(directory, identity, origin) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.origin !== origin || typeof directory !== 'string' || !path.isAbsolute(directory)) throw new Error('gui_options');
  const read = (name, limit) => {
    const file = path.join(directory, name), stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > limit) throw new Error('gui_artifact_size');
    const bytes = fs.readFileSync(file); if (bytes.length > limit) throw new Error('gui_artifact_size'); return bytes;
  };
  const manifest = JSON.parse(read('gui-manifest.json', 65536));
  if (!exact(manifest, 'artifacts,format,sdk_manifest_sha256,selection') || manifest.format !== 'leafseamer.gui.build/1' || !sameSelection(manifest.selection) ||
      !/^[a-f0-9]{64}$/.test(manifest.sdk_manifest_sha256) || !manifest.artifacts || typeof manifest.artifacts !== 'object' || Array.isArray(manifest.artifacts)) throw new Error('gui_manifest');
  if (manifest.sdk_manifest_sha256 !== hash(fs.readFileSync(new URL('./sdk/build-manifest.json', import.meta.url)))) throw new Error('gui_sdk_drift');
  const entries = Object.entries(manifest.artifacts), assets = new Map(); let total = 0;
  if (entries.length < 4 || entries.length > 128) throw new Error('gui_artifact_count');
  for (const [name, expected] of entries) {
    if (!/^(index\.html|site\.json|SDK-LICENSE\.txt|THIRD-PARTY-LICENSES\.txt|assets\/[A-Za-z0-9_-]+\.(js|css))$/.test(name) || !/^[a-f0-9]{64}$/.test(expected)) throw new Error('gui_artifact_path');
    const bytes = read(name, name === 'site.json' ? 4096 : 16 * 1024 * 1024);
    total += bytes.length; if (total > 32 * 1024 * 1024 || hash(bytes) !== expected) throw new Error('gui_artifact_drift');
    assets.set('/' + name, {bytes, type: types[path.extname(name)]});
  }
  if (!assets.has('/index.html') || !assets.has('/site.json') || !assets.has('/SDK-LICENSE.txt') || !entries.some(([n]) => n.endsWith('.js')) || !entries.some(([n]) => n.endsWith('.css'))) throw new Error('gui_artifact_missing');
  const site = JSON.parse(assets.get('/site.json').bytes);
  if (!exact(site, 'database_instance_id,format,selection,service_id,site_label') || site.format !== 'leafseamer.gui.site/1' || !sameSelection(site.selection) ||
      site.service_id !== identity.service_id || site.database_instance_id !== identity.database_instance_id || typeof site.site_label !== 'string' ||
      site.site_label.length < 1 || site.site_label.length > 120 || /[\u0000-\u001f\u007f]/.test(site.site_label)) throw new Error('gui_site_scope');
  return Object.freeze({handle(req, res) {
    const asset = assets.get(req.url === '/' ? '/index.html' : req.url); if (!asset) return false;
    if (req.headers.host !== url.host || req.headers.origin !== undefined && req.headers.origin !== origin) { res.writeHead(403); res.end(); return true; }
    res.writeHead(200, {'Content-Type': asset.type, 'Content-Length': String(asset.bytes.length), 'Content-Security-Policy': csp,
      'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer'});
    res.end(req.method === 'HEAD' ? undefined : asset.bytes); return true;
  }});
}
