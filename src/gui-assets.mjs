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
export function loadGuiAssets(directory, identity, origin, {manifestSha256 = null, seamerIdentity = null} = {}) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.origin !== origin || typeof directory !== 'string' || !path.isAbsolute(directory)) throw new Error('gui_options');
  const read = (name, limit) => {
    const file = path.join(directory, name), stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > limit) throw new Error('gui_artifact_size');
    const bytes = fs.readFileSync(file); if (bytes.length > limit) throw new Error('gui_artifact_size'); return bytes;
  };
  const manifestBytes = read('gui-manifest.json', 65536);
  if (manifestSha256 !== null && manifestSha256 !== 'sha256:' + hash(manifestBytes)) throw new Error('gui_manifest_drift');
  const manifest = JSON.parse(manifestBytes);
  if (!exact(manifest, 'artifacts,format,sdk_manifest_sha256,selection') || manifest.format !== 'leafseamer.gui.build/1' || !sameSelection(manifest.selection) ||
      !/^[a-f0-9]{64}$/.test(manifest.sdk_manifest_sha256) || !manifest.artifacts || typeof manifest.artifacts !== 'object' || Array.isArray(manifest.artifacts)) throw new Error('gui_manifest');
  if (manifest.sdk_manifest_sha256 !== hash(fs.readFileSync(new URL('./sdk/build-manifest.json', import.meta.url)))) throw new Error('gui_sdk_drift');
  const entries = Object.entries(manifest.artifacts), assets = new Map(); let total = 0;
  if (entries.length < 4 || entries.length > 128) throw new Error('gui_artifact_count');
  for (const [name, expected] of entries) {
    if (!/^(index\.html|site\.json|SDK-LICENSE\.txt|THIRD-PARTY-LICENSES\.txt|assets\/[A-Za-z0-9_-]+\.(js|css))$/.test(name) || !/^[a-f0-9]{64}$/.test(expected)) throw new Error('gui_artifact_path');
    const bytes = read(name, name === 'site.json' ? 32768 : 16 * 1024 * 1024);
    total += bytes.length; if (total > 32 * 1024 * 1024 || hash(bytes) !== expected) throw new Error('gui_artifact_drift');
    assets.set('/' + name, {bytes, type: types[path.extname(name)]});
  }
  if (!assets.has('/index.html') || !assets.has('/site.json') || !assets.has('/SDK-LICENSE.txt') || !entries.some(([n]) => n.endsWith('.js')) || !entries.some(([n]) => n.endsWith('.css'))) throw new Error('gui_artifact_missing');
  const site = JSON.parse(assets.get('/site.json').bytes);
  const v3=site.format==='leafseamer.gui.site/3',v2=v3||site.format==='leafseamer.gui.site/2';
  if(!v3&&assets.get('/site.json').bytes.length>4096)throw new Error('gui_artifact_size');
  if (!exact(site, v2?'database_instance_id,format,seamer,selection,service_id,site_label':'database_instance_id,format,selection,service_id,site_label') || !['leafseamer.gui.site/1','leafseamer.gui.site/2','leafseamer.gui.site/3'].includes(site.format) || !sameSelection(site.selection) ||
      site.service_id !== identity.service_id || site.database_instance_id !== identity.database_instance_id || typeof site.site_label !== 'string' ||
      site.site_label.length < 1 || site.site_label.length > 120 || /[\u0000-\u001f\u007f]/.test(site.site_label)) throw new Error('gui_site_scope');
  let policy=csp;
  if(v2&&site.seamer!==null){
    const s=site.seamer,uuid=v=>typeof v==='string'&&v.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
    if(!exact(s,v3?'base_url,binding_source,database_instance_id,service_id,service_label':'base_url,database_instance_id,service_id,service_label')||!uuid(s.service_id)||!uuid(s.database_instance_id)||s.service_id===identity.service_id||typeof s.service_label!=='string'||s.service_label.length<1||s.service_label.length>120||/[\u0000-\u001f\u007f]/.test(s.service_label)||typeof s.base_url!=='string'||s.base_url.length>1024)throw new Error('gui_seamer_scope');
    if(seamerIdentity!==null&&(s.service_id!==seamerIdentity.service_id||s.database_instance_id!==seamerIdentity.database_instance_id))throw new Error('gui_seamer_scope');
    if(v3&&s.binding_source!==null){const b=s.binding_source;if(!exact(b,'binding_id,devices')||!uuid(b.binding_id)||!Array.isArray(b.devices)||b.devices.length<1||b.devices.length>64||b.devices.some(d=>!exact(d,'device_id,label')||!uuid(d.device_id)||typeof d.label!=='string'||d.label.length<1||d.label.length>120||/[\u0000-\u001f\u007f]/.test(d.label))||new Set(b.devices.map(d=>d.device_id)).size!==b.devices.length)throw new Error('gui_binding_source');}
    const remote=new URL(s.base_url),prefix=remote.pathname==='/'?'':remote.pathname;
    if(!/^https:\/\/(?:\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::[0-9]+)?$/.test(remote.origin)||remote.username||remote.password||remote.search||remote.hash||
       !(prefix===''||/^\/services\/[A-Za-z0-9_-]+$/.test(prefix))||s.base_url!==remote.origin+prefix)throw new Error('gui_seamer_scope');
    if(remote.origin!==origin)policy=csp.replace("connect-src 'self'", "connect-src 'self' "+remote.origin);
  }
  return Object.freeze({handle(req, res) {
    const asset = assets.get(req.url === '/' ? '/index.html' : req.url); if (!asset) return false;
    if (req.headers.host !== url.host || req.headers.origin !== undefined && req.headers.origin !== origin) { res.writeHead(403); res.end(); return true; }
    res.writeHead(200, {'Content-Type': asset.type, 'Content-Length': String(asset.bytes.length), 'Content-Security-Policy': policy,
      'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer'});
    res.end(req.method === 'HEAD' ? undefined : asset.bytes); return true;
  }});
}
