import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {contractSelection} from '../dist/sdk/index.mjs';
import {loadGuiAssets} from '../dist/gui-assets.mjs';
import {startController} from '../dist/server.mjs';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-assets-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); fs.rmSync(root, {recursive: true, force: true}); });
  const identity = {service_id: crypto.randomUUID(), database_instance_id: crypto.randomUUID()};
  const site = {format: 'leafseamer.gui.site/1', site_label: '测试', ...identity, selection: contractSelection};
  const files = {'index.html': '<!doctype html><title>Test</title>', 'site.json': JSON.stringify(site), 'SDK-LICENSE.txt': 'Test', 'assets/app.js': 'export{};', 'assets/app.css': 'body{margin:0}'};
  const manifest = {format: 'leafseamer.gui.build/1', selection: contractSelection,
    sdk_manifest_sha256: hash(fs.readFileSync(new URL('../dist/sdk/build-manifest.json', import.meta.url))), artifacts: {}};
  const save = () => { for (const [name, content] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, name)), {recursive: true}); fs.writeFileSync(path.join(root, name), content); manifest.artifacts[name] = hash(content); }
    fs.writeFileSync(path.join(root, 'gui-manifest.json'), JSON.stringify(manifest)); };
  save(); return {root, identity, site, files, manifest, save, load: () => loadGuiAssets(root, identity, 'https://127.0.0.1:3443')};
}
function send(assets, url = '/', method = 'GET', headers = {host: '127.0.0.1:3443'}) {
  const result = {}; result.handled = assets.handle({url, method, headers}, {writeHead(status, headers) { result.status = status; result.headers = headers; }, end(body) { result.body = body; }}); return result;
}
test('静态资源固定字节、HEAD与CSP，不覆盖API或提供路径回退', t => {
  const f = fixture(t), assets = f.load(); fs.writeFileSync(path.join(f.root, 'index.html'), 'changed');
  const response = send(assets); assert.equal(response.status, 200); assert.equal(response.body.toString(), f.files['index.html']);
  assert.match(response.headers['Content-Security-Policy'], /frame-ancestors 'none'/); assert(!response.headers['Content-Security-Policy'].includes('unsafe'));
  assert.equal(send(assets, '/', 'HEAD').body, undefined);
  for (const url of ['/auth/sessions', '/health/ready', '/../index.html', '/assets/../site.json', '/?x=1', '/gui-manifest.json']) assert.equal(send(assets, url).handled, false);
  assert.equal(send(assets, '/', 'GET', {host: 'other.invalid'}).status, 403);
  assert.equal(send(assets, '/', 'GET', {host: '127.0.0.1:3443', origin: 'https://other.invalid'}).status, 403);
});
test('摘要漂移、跨库站点、未知资源与SDK版本均拒绝启动', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.root, 'assets/app.js'), 'changed'); assert.throws(f.load, /gui_artifact_drift/); f.save();
  f.site.database_instance_id = crypto.randomUUID(); f.files['site.json'] = JSON.stringify(f.site); f.save(); assert.throws(f.load, /gui_site_scope/);
  f.site.database_instance_id = f.identity.database_instance_id; f.files['site.json'] = JSON.stringify(f.site); f.save();
  f.manifest.artifacts['auth/sessions'] = '0'.repeat(64); f.save(); assert.throws(f.load, /gui_artifact_path/); delete f.manifest.artifacts['auth/sessions'];
  f.manifest.sdk_manifest_sha256 = '0'.repeat(64); f.save(); assert.throws(f.load, /gui_sdk_drift/);
});
test('GUI不允许装配到明文HTTP服务', async () => {
  await assert.rejects(startController({guiDirectory: path.resolve('dist')}), /gui_requires_https/);
});
