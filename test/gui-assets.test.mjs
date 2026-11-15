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
test('新版固定Seamer配置只扩展connect-src，拒绝通配和配置混用',t=>{
 const f=fixture(t),seamer={service_id:crypto.randomUUID(),database_instance_id:crypto.randomUUID(),service_label:'Seamer',base_url:'https://127.0.0.1:4443'};
 f.files['site.json']=JSON.stringify({...f.site,format:'leafseamer.gui.site/2',seamer});f.save();
 const csp=send(f.load()).headers['Content-Security-Policy'];assert.match(csp,/connect-src 'self' https:\/\/127\.0\.0\.1:4443;/);assert.match(csp,/script-src 'self';/);
 for(const base_url of ['https://*.invalid','https://127.0.0.1:4443/?target=other','http://127.0.0.1:4443','https://user:secret@other.invalid']){
  f.files['site.json']=JSON.stringify({...f.site,format:'leafseamer.gui.site/2',seamer:{...seamer,base_url}});f.save();assert.throws(f.load);
 }
 f.files['site.json']=JSON.stringify({...f.site,seamer});f.save();assert.throws(f.load,/gui_site_scope/);
});

test('绑定来源配置固定设备白名单，拒绝重复、额外字段和旧版混入',t=>{
 const f=fixture(t),source={binding_id:crypto.randomUUID(),devices:[{device_id:crypto.randomUUID(),label:'模拟器'}]},seamer={service_id:crypto.randomUUID(),database_instance_id:crypto.randomUUID(),service_label:'Seamer',base_url:'https://127.0.0.1:4443',binding_source:source};
 const save=(s=seamer,format='leafseamer.gui.site/3')=>{f.files['site.json']=JSON.stringify({...f.site,format,seamer:s});f.save();};
 save();assert.equal(send(f.load(),'/site.json').status,200);
 for(const binding_source of [{...source,devices:[]},{...source,devices:[...source.devices,...source.devices]},{...source,devices:[{...source.devices[0],label:'bad\nlabel'}]},{...source,extra:true}]){save({...seamer,binding_source});assert.throws(f.load,/gui_binding_source/);}
 save(seamer,'leafseamer.gui.site/2');assert.throws(f.load,/gui_seamer_scope/);
 const devices=Array.from({length:64},()=>({device_id:crypto.randomUUID(),label:'设备'.repeat(60)}));save({...seamer,binding_source:{...source,devices}});assert.ok(Buffer.byteLength(f.files['site.json'])>4096);assert.equal(send(f.load(),'/site.json').status,200);
});
