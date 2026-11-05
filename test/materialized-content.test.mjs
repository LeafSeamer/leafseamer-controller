import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {openMaterializedContent} from '../dist/materialized-content.mjs';
import {pinLaunchContent} from '../dist/launch-content.mjs';

const windows = {skip: process.platform !== 'win32'};
const hash = value => 'sha256:' + crypto.createHash('sha256').update(value).digest('hex');
function fixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-content-'));
  const root = path.join(base, '内容'); fs.mkdirSync(root); const pins = [];
  t.after(() => {
    for (const pin of pins) pin.close();
    assert.equal(path.dirname(path.resolve(base)), path.resolve(os.tmpdir())); fs.rmSync(base, {recursive: true, force: true});
  });
  const inventory = {inventory_version: 'extension-files/1', files: []};
  function add(relative, bytes = Buffer.from('export const value = 1;\n')) {
    fs.mkdirSync(path.dirname(path.join(root, relative)), {recursive: true}); fs.writeFileSync(path.join(root, relative), bytes);
    const file = {file_id: 'file-' + inventory.files.length, path: relative, size_bytes: String(bytes.length), digest: hash(bytes), role: 'module', executable: false};
    inventory.files.push(file); return file;
  }
  const source = openMaterializedContent();
  return {root, base, inventory, add, source, pin(input = inventory) { const pin = source.pin(root, input); pins.push(pin); return pin; }};
}

test('固定加载worker独立持有文件锁，核验与关闭可等待且错根身份不留下锁',windows,async t=>{
  const f=fixture(t);f.add('main.mjs');const observed=f.pin(),identity=observed.rootIdentity;observed.close();
  const file=path.join(f.root,'main.mjs');
  await assert.rejects(pinLaunchContent(f.root,f.inventory,'0'.repeat(48)),{code:'content_root_identity'});
  // 失败回复时线程可能仍在退出；pinLaunchContent须在拒绝之前完成释放。
  const writer=fs.openSync(file,'r+');fs.closeSync(writer);
  const held=await pinLaunchContent(f.root,f.inventory,identity);
  try{held.assertHeld();assert.throws(()=>fs.writeFileSync(file,'replacement'));await held.verify();
    const pending=held.verify();await assert.rejects(async()=>held.verify(),{code:'content_verify_pending'});await pending;
  }finally{assert.equal((await held.close()).status,'closed');}
  assert.throws(()=>held.assertHeld(),{code:'content_pin_closed'});fs.writeFileSync(file,'released');
});
test('真实内容句柄核对摘要，并在持有期间阻止跨进程写入、替换及祖先重命名', windows, t => {
  const f = fixture(t); f.add('worker/main.mjs'); f.add('resources/data.bin', Buffer.alloc(1024 * 1024, 7));
  const pinned = f.pin(); assert.match(pinned.rootIdentity, /^[0-9a-f]{48}$/); pinned.verify();
  assert.equal(Object.isFrozen(pinned), true);
  const target = path.join(f.root, 'worker/main.mjs');
  assert.equal(fs.readFileSync(target, 'utf8'), 'export const value = 1;\n');
  const child = spawnSync(process.execPath, ['--input-type=module', '-e',
    "import fs from 'node:fs'; import assert from 'node:assert/strict'; assert.throws(() => fs.writeFileSync(process.argv[1], 'changed')); assert.throws(() => fs.renameSync(process.argv[1], process.argv[1] + '.old'));", target],
  {encoding: 'utf8', windowsHide: true, timeout: 10000});
  assert.equal(child.error, undefined); assert.equal(child.status, 0, child.stderr);
  assert.throws(() => fs.renameSync(f.root, f.root + '-moved'));
  assert.throws(() => fs.renameSync(f.base, f.base + '-moved'));
  pinned.verify(); pinned.close(); pinned.close(); assert.throws(() => pinned.verify(), {code: 'content_pin_closed'});
  fs.writeFileSync(target, 'now writable');
});
test('摘要、大小、缺项、额外文件或目录失败均不留下文件锁', windows, t => {
  const f = fixture(t); f.add('main.mjs');
  for (const patch of [{digest: hash('other')}, {size_bytes: '999'}, {path: 'missing.mjs'}]) {
    const inventory = structuredClone(f.inventory); Object.assign(inventory.files[0], patch);
    assert.throws(() => f.pin(inventory));
    const fd = fs.openSync(path.join(f.root, 'main.mjs'), 'r+'); fs.closeSync(fd);
  }
  fs.writeFileSync(path.join(f.root, 'unlisted'), 'x'); assert.throws(() => f.pin(), {code: 'content_inventory_mismatch'});
  fs.unlinkSync(path.join(f.root, 'unlisted')); fs.mkdirSync(path.join(f.root, 'empty'));
  assert.throws(() => f.pin(), {code: 'content_inventory_mismatch'}); fs.rmdirSync(path.join(f.root, 'empty'));
  const writer = fs.openSync(path.join(f.root, 'main.mjs'), 'r+');
  try { assert.throws(() => f.pin(), {code: 'content_file_open'}); } finally { fs.closeSync(writer); }
  f.pin().verify();
});
test('句柄核验发现目录变化后永久关闭，恢复目录不能复用旧证明', windows, t => {
  const f = fixture(t); f.add('main.mjs'); const pin = f.pin();
  fs.writeFileSync(path.join(f.root, 'added'), 'x');
  assert.throws(() => pin.verify(), {code: 'content_inventory_mismatch'}); fs.unlinkSync(path.join(f.root, 'added'));
  assert.throws(() => pin.verify(), {code: 'content_pin_closed'});
  f.pin().verify();
});
test('拒绝硬链接、目录联接和额外数据流', windows, t => {
  const f = fixture(t); f.add('worker/main.mjs'); const target = path.join(f.root, 'worker/main.mjs');
  const link = path.join(f.base, 'alias.mjs'); fs.linkSync(target, link);
  assert.throws(() => f.pin(), {code: 'content_hardlink'}); fs.unlinkSync(link);
  fs.writeFileSync(target + ':hidden', 'x');
  assert.throws(() => f.pin(), {code: 'content_alternate_stream'}); fs.unlinkSync(target + ':hidden');
  for (const directory of [f.root, path.join(f.root, 'worker')]) {
    fs.writeFileSync(directory + ':hidden', 'x'); assert.throws(() => f.pin(), {code: 'content_alternate_stream'}); fs.unlinkSync(directory + ':hidden');
  }
  fs.symlinkSync(path.join(f.root, 'worker'), path.join(f.root, 'alias'), 'junction');
  const aliasInventory = structuredClone(f.inventory); aliasInventory.files[0].path = 'alias/main.mjs';
  assert.throws(() => f.pin(aliasInventory), {code: 'content_file_type'});
  fs.unlinkSync(path.join(f.root, 'alias'));
  const aliasRoot = path.join(f.base, 'root-alias'); fs.symlinkSync(f.root, aliasRoot, 'junction');
  assert.throws(() => f.source.pin(aliasRoot, f.inventory), {code: 'content_file_type'});
  fs.unlinkSync(aliasRoot); f.pin().verify();
});
test('库存校验拒绝路径别名、保留名、非规范Unicode和越界输入', windows, t => {
  const f = fixture(t); f.add('main.mjs');
  for (const relative of ['../main.mjs', '/main.mjs', 'a//main.mjs', 'a/./main.mjs', 'a\\main.mjs', 'main.mjs:stream', 'main.mjs.', 'main.mjs ',
    'CON', 'con.txt', 'COM1.mjs', 'LPT².txt', 'a\0b', 'e\u0301.mjs', '\ud800.mjs', '数据.bin', 'extension.json', 'files.json', 'EXTENSION.JSON', 'Files.Json']) {
    const inventory = structuredClone(f.inventory); inventory.files[0].path = relative; assert.throws(() => f.pin(inventory), undefined, relative);
  }
  const duplicate = structuredClone(f.inventory); duplicate.files.push({...duplicate.files[0], file_id: 'other', path: 'MAIN.MJS'});
  assert.throws(() => f.pin(duplicate), {code: 'content_path_collision'});
  for (const patch of [{size_bytes: '268435457'}, {size_bytes: '01'}, {size_bytes: '18446744073709551615'}, {digest: hash('x') + '\n'}, {file_id: 'x\n'}, {role: 'unknown'}, {extra: true}]) {
    const inventory = structuredClone(f.inventory); Object.assign(inventory.files[0], patch); assert.throws(() => f.pin(inventory));
  }
  for (const timeoutMs of [0, 5001, 1.5, NaN, Infinity]) assert.throws(() => f.source.pin(f.root, f.inventory, {timeoutMs}), {code: 'content_timeout_argument'});
  f.pin().verify();
});
test('原生令牌不可从属性、原型或克隆伪造，关闭后不能恢复', windows, t => {
  const f = fixture(t); f.add('main.mjs');
  const native = createRequire(import.meta.url)('../dist/native/leafseamer_materialization.node');
  const token = native.pin(f.root, f.inventory.files, 5000);
  try {
    for (const fake of [{}, Object.create(token), structuredClone(token), 1, null]) assert.throws(() => native.verify(fake, 5000));
    native.verify(token, 5000); assert.equal(Object.isFrozen(token), true);
  } finally { native.close(token); }
  assert.throws(() => native.verify(token, 5000), {code: 'content_pin_closed'});
});
