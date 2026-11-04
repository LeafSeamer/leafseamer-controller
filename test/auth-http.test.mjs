import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {createClient, createFetchTransport, contractSelection as selection} from '@leafseamer/sdk';
import {initializeStorage, migrateStorage} from '../dist/storage.mjs';
import {startController} from '../dist/server.mjs';

const headers = {'Content-Type': 'application/json', Origin: 'https://controller.invalid',
  'X-LeafSeamer-Contract': selection.contract_id, 'X-LeafSeamer-Contract-Digest': selection.contract_digest};
async function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-http-'));
  let server;
  t.after(async () => { await server?.close(); assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  initializeStorage(dir); await migrateStorage(dir);
  server = await startController({dataDir: dir});
  return {server, baseUrl: 'http://127.0.0.1:' + server.address.port};
}
function send(baseUrl, body, overrides = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(baseUrl + '/auth/sessions', {method: 'POST', headers: {...headers, ...overrides}}, res => {
      let text = ''; res.setEncoding('utf8').on('data', x => { text += x; });
      res.on('end', () => resolve({status: res.statusCode, headers: res.headers, text}));
    });
    req.on('error', reject); req.end(body);
  });
}

test('SDK经真实HTTP取得身份保护态响应，不发Cookie或伪造会话', async t => {
  const {server, baseUrl} = await setup(t);
  const client = createClient('controller', selection, createFetchTransport({authority: 'controller', baseUrl, allowInsecureLoopback: true}));
  const response = await client.call('login', {headers: {origin: 'https://controller.invalid'}, body: {login: 'operator', password: 'password-long-enough'}});
  assert.equal(response.status, '503'); assert.equal(response.body.error.code, 'WORKER_NOT_READY');
  assert.equal(response.body.service_id, server.identity.service_id); assert.equal(response.body.service_boot_id, server.serviceBootId);
  assert.equal(response.body.error.retry_advice, 'do_not_retry'); assert.equal(response.authorization_granted, false);
  const refresh = await client.call('refreshSession', {headers: {origin: 'https://controller.invalid'}, body: {client_instance_id: 'client'}});
  assert.equal(refresh.status, '503');
  const token = await client.call('issueToken', {headers: {origin: 'https://controller.invalid'}, body: {audience: 'audience', requested_scopes: ['read'], extension_instance_id: null}});
  assert.equal(token.status, '503');
  const current = await client.call('getSession'); assert.equal(current.status, '503');
  const raw = await send(baseUrl, JSON.stringify({login: 'operator', password: 'password-long-enough'}));
  assert.equal(raw.headers['set-cookie'], undefined); assert.equal(raw.headers['x-csrf-token'], undefined);
  assert.equal(raw.headers['cache-control'], 'no-store');
  assert.equal((await fetch(baseUrl + '/.well-known/leafseamer-contracts')).status, 503);
  assert.equal((await fetch(baseUrl + '/health/ready')).status, 503);
});

test('身份入口拒绝错误选择、畸形JSON和未知写字段', async t => {
  const {baseUrl} = await setup(t);
  for (const body of ['{}', '{"login":"a","login":"b","password":"password-long-enough"}',
    JSON.stringify({login: 'operator', password: 'password-long-enough', permissions: ['administrator']}), Buffer.from([0xff])]) {
    const response = await send(baseUrl, body);
    assert.equal(response.status, 400); assert.equal(JSON.parse(response.text).error.code, 'INVALID_REQUEST');
    assert(!response.text.includes('password-long-enough'));
  }
  const badSelection = await send(baseUrl, '{}', {'X-LeafSeamer-Contract-Digest': 'sha256:' + '0'.repeat(64)});
  assert.equal(badSelection.status, 400); assert.equal(badSelection.text, '');
  assert.equal(badSelection.headers['x-leafseamer-contract'], undefined);
  const duplicate = await send(baseUrl, '{}', {'X-CSRF-Token': ['first', 'second']});
  assert.equal(duplicate.status, 400); assert.equal(duplicate.text, '');
});

test('身份正文声明与分块累计均有界，失败后健康入口继续可用', async t => {
  const {baseUrl} = await setup(t);
  for (const extra of [{'Content-Length': '16385'}, {'Transfer-Encoding': 'chunked'}]) {
    const response = await send(baseUrl, 'x'.repeat(16385), extra);
    assert.equal(response.status, 413); assert.equal(JSON.parse(response.text).error.code, 'PAYLOAD_TOO_LARGE');
  }
  assert.equal((await fetch(baseUrl + '/health/live')).status, 200);
});

test('慢正文有绝对接收期限，不占用永久容量', {timeout: 10000}, async t => {
  const {server, baseUrl} = await setup(t);
  const response = await new Promise((resolve, reject) => {
    const socket = net.connect(server.address.port, '127.0.0.1'); let text = '';
    t.after(() => socket.destroy()); socket.setTimeout(5000, () => socket.destroy(new Error('test_deadline')));
    socket.once('connect', () => socket.write('POST /auth/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n' +
      Object.entries(headers).map(([k, v]) => k + ': ' + v + '\r\n').join('') + 'Content-Length: 100\r\n\r\n{'));
    socket.setEncoding('utf8').on('data', x => { text += x; }); socket.once('error', reject); socket.once('end', () => resolve(text));
  });
  assert.match(response, /^HTTP\/1.1 408 /);
  assert.equal((await send(baseUrl, '{}')).status, 400);
});

test('同时接收额度耗尽时拒绝新正文，断连归还额度', {timeout: 10000}, async t => {
  const {server, baseUrl} = await setup(t);
  const sockets = [];
  t.after(() => sockets.forEach(s => s.destroy()));
  await Promise.all(Array.from({length: 16}, () => new Promise((resolve, reject) => {
    const socket = net.connect(server.address.port, '127.0.0.1'); sockets.push(socket);
    socket.on('error', reject);
    socket.once('connect', () => socket.write('POST /auth/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n' +
      Object.entries(headers).map(([k, v]) => k + ': ' + v + '\r\n').join('') + 'Content-Length: 100\r\n\r\n{', resolve));
  })));
  let response;
  for (let i = 0; i < 25; i++) {
    response = await send(baseUrl, '{}'); if (response.status === 429) break;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.equal(response.status, 429); assert.equal(JSON.parse(response.text).error.code, 'CAPACITY_EXCEEDED');
  sockets.forEach(s => s.destroy());
  for (let i = 0; i < 25; i++) {
    response = await send(baseUrl, '{}'); if (response.status === 400) break;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.equal(response.status, 400);
});
