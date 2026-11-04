import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import https from 'node:https';
import Database from 'better-sqlite3';
import {createBrowserSessionClient, contractSelection as selection} from '@leafseamer/sdk';
import {initializeStorage, migrateStorage, openStorage} from '../dist/storage.mjs';
import {startController} from '../dist/server.mjs';
import {certificate, supervisedFixture, browserFetch} from './https-auth-fixture.mjs';

const material = certificate(), login = {login: 'synthetic-https-admin', password: 'synthetic-https-password-012345'};
async function setup(t, qualified = true) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-https-')); let app;
  t.after(async () => { await app?.close(); assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); });
  initializeStorage(dir); await migrateStorage(dir);
  const storage = openStorage(dir); let enrolled;
  try { const capability = storage.enrollment.begin(); enrolled = await storage.enrollment.complete({...login, mode: 'standalone', token_id: capability.token_id, secret: capability.secret}); }
  finally { storage.close(); }
  const reservation = net.createServer(); await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port; await new Promise(resolve => reservation.close(resolve));
  const origin = 'https://127.0.0.1:' + port, trust = supervisedFixture();
  app = await startController({dataDir: dir, port, tls: {...material, origin}, authenticationProvider: qualified ? trust.provider : null});
  const browser = browserFetch(material.cert), client = createBrowserSessionClient({baseUrl: origin, fetchImpl: browser.fetchImpl});
  const send = (method, route, body, headers = {}) => browser.fetchImpl(origin + route, {method, credentials: 'same-origin',
    headers: new Headers({'X-LeafSeamer-Contract': selection.contract_id, 'X-LeafSeamer-Contract-Digest': selection.contract_digest,
      ...(body === undefined ? {} : {'Content-Type': 'application/json'}), Origin: origin, ...headers}),
    body: body === undefined ? undefined : Buffer.from(JSON.stringify(body))});
  return {app, dir, origin, trust, browser, client, send, enrolled};
}

test('实际Controller原生采样加HTTPS：SDK登录、刷新、定向token和会话读取闭环', {timeout: 15000}, async t => {
  const a = await setup(t);
  const logged = await a.client.login(login);
  assert.equal(logged.status, '201'); assert.equal(logged.body.data.principal_id, a.enrolled.principal_id);
  assert(logged.body.data.permissions.includes('auth.manage')); assert(!JSON.stringify(logged.body).includes(login.password));
  const firstCookie = a.browser.state.cookie;
  assert.match(a.browser.state.cookies[0], /; Path=\/auth; Secure; HttpOnly; SameSite=Strict$/);
  assert(!a.browser.state.cookies[0].includes('Domain=')); assert.equal(logged.headers['x-csrf-token'], undefined);
  const first = await a.client.issueToken({audience: a.app.identity.service_id, requested_scopes: ['session.read']});
  assert.equal(first.status, '201'); assert(first.body.data.expires_in >= 1 && first.body.data.expires_in <= 60);
  const current = await a.client.current(); assert.equal(current.status, '200'); assert.equal(current.body.data.session_id, logged.body.data.session_id);
  const refreshed = await a.client.refresh('synthetic-browser'); assert.equal(refreshed.status, '200');
  assert.equal(refreshed.body.data.session_id, logged.body.data.session_id); assert.notEqual(a.browser.state.cookie, firstCookie);
  await assert.rejects(a.client.current(), e => e.code === 'session_credentials_missing');
  const renewed = await a.client.issueToken({audience: a.app.identity.service_id, requested_scopes: ['session.read']}); assert.equal(renewed.status, '201');
  assert.equal((await a.client.current()).status, '200');
  assert.equal((await a.send('GET', '/health/ready')).status, 503);
  const ready = await (await a.send('GET', '/health/ready')).json(); assert.equal(ready.reason, 'business_incomplete');
  await assert.rejects(new Promise((resolve, reject) => https.get(a.origin + '/health/live', {agent: false}, resolve).on('error', reject)), /certificate/i);
});

test('精确Origin与Host、CSRF和Cookie唯一性均在身份操作前验证', {timeout: 15000}, async t => {
  const a = await setup(t);
  for (const origin of ['https://other.invalid', a.origin + '/']) assert.equal((await a.send('POST', '/auth/sessions', login, {Origin: origin})).status, 403);
  assert.equal((await a.send('POST', '/auth/sessions', login, {Origin: 'null'})).status, 400);
  // 证书也覆盖localhost，使请求通过TLS后确实命中应用的精确Host检查。
  assert.equal((await a.send('POST', '/auth/sessions', login, {Host: 'localhost'})).status, 403);
  assert.equal((await a.client.login(login)).status, '201');
  const cookie = a.browser.state.cookie;
  assert.equal((await a.send('POST', '/auth/sessions/refresh', {client_instance_id: 'browser'}, {'X-CSRF-Token': 'A'.repeat(43)})).status, 401);
  a.browser.state.cookie = cookie + '; ' + cookie;
  assert.equal((await a.send('POST', '/auth/sessions/refresh', {client_instance_id: 'browser'}, {'X-CSRF-Token': 'A'.repeat(43)})).status, 401);
  await a.app.close();
  const db = new Database(path.join(a.dir, 'controller.sqlite'), {fileMustExist: true});
  try { assert.equal(db.prepare('SELECT count(*) FROM auth_session').pluck().get(), 1); assert.equal(db.prepare("SELECT count(*) FROM session_refresh_credential WHERE state = 'active'").pluck().get(), 1); }
  finally { db.close(); }
});

test('SDK禁止并发刷新，旧Cookie正确复用撤销该session全部token', {timeout: 15000}, async t => {
  const a = await setup(t); await a.client.login(login);
  const oldCookie = a.browser.state.cookie;
  const issued = await a.client.issueToken({audience: a.app.identity.service_id, requested_scopes: ['session.read']});
  const csrf = a.browser.state.requests.at(-1).headers['x-csrf-token'];
  const first = a.client.refresh('browser');
  await assert.rejects(a.client.refresh('browser'), e => e.code === 'session_busy');
  assert.equal((await first).status, '200');
  a.browser.state.cookie = oldCookie;
  assert.equal((await a.send('POST', '/auth/sessions/refresh', {client_instance_id: 'browser'}, {'X-CSRF-Token': csrf})).status, 401);
  assert.equal(a.browser.state.cookie, null);
  assert.equal((await a.send('GET', '/api/v1/session', undefined, {Authorization: 'Bearer ' + issued.body.data.access_token})).status, 401);
});

test('可信来源失效和缺失均不交付身份成功，TLS证书本身不授认证资格', {timeout: 15000}, async t => {
  const a = await setup(t); await a.client.login(login); a.trust.state.failed = true;
  const failed = await a.client.issueToken({audience: a.app.identity.service_id, requested_scopes: ['session.read']});
  assert.equal(failed.status, '503'); assert.equal(failed.body.error.code, 'CLOCK_UNTRUSTED');
  const b = await setup(t, false);
  const missing = await b.client.login(login); assert.equal(missing.status, '503'); assert.equal(missing.body.error.code, 'CLOCK_UNTRUSTED');
  assert.equal(b.browser.state.cookie, null);
});

test('清除内存凭据后，迟到登录响应不能重新安装CSRF或token', {timeout: 15000}, async t => {
  const a = await setup(t); let release, delivered;
  const waiting = new Promise(resolve => { delivered = resolve; });
  a.browser.state.held = resume => { release = resume; delivered(); };
  const pending = a.client.login(login); await waiting;
  a.client.clearLocalState(); release();
  await assert.rejects(pending, e => e.code === 'session_state_changed');
  await assert.rejects(a.client.refresh('browser'), e => e.code === 'session_credentials_missing');
  assert.equal(a.browser.state.requests.length, 1);
});

test('HTTPS注销只撤当前会话并返回真实固定目标，旧Cookie和token不能继续使用', {timeout: 15000}, async t => {
  const a = await setup(t); const logged = await a.client.login(login);
  const issued = await a.client.issueToken({audience: a.app.identity.service_id, requested_scopes: ['session.read']});
  const oldCookie = a.browser.state.cookie, csrf = a.browser.state.requests.at(-1).headers['x-csrf-token'];
  const bad = await a.send('DELETE', '/auth/sessions/current', {session_id: 'another-session'}, {'X-CSRF-Token': csrf});
  assert.equal(bad.status, 400); assert.equal((await a.client.current()).status, '200');
  const result = await a.client.logout(); assert.equal(result.status, '202');
  const {operation_ref: ref, propagation: record} = result.body.data;
  assert.equal(ref.authority_service_id, a.app.identity.service_id); assert.equal(ref.database_instance_id, a.app.identity.database_instance_id);
  assert.equal(record.selector.target_id, logged.body.data.session_id); assert.equal(record.selector.revision_floor, '2');
  assert.deepEqual(record.target_service_ids, [a.app.identity.service_id]); assert.equal(record.state, 'accepted'); assert.deepEqual(record.receipts, []);
  assert.equal(a.browser.state.cookie, null); assert.match(a.browser.state.cookies.at(-1), /Max-Age=0$/);
  const count = a.browser.state.requests.length;
  await assert.rejects(a.client.current(), e => e.code === 'session_credentials_missing');
  await assert.rejects(a.client.refresh('browser'), e => e.code === 'session_credentials_missing');
  assert.equal(a.browser.state.requests.length, count);
  assert.equal((await a.send('GET', '/api/v1/session', undefined, {Authorization: 'Bearer ' + issued.body.data.access_token})).status, 401);
  a.browser.state.cookie = oldCookie;
  assert.equal((await a.send('DELETE', '/auth/sessions/current', undefined, {'X-CSRF-Token': csrf})).status, 401);
  assert.equal(a.browser.state.cookie, null);
  await a.app.close();
  const db = new Database(path.join(a.dir, 'controller.sqlite'), {fileMustExist: true});
  try {
    const [id, floor, tx] = db.prepare('SELECT operation_id, revision_floor, tx_id FROM session_revocation').raw().get();
    assert.equal(id, ref.id); assert.equal(tx, record.audit_id); assert.equal(floor, 2);
    assert.equal(db.prepare('SELECT count(*) FROM session_revocation_outbox').pluck().get(), 1);
    assert.equal(db.prepare("SELECT count(*) FROM session_revocation_target WHERE state = 'pending'").pluck().get(), 1);
    assert.equal(db.prepare("SELECT count(*) FROM access_token WHERE state = 'active'").pluck().get(), 0);
  } finally { db.close(); }
});

test('注销来源失信返回503并清SDK内存，不伪报本地或传播完成', {timeout: 15000}, async t => {
  const a = await setup(t); await a.client.login(login); a.trust.state.failed = true;
  const result = await a.client.logout(); assert.equal(result.status, '503'); assert.equal(result.body.error.code, 'CLOCK_UNTRUSTED');
  await assert.rejects(a.client.refresh('browser'), e => e.code === 'session_credentials_missing');
  await a.app.close();
  const db = new Database(path.join(a.dir, 'controller.sqlite'), {fileMustExist: true});
  try { assert.equal(db.prepare('SELECT count(*) FROM session_revocation').pluck().get(), 0); }
  finally { db.close(); }
});
