import http from 'node:http';
import https from 'node:https';
import {openStorage} from './storage.mjs';
import {openNativeClock} from './native-clock.mjs';
import {startClockMonitor} from './clock-monitor.mjs';
import {startAuthenticationClock} from './auth-clock.mjs';
import {createAuthenticationHttp} from './auth-http.mjs';

export async function startController({dataDir, host = '127.0.0.1', port = 0, tls = null, authenticationProvider = null} = {}) {
  if (!['127.0.0.1', '::1'].includes(host) || !Number.isInteger(port) || port < 0 || port > 65535) throw new Error('listen_options');
  if (authenticationProvider !== null && typeof authenticationProvider !== 'function') throw new Error('authentication_provider');
  if (tls !== null && (!tls || Object.keys(tls).sort().join(',') !== 'cert,key,origin' || typeof tls.origin !== 'string')) throw new Error('tls_options');
  const storage = openStorage(dataDir);
  let clock = null, authentication = null, sessions = null;
  if (storage.clockJournal) {
    try {
      const source = openNativeClock();
      clock = startClockMonitor(source, storage.clockJournal);
      // 本地监督装配点；普通CLI、HTTP和环境变量不能提供批准正文或替换原生source。
      if (storage.authenticationClock) authentication = startAuthenticationClock(source, storage.authenticationClock,
        authenticationProvider?.(Object.freeze({scope: storage.authenticationClock.scope, source})) ?? null);
      if (Number(storage.identity.schema_revision) >= 5 && authentication) sessions = storage.sessions(authentication);
    }
    catch {
      clock?.stop(); authentication?.stop(); sessions = null;
      try { storage.clockJournal.fault('native_clock_unavailable'); }
      catch (error) { storage.close(); throw error; }
      clock = {status: () => ({state: 'faulted', qualified: false}), stop() {}};
    }
  }
  let server;
  try {
    const authenticationHttp = createAuthenticationHttp({serviceId: storage.identity.service_id, databaseInstanceId: storage.identity.database_instance_id,
      serviceBootId: storage.serviceBootId, sessions, origin: tls?.origin ?? null});
    const options = {maxHeaderSize: 16384, requestTimeout: 5000, headersTimeout: 5000, keepAliveTimeout: 1000};
    const listener = (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (authenticationHttp.handle(req, res)) return;
    // 其它启动端点仍不接收正文。
    if (req.headers['transfer-encoding'] !== undefined || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) {
      res.writeHead(413, {Connection: 'close'}); res.end(); return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405, {Allow: 'GET, HEAD'}); res.end(); return; }
    let status, body;
    if (req.url === '/health/live') { status = 200; body = {status: 'alive'}; }
    else if (req.url === '/health/ready') {
      status = 503; body = {ready: false, reason: authentication?.status().qualified ? 'business_incomplete' : clock ? (clock.status().state === 'faulted' ? 'authentication_clock_unavailable' : 'authentication_clock_unqualified') : 'bootstrap_incomplete'};
    }
    else if (req.url === '/.well-known/leafseamer-contracts') { res.writeHead(503); res.end(); return; }
    else { res.writeHead(404); res.end(); return; }
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, {'Content-Type': 'application/json', 'Content-Length': String(bytes.length)});
    res.end(req.method === 'HEAD' ? undefined : bytes);
    };
    server = tls ? https.createServer({...options, key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3'}, listener) : http.createServer(options, listener);
  } catch (error) { clock?.stop(); authentication?.stop(); storage.close(); throw error; }
  server.maxRequestsPerSocket = 100;
  server.on('clientError', (_error, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }); }
  catch (error) { clock?.stop(); authentication?.stop(); storage.close(); throw error; }
  let stopping;
  return Object.freeze({address: server.address(), identity: storage.identity, serviceBootId: storage.serviceBootId,
    close() {
      if (!stopping) stopping = new Promise((resolve, reject) => {
        server.close(error => { try { clock?.stop(); authentication?.stop(); storage.close(); if (error) reject(error); else resolve(); } catch (e) { reject(e); } });
        server.closeAllConnections();
      });
      return stopping;
    }});
}
