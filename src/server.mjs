import http from 'node:http';
import {openStorage} from './storage.mjs';
import {openNativeClock} from './native-clock.mjs';
import {startClockMonitor} from './clock-monitor.mjs';
import {startAuthenticationClock} from './auth-clock.mjs';

export async function startController({dataDir, host = '127.0.0.1', port = 0} = {}) {
  if (!['127.0.0.1', '::1'].includes(host) || !Number.isInteger(port) || port < 0 || port > 65535) throw new Error('listen_options');
  const storage = openStorage(dataDir);
  let clock = null, authentication = null;
  if (storage.clockJournal) {
    try {
      const source = openNativeClock();
      clock = startClockMonitor(source, storage.clockJournal);
      // 可信安装/监督提供者未接通；不从普通配置自报环境批准。
      if (storage.authenticationClock) authentication = startAuthenticationClock(source, storage.authenticationClock);
      if (Number(storage.identity.schema_revision) >= 5 && authentication) storage.sessions(authentication);
    }
    catch {
      try { storage.clockJournal.fault('native_clock_unavailable'); }
      catch (error) { storage.close(); throw error; }
      clock = {status: () => ({state: 'faulted', qualified: false}), stop() {}};
    }
  }
  const server = http.createServer({maxHeaderSize: 16384, requestTimeout: 5000, headersTimeout: 5000,
    keepAliveTimeout: 1000}, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // 启动阶段没有写接口。拒收带正文请求并关闭连接，不排队读入无界数据。
    if (req.headers['transfer-encoding'] !== undefined || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) {
      res.writeHead(413, {Connection: 'close'}); res.end(); return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405, {Allow: 'GET, HEAD'}); res.end(); return; }
    let status, body;
    if (req.url === '/health/live') { status = 200; body = {status: 'alive'}; }
    else if (req.url === '/health/ready') {
      status = 503; body = {ready: false, reason: clock ? (clock.status().state === 'faulted' ? 'authentication_clock_unavailable' : 'authentication_clock_unqualified') : 'bootstrap_incomplete'};
    }
    else if (req.url === '/.well-known/leafseamer-contracts') { res.writeHead(503); res.end(); return; }
    else { res.writeHead(404); res.end(); return; }
    const bytes = Buffer.from(JSON.stringify(body));
    res.writeHead(status, {'Content-Type': 'application/json', 'Content-Length': String(bytes.length)});
    res.end(req.method === 'HEAD' ? undefined : bytes);
  });
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
