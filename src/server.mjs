import http from 'node:http';
import https from 'node:https';
import {openStorage} from './storage.mjs';
import {openNativeClock} from './native-clock.mjs';
import {startClockMonitor} from './clock-monitor.mjs';
import {startAuthenticationClock} from './auth-clock.mjs';
import {createAuthenticationHttp} from './auth-http.mjs';
import {loadGuiAssets} from './gui-assets.mjs';
import {startPeerPairingTransport} from './peer-pairing-transport.mjs';
import {createSubscriptionEndpoint} from './service-subscription-http.mjs';
import {createIntrospectionEndpoint} from './introspection-http.mjs';
import {pairingUuid} from './peer-pairing-value.mjs';

export async function startController({dataDir, host = '127.0.0.1', port = 0, tls = null, authenticationProvider = null, guiDirectory = null, coreBootstrap = null, pairing = null} = {}) {
  if (!['127.0.0.1', '::1'].includes(host) || !Number.isInteger(port) || port < 0 || port > 65535) throw new Error('listen_options');
  if (authenticationProvider !== null && typeof authenticationProvider !== 'function') throw new Error('authentication_provider');
  if (tls !== null && (!tls || Object.keys(tls).sort().join(',') !== 'cert,key,origin' || typeof tls.origin !== 'string')) throw new Error('tls_options');
  if (guiDirectory !== null && tls === null) throw new Error('gui_requires_https');
  if (pairing !== null) pairingUuid(pairing.credential_id);
  const storage = openStorage(dataDir);
  let supervision = null;
  try {
    if (coreBootstrap !== null) {
      if (typeof coreBootstrap !== 'function' || Number(storage.identity.schema_revision) < 11) throw new Error('core_runtime_migration_required');
      const result = await coreBootstrap(storage.identity), {binding, policy} = result;
      supervision = result.supervision ?? null; supervision?.assertCurrent();
      storage.bindCoreRuntime(binding, policy);
      if(supervision)storage.workerLaunches?.runtime?.bindSource(supervision);
      if(supervision)storage.extensionInstallations?.bindRuntimeSource?.(supervision);
      if(supervision)storage.workerLaunches?.authorization?.bindSource(supervision);
      supervision?.assertCurrent();
    }
  } catch (error) { try { storage.close(); } finally { supervision?.close(); } throw error; }
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
      catch (error) { try { storage.close(); } finally { supervision?.close(); } throw error; }
      clock = {status: () => ({state: 'faulted', qualified: false}), stop() {}};
    }
  }
  let server, peerTransport = null;
  const closeHttp = () => !server?.listening ? Promise.resolve() : new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve()); server.closeAllConnections();
  });
  const cleanup = async () => {
    const results = await Promise.allSettled([closeHttp(), peerTransport?.close()]);
    for (const stop of [() => clock?.stop(), () => authentication?.stop(), () => storage.close(), () => supervision?.close()]) {
      try { stop(); } catch (reason) { results.push({status: 'rejected', reason}); }
    }
    const failed = results.find(result => result.status === 'rejected'); if (failed) throw failed.reason;
  };
  try {
    const gui = guiDirectory === null ? null : loadGuiAssets(guiDirectory, storage.identity, tls.origin);
    const authenticationHttp = createAuthenticationHttp({serviceId: storage.identity.service_id, databaseInstanceId: storage.identity.database_instance_id,
      serviceBootId: storage.serviceBootId, sessions, origin: tls?.origin ?? null});
    const options = {maxHeaderSize: 16384, requestTimeout: 5000, headersTimeout: 5000, keepAliveTimeout: 1000};
    const listener = (req, res) => {
    try { supervision?.assertCurrent(); } catch { res.writeHead(503, {'Cache-Control': 'no-store', Connection: 'close'}); res.end(); return; }
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (authenticationHttp.handle(req, res)) return;
    // 其它启动端点仍不接收正文。
    if (req.headers['transfer-encoding'] !== undefined || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) {
      res.writeHead(413, {Connection: 'close'}); res.end(); return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405, {Allow: 'GET, HEAD'}); res.end(); return; }
    if (gui?.handle(req, res)) return;
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
  } catch (error) { await cleanup().catch(() => {}); throw error; }
  server.maxRequestsPerSocket = 100;
  server.on('clientError', (_error, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  try {
    supervision?.assertCurrent(); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }); supervision?.assertCurrent();
    if (pairing !== null) {
      const issuer = storage.enrollment?.summary();
      if (!issuer?.initialized || !sessions?.peerPairings || !sessions?.sessionDenials || !authentication?.status().qualified) throw new Error('pairing_runtime_unavailable');
      const identity = {service_id: storage.identity.service_id, database_instance_id: storage.identity.database_instance_id, service_kind: 'controller',
        issuer_id: issuer.issuer_id, issuer_epoch: issuer.issuer_epoch, credential_id: pairing.credential_id};
      const introspection = createIntrospectionEndpoint({sessions, serviceId: storage.identity.service_id, serviceBootId: storage.serviceBootId});
      peerTransport = await startPeerPairingTransport({pairings: sessions.peerPairings,
        clock: {pairingSample() { supervision?.assertCurrent(); return authentication.pairingSample(); }}, identity,
        cert: pairing.cert, key: pairing.key, ca: pairing.ca, host: pairing.host ?? '127.0.0.1', port: pairing.port ?? 0,
        serverName: pairing.serverName ?? pairing.host ?? '127.0.0.1', sessionDenials: sessions.sessionDenials,
        deviceBindings(device,reference) { supervision?.assertCurrent(); return storage.workerLaunches.deviceAutomation(device,reference); },
        deviceEvents(device,reference,after,limit) { supervision?.assertCurrent(); return storage.workerLaunches.deviceEvents(device,reference,after,limit); },
        subscriptions:sessions.serviceSubscriptions?createSubscriptionEndpoint({store:sessions.serviceSubscriptions}):null,
        async introspection(request) {
          supervision?.assertCurrent(); const response = await introspection(request);
          return {...response, beforeSend() { supervision?.assertCurrent(); response.beforeSend(); }};
        }});
      if (pairing.peers !== undefined) peerTransport.bindPeers(pairing.peers);
      supervision?.assertCurrent();
    }
  } catch (error) { await cleanup().catch(() => {}); throw error; }
  let stopping;
  const application = Object.freeze({address: server.address(), identity: storage.identity, serviceBootId: storage.serviceBootId,
    authenticationStatus: () => authentication?.status() ?? null,
    pairing: peerTransport ? Object.freeze({api: sessions.peerPairings, transport: peerTransport, remotePermissions: sessions.remotePermissions, sessionDenials: sessions.sessionDenials}) : null,
    close() {
      stopping ??= cleanup();
      return stopping;
    }});
  supervision?.onLost(() => { void application.close().catch(() => {}); });
  return application;
}
