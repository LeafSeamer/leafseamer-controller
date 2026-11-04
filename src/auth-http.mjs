import crypto from 'node:crypto';
import {createHttpAdapter} from './sdk/http.mjs';
import {contractSelection as selection} from './sdk/index.mjs';

const routes = new Map([
  ['/auth/sessions', 'POST'], ['/auth/sessions/refresh', 'POST'],
  ['/auth/service-tokens', 'POST'], ['/api/v1/session', 'GET'],
]);
const maximumBody = 16384, maximumPending = 16, bodyDeadline = 2000;
const rawPairs = flat => Array.from({length: flat.length / 2}, (_, i) => [flat[2 * i], flat[2 * i + 1]]);

// 保护态身份入口。成功身份投影、可信来源和受控TLS尚未装配，不调用会话写服务。
export function createAuthenticationHttp({serviceId, serviceBootId}) {
  const adapter = createHttpAdapter(selection);
  let pending = 0;
  function empty(res, status, headers = {}) {
    if (!res.destroyed && !res.headersSent) { res.writeHead(status, {...headers, 'Cache-Control': 'no-store', Connection: 'close', 'Content-Length': '0'}); res.end(); }
  }
  async function reply(res, request, status, code) {
    const requestId = crypto.randomUUID();
    const body = Buffer.from(JSON.stringify({request_id: requestId, service_id: serviceId, service_boot_id: serviceBootId,
      protocol_version: selection.contract_id, selection, error: {code, message_key: code.toLowerCase(), request_id: requestId,
        details: {}, existing_command_id: null, existing_operation_id: null, retry_advice: 'do_not_retry'}}));
    const headers = [['content-type', 'application/json'], ['content-length', String(body.length)],
      ['x-leafseamer-contract', selection.contract_id], ['x-leafseamer-contract-digest', selection.contract_digest],
      ['cache-control', 'no-store'], ['x-content-type-options', 'nosniff'], ['connection', 'close']];
    // 任何响应字段或选择失配均在发送响应头前失败，不能交付半个可信结果。
    await adapter.decodeResponse(body, adapter.prepareResponse(request, String(status), headers));
    if (!res.destroyed && !res.headersSent) { res.writeHead(status, Object.fromEntries(headers)); res.end(body); }
  }
  async function serve(req, res) {
    let request;
    try { request = adapter.prepareRequest('controller', req.method, req.url, rawPairs(req.rawHeaders)); }
    catch { empty(res, 400); return; }
    if (pending >= maximumPending) { await reply(res, request, 429, 'CAPACITY_EXCEEDED'); return; }
    if (req.headers['transfer-encoding'] !== undefined && req.headers['transfer-encoding'] !== 'chunked') { empty(res, 400); return; }
    if (Number(req.headers['content-length'] ?? 0) > maximumBody) { await reply(res, request, 413, 'PAYLOAD_TOO_LARGE'); return; }
    pending++;
    try {
      const bytes = await new Promise((resolve, reject) => {
        const chunks = []; let size = 0, settled = false;
        const finish = (error, value) => {
          if (settled) return; settled = true; clearTimeout(timer);
          req.off('data', data); req.off('end', end); req.off('aborted', abort); req.off('error', abort); res.off('close', abort);
          req.pause(); error ? reject(error) : resolve(value);
        };
        const data = chunk => { size += chunk.length; if (size > maximumBody) finish(413); else chunks.push(chunk); };
        const end = () => finish(null, Buffer.concat(chunks, size));
        const abort = () => finish(400);
        const timer = setTimeout(() => finish(408), bodyDeadline); timer.unref();
        req.on('data', data); req.once('end', end); req.once('aborted', abort); req.once('error', abort); res.once('close', abort);
      });
      try { await adapter.decodeRequest(bytes, request); }
      catch { await reply(res, request, 400, 'INVALID_REQUEST'); return; }
      // 包括登录在内的所有入口均拒绝。结构校验不构成Origin、Cookie、CSRF或权限批准。
      await reply(res, request, 503, 'WORKER_NOT_READY');
    } catch (status) {
      if (status === 413) await reply(res, request, 413, 'PAYLOAD_TOO_LARGE');
      else empty(res, status === 408 ? 408 : status === 400 ? 400 : 503);
    } finally { pending--; }
  }
  return Object.freeze({handle(req, res) {
    const method = routes.get(req.url?.split('?')[0]);
    if (!method) return false;
    if (req.method !== method) { empty(res, 405, {Allow: method}); return true; }
    void serve(req, res).catch(() => empty(res, 503)); return true;
  }});
}
