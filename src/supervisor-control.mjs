import net from 'node:net';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {decodeSupervisorControl, supervisorControlVersion} from './sdk/supervisor-control.mjs';
import {openNativeClock} from './native-clock.mjs';

export class SupervisorError extends Error { constructor(code) { super(code); this.name = 'SupervisorError'; this.code = code; } }
const check = (ok, code) => { if (!ok) throw new SupervisorError(code); };
const same = (a, b) => canonicalize(a) === canonicalize(b);
const maxSequence = 99999999999999999999n;

// 端点由原生父进程创建并通过固定启动参数交付。一次连接失败后不重连或恢复旧资格。
export async function connectCoreSupervisor({pipe, channelId, binding, policy}) {
  check(process.platform === 'win32' && /^[0-9a-f]{32}$(?![\s\S])/.test(channelId) &&
    pipe === '\\\\.\\pipe\\LeafSeamer.Control.' + channelId, 'supervisor_endpoint');
  const {descriptor, receipt} = binding, source = openNativeClock();
  const scope = Object.freeze({service_id: policy.service_id, database_instance_id: policy.database_instance_id,
    supervisor_instance_id: descriptor.supervisor_instance_id, domain_ref: Object.freeze({...receipt.domain_ref})});
  const key = Object.freeze({launch_id: receipt.launch_id, launch_intent_digest: receipt.launch_intent_digest});
  const socket = net.createConnection(pipe);
  let pending = null, input = Buffer.alloc(0), failed = null, stopped = false, timer = null, lastDeadline = null;
  let outgoing = 1n, incoming = 1n, listener = null, latest = null;
  let previousTick = null;
  const fail = code => {
    if (failed || stopped) return;
    failed = new SupervisorError(code); clearTimeout(timer);
    const call = pending; pending = null; if (call) { clearTimeout(call.timer); call.reject(failed); }
    socket.destroy(); try { listener?.(failed); } catch { /* 资格已先关闭。 */ }
  };
  socket.on('error', () => fail('supervisor_channel_closed'));
  socket.on('end', () => fail('supervisor_channel_closed'));
  socket.on('close', () => fail('supervisor_channel_closed'));
  socket.on('data', chunk => {
    if (failed || stopped) return;
    if (!pending || input.length + chunk.length > 65537) { fail('supervisor_frame'); return; }
    input = Buffer.concat([input, chunk]); const end = input.indexOf(10); if (end < 0) return;
    if (end !== input.length - 1) { fail('supervisor_frame'); return; }
    const call = pending; pending = null; clearTimeout(call.timer);
    const bytes = input.subarray(0, end); input = Buffer.alloc(0); call.resolve(bytes);
  });
  const assertCurrent = () => {
    if (!failed && !stopped && lastDeadline !== null) {
      try { if (now() >= lastDeadline) fail('supervisor_confirmation_expired'); }
      catch { fail('supervisor_clock_unavailable'); }
    }
    if (failed) throw failed;
    check(!stopped && lastDeadline !== null, 'supervisor_unavailable');
  };
  const now = () => {
    const tick = source.tick();
    check(previousTick === null || tick >= previousTick, 'supervisor_clock_unavailable'); previousTick = tick; return tick;
  };
  async function query() {
    try {
      check(!failed && !stopped && !pending && outgoing <= maxSequence && incoming <= maxSequence, 'supervisor_state');
      const deadline = now() + 2000000000n, message = crypto.randomUUID();
      const frame = {version: supervisorControlVersion, type: 'LAUNCH_QUERY', scope, channel_id: channelId,
        sequence: String(outgoing++), message_id: message, reply_to: null, payload: key};
      const response = new Promise((resolve, reject) => { pending = {resolve, reject, timer: setTimeout(() => fail('supervisor_timeout'), 2000)}; });
      socket.write(canonicalize(frame) + '\n', error => { if (error) fail('supervisor_channel_closed'); });
      const result = await decodeSupervisorControl(await response, 'LAUNCH_RESULT');
      check(!failed && !stopped && now() < deadline, 'supervisor_confirmation_expired');
      check(result.channel_id === channelId && result.sequence === String(incoming) && result.reply_to === message && same(result.scope, scope) &&
        same(result.payload.key, key), 'supervisor_response_binding');
      const record = result.payload.record;
      check(record && same(record.key, key) && record.supervisor_instance_id === descriptor.supervisor_instance_id && record.state === 'admitted_closed' &&
        record.creation_attempted === true && record.gate_state === 'closed' && record.retirement_evidence === null && same(record.admission_receipt, receipt), 'supervisor_receipt_binding');
      incoming++; lastDeadline = deadline; latest = result;
      timer = setTimeout(() => { void query().catch(() => {}); }, 500);
      return result;
    } catch (error) { fail(error instanceof SupervisorError ? error.code : 'supervisor_response_rejected'); throw failed ?? error; }
  }
  try {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => { fail('supervisor_connect_timeout'); reject(failed); }, 2000);
      const done = error => { clearTimeout(timeout); socket.removeListener('connect', connected); socket.removeListener('error', broken); error ? reject(error) : resolve(); };
      const connected = () => done(), broken = () => done(failed ?? new SupervisorError('supervisor_channel_closed'));
      socket.once('connect', connected); socket.once('error', broken);
    });
    await query();
  } catch (error) { socket.destroy(); clearTimeout(timer); throw error; }
  return Object.freeze({
    assertCurrent,
    current() { assertCurrent(); return latest; },
    onLost(callback) { check(typeof callback === 'function' && listener === null, 'supervisor_listener'); listener = callback; if (failed) listener(failed); },
    close() {
      if (stopped) return; stopped = true; clearTimeout(timer);
      const call = pending; pending = null; if (call) { clearTimeout(call.timer); call.reject(new SupervisorError('supervisor_stopped')); }
      socket.destroy();
    }
  });
}
