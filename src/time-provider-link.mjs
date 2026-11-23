import {createHash,randomUUID} from 'node:crypto';
import net from 'node:net';
import canonicalize from './runtime/canonicalize.mjs';
import {clockInteger} from './native-clock.mjs';

const version = 'time-provider-link/1';
const authVersion = 'time-provider-auth/1';
const maximum = 16384;
const captureMaximum = 98304;
const authMaximum = 2048;
const timeoutMs = 2000;
const pollResponseTimeoutMs = 6000;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const sha256 = /^sha256:[0-9a-f]{64}$/;
const pipePrefix = '\\\\.\\pipe\\LeafSeamer.TimeCollector.';
const exact = (value, keys) => value !== null && typeof value === 'object' && Object.keys(value).sort().join(',') === keys;
const validDatagram = value => {
  if (typeof value !== 'string' || value.length < 64 || value.length > 1643) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length >= 48 && bytes.length <= 1232 && bytes.toString('base64url') === value;
};

export function sealTimeProviderRuntime({identity,serviceBootId,core,provider}) {
  const {intent,descriptor,receipt,process_observation:observed}=provider;
  const same=(left,right)=>canonicalize(left)===canonicalize(right);
  if(intent.role!=='time_provider'||intent.service_id!==identity.service_id||intent.device_ids.length!==0||
    !same(descriptor,core.descriptor)||receipt.role!=='time_provider'||receipt.gate_state!=='closed'||
    !same(receipt.domain_ref,core.receipt.domain_ref)||receipt.receipt_id===core.receipt.receipt_id||
    receipt.bootstrap_id===core.receipt.bootstrap_id||receipt.member_boot_id===core.receipt.member_boot_id||
    observed.observation_id!==receipt.os_observation_ref)throw new Error('time_provider_runtime_binding');
  const body={format:'leafseamer-time-provider-runtime-binding/1',service_id:identity.service_id,
    database_instance_id:identity.database_instance_id,service_boot_id:serviceBootId,core_receipt_id:core.receipt.receipt_id,
    launch_intent:intent,clock_domain_descriptor:descriptor,admission_receipt:receipt,process_observation:observed,gate_state:'closed'};
  const digest=value=>createHash('sha256').update(value).digest('hex');
  const runtime_binding_id='time-runtime.'+digest(canonicalize(body));
  const text=canonicalize({...body,runtime_binding_id});
  if(Buffer.byteLength(text)>32768)throw new Error('time_provider_runtime_capacity');
  return Object.freeze({text,digest:'sha256:'+digest(text),memberBoot:receipt.member_boot_id,runtimeId:runtime_binding_id});
}

export function openTimeProviderLink({text, digest, memberBoot}, {assertCurrent = () => {}, readAuthentication = () => null} = {}) {
  if (!/^[0-9a-f]{32}$/.test(memberBoot)) throw new Error('time_provider_link_identity');
  const binding = JSON.parse(text);
  const requestId = randomUUID();
  const request = Buffer.from(canonicalize({
    version, type: 'BIND', request_id: requestId, binding_digest: digest, binding
  }) + '\n');
  if (request.length > maximum + 1) throw new Error('time_provider_link_capacity');
  const expected = Buffer.from(canonicalize({version, type: 'BOUND', reply_to: requestId, binding_digest: digest}));
  const socket = net.createConnection(pipePrefix + memberBoot + '.core');
  let state = 'authenticating', buffer = Buffer.alloc(0), lastTick = -1n, replying = false, onLost = null, quiescing = false;
  let pending = null, pollSequence = 0n;
  const ready = Promise.withResolvers();
  const timer = setTimeout(() => fail('time_provider_link_timeout'), timeoutMs);
  function abortPoll(code) {
    if (!pending) return;
    clearTimeout(pending.timer);
    pending.reject(new Error(code));
    pending = null;
  }
  function fail(code) {
    if (state === 'closed' || state === 'lost') return;
    const live = state === 'bound';
    state = 'lost';
    clearTimeout(timer);
    abortPoll(code);
    socket.destroy();
    if (live) onLost?.();
    else ready.reject(new Error(code));
  }
  const link = Object.freeze({
    assertCurrent() {
      if (state !== 'bound' || socket.destroyed || quiescing) throw new Error('time_provider_link_lost');
    },
    onLost(listener) {
      onLost = listener;
      if (state === 'lost') listener();
    },
    collect(prepare) {
      link.assertCurrent();
      assertCurrent();
      if (pending) throw new Error('time_provider_poll_busy');
      const prepared = prepare();
      const {reservation, attempt, network} = prepared;
      const sequence = String(pollSequence + 1n);
      clockInteger(sequence);
      const frame = Buffer.from(canonicalize({version, type: 'POLL', binding_digest: digest, poll_sequence: sequence,
        reservation, attempt, network}) + '\n');
      if (frame.length > maximum + 1) throw new Error('time_provider_poll_capacity');
      const result = Promise.withResolvers();
      pending = {...result, ...prepared, sequence, expectedAck: null,
        timer: setTimeout(() => fail('time_provider_poll_reply_timeout'), pollResponseTimeoutMs)};
      pollSequence++;
      socket.write(frame, error => { if (error) fail('time_provider_link_lost'); });
      return result.promise;
    },
    quiesce() {
      quiescing=true;
      abortPoll('controller_closing');
    },
    close() {
      state = 'closed';
      onLost = null;
      clearTimeout(timer);
      abortPoll('time_provider_link_lost');
      socket.destroy();
    }
  });
  function respond(body) {
    if (replying || (state === 'bound' && (!pending || pending.expectedAck)) || !exact(body, 'binding_digest,request_id,tick_ns,type,version') ||
        body.version !== authVersion || body.type !== 'AUTH_READ' || body.binding_digest !== digest ||
        typeof body.request_id !== 'string' || !uuid.test(body.request_id)) {
      throw new Error('time_provider_auth_request');
    }
    const asked = clockInteger(body.tick_ns);
    if (asked <= lastTick) throw new Error('time_provider_auth_replay');
    lastTick = asked;
    assertCurrent();
    let sample;
    try { sample = pending ? pending.authorize() : readAuthentication(); }
    catch { sample = null; }
    const domain = binding.clock_domain_descriptor;
    if (sample && (sample.runtime_domain_ref.clock_domain_id !== domain.clock_domain_id ||
        sample.runtime_domain_ref.descriptor_digest !== domain.descriptor_digest ||
        clockInteger(sample.tick_ns) < asked || clockInteger(sample.tick_ns) - asked >= BigInt(timeoutMs) * 1000000n)) {
      sample = null;
    }
    const reply = Buffer.from(canonicalize({version: authVersion, type: 'AUTH_RESULT', reply_to: body.request_id,
      binding_digest: digest, sample}) + '\n');
    if (reply.length > authMaximum + 1) throw new Error('time_provider_auth_capacity');
    assertCurrent();
    if (state === 'authenticating') state = 'confirming';
    replying = true;
    socket.write(reply, error => {
      replying = false;
      if (error) fail('time_provider_link_lost');
    });
  }
  function pollResult(body) {
    if (!pending || pending.expectedAck || !exact(body, 'attempt_id,binding_digest,candidate,control,poll_ref,poll_sequence,status,type,version') ||
        body.version !== version || body.binding_digest !== digest || !['candidate','control','failed','unavailable'].includes(body.status) ||
        body.poll_sequence !== pending.sequence || body.attempt_id !== pending.attempt.attempt_id ||
        canonicalize(body.poll_ref) !== canonicalize(pending.attempt.poll_ref)) {
      throw new Error('time_provider_poll_response');
    }
    const {candidate, control} = body;
    if (body.status === 'candidate') {
      const nts = pending.network.authentication === 'nts';
      if (control !== null || !exact(candidate, 'endpoint,key_reply,key_reply_digest,m1_tick_ns,m4_tick_ns,request,response') ||
          !validDatagram(candidate.request) || !validDatagram(candidate.response) ||
          (nts ? typeof candidate.key_reply !== 'string' || candidate.key_reply.length < 1 || candidate.key_reply.length > 87382 ||
            typeof candidate.key_reply_digest !== 'string' || !sha256.test(candidate.key_reply_digest) ||
            !pending.network.targets.some(target => target.endpoint === candidate.endpoint) :
            candidate.key_reply !== null || candidate.key_reply_digest !== null || candidate.endpoint !== pending.network.endpoint) ||
          clockInteger(candidate.m1_tick_ns) < clockInteger(pending.attempt.attempted_tick_ns) ||
          clockInteger(candidate.m4_tick_ns) < clockInteger(candidate.m1_tick_ns) ||
          clockInteger(candidate.m4_tick_ns) >= clockInteger(pending.attempt.valid_before_tick_ns)) {
        throw new Error('time_provider_poll_candidate');
      }
    } else if (candidate !== null || (body.status === 'control' ?
      !exact(control, 'code,observed_tick_ns,wait_ns') || !Number.isInteger(control.code) || control.code < 0 || control.code > 0xffffffff ||
      clockInteger(control.observed_tick_ns) < clockInteger(pending.attempt.attempted_tick_ns) ||
      clockInteger(control.observed_tick_ns) >= clockInteger(pending.attempt.valid_before_tick_ns) ||
      clockInteger(control.wait_ns) > 3600000000000n : control !== null)) {
      throw new Error('time_provider_poll_result');
    }
    assertCurrent();
    const call = pending;
    clearTimeout(call.timer);
    try { call.authorize(); }
    catch { pending = null; call.resolve({status: 'unavailable', candidate: null, control: null}); return; }
    const persistentControl = body.status==='control' && typeof call.storeControl==='function';
    if (body.status !== 'candidate' && !persistentControl) {
      pending = null;
      call.resolve({status: body.status, candidate, control});
      return;
    }
    try { call.receipt = persistentControl ? call.storeControl(control) : call.archive(candidate); }
    catch (error) { pending = null; call.reject(error); return; }
    assertCurrent();
    call.control = persistentControl ? control : null;
    const type = persistentControl ? 'POLL_CONTROL_STORED' : 'POLL_STORED';
    const stored = {version, type, binding_digest: digest, poll_sequence: call.sequence, receipt: call.receipt};
    const message = canonicalize(stored);
    if (Buffer.byteLength(message) > authMaximum) throw new Error('time_provider_poll_capacity');
    call.expectedAck = canonicalize({...stored,type:type+'_ACK'});
    call.timer = setTimeout(() => fail('time_provider_poll_ack_timeout'), timeoutMs);
    socket.write(message + '\n',error=>{if(error)fail('time_provider_link_lost');});
  }
  function pollAcknowledged(body, bytes) {
    if (!pending?.expectedAck || !bytes.equals(Buffer.from(pending.expectedAck))) throw new Error('time_provider_poll_ack');
    assertCurrent();
    const call = pending;
    pending = null;
    clearTimeout(call.timer);
    try {
      if (call.control) {
        call.releaseControl(call.receipt,body);
        call.resolve({status:'control',candidate:null,control:call.control,receipt:call.receipt});
      } else {
        call.release(call.receipt,body);
        call.resolve({status:'archived',receipt:call.receipt});
      }
    } catch (error) { call.reject(error); }
  }
  socket.once('connect', () => socket.write(request));
  socket.on('data', chunk => {
    if(quiescing) return;
    if (chunk.length + buffer.length > (pending && !pending.expectedAck ? captureMaximum : authMaximum) + 1) {
      fail('time_provider_link_capacity'); return;
    }
    buffer = Buffer.concat([buffer, chunk]);
    try {
      const end = buffer.indexOf(10);
      if (end < 0) return;
      if (end !== buffer.length - 1) throw new Error('time_provider_auth_overlap');
      const bytes = buffer.subarray(0, end);
      buffer = Buffer.alloc(0);
      if (state === 'confirming') {
        if (!bytes.equals(expected)) throw new Error('time_provider_link_response');
        state = 'bound';
        clearTimeout(timer);
        ready.resolve(link);
      } else {
        const body = JSON.parse(bytes.toString('utf8'));
        if (!Buffer.from(canonicalize(body)).equals(bytes)) throw new Error('time_provider_link_response');
        if (body?.type === 'POLL_RESULT') pollResult(body);
        else if (body?.type === 'POLL_STORED_ACK' || body?.type === 'POLL_CONTROL_STORED_ACK') pollAcknowledged(body,bytes);
        else if (bytes.length <= authMaximum) respond(body);
        else throw new Error('time_provider_link_capacity');
      }
    } catch { fail('time_provider_link_response'); }
  });
  const lost = () => fail('time_provider_link_lost');
  socket.on('error', lost);
  socket.on('end', lost);
  socket.on('close', lost);
  return ready.promise;
}
