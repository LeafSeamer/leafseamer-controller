import net from 'node:net';
import crypto from 'node:crypto';
import canonicalize from './runtime/canonicalize.mjs';
import {decodeWorkerControl as decodeSupervisorControl, workerControlVersion as supervisorControlVersion, decodeWorkerIntent, decodeLaunchAuthorization, decodeWorkerLoadMaterials} from './sdk/worker-runtime.mjs';
import {openNativeClock} from './native-clock.mjs';

export class SupervisorError extends Error { constructor(code) { super(code); this.name = 'SupervisorError'; this.code = code; } }
const check = (ok, code) => { if (!ok) throw new SupervisorError(code); };
const same = (a, b) => canonicalize(a) === canonicalize(b);
const maxSequence = 99999999999999999999n;

// 端点由原生父进程创建并通过固定启动参数交付。一次连接失败后不重连或恢复旧资格。
export async function connectCoreSupervisor({pipe, channelId, binding, policy}) {
  check(process.platform === 'win32' && /^[0-9a-f]{32}$(?![\s\S])/.test(channelId) &&
    pipe === '\\\\.\\pipe\\LeafSeamer.Control.' + channelId, 'supervisor_endpoint');
  const {descriptor, receipt} = structuredClone(binding), source = openNativeClock();
  const scope = Object.freeze({service_id: policy.service_id, database_instance_id: policy.database_instance_id,
    supervisor_instance_id: descriptor.supervisor_instance_id, domain_ref: Object.freeze({...receipt.domain_ref})});
  const key = Object.freeze({launch_id: receipt.launch_id, launch_intent_digest: receipt.launch_intent_digest});
  const socket = net.createConnection(pipe);
  let pending = null, input = Buffer.alloc(0), failed = null, stopped = false, timer = null, lastDeadline = null;
  let outgoing = 1n, incoming = 1n, listener = null, latest = null;
  const lostListeners=new Set(),workerObservations=new WeakMap(),workerVersions=new Map();let workerEpoch=0;
  const freeze=value=>{if(value&&typeof value==='object'){for(const item of Object.values(value))freeze(item);Object.freeze(value);}return value;};
  const notifyLost=error=>{for(const callback of [...lostListeners])try{callback(error);}catch{}};
  let previousTick = null, tail = Promise.resolve(), queued = 0;
  const fail = code => {
    if (failed || stopped) return;
    failed = new SupervisorError(code); clearTimeout(timer);
    const call = pending; pending = null; if (call) { clearTimeout(call.timer); call.reject(failed); }
    socket.destroy();notifyLost(failed); try { listener?.(failed); } catch { /* 资格已先关闭。 */ }
  };
  socket.on('error', () => fail('supervisor_channel_closed'));
  socket.on('end', () => fail('supervisor_channel_closed'));
  socket.on('close', () => fail('supervisor_channel_closed'));
  socket.on('data', chunk => {
    if (failed || stopped) return;
    if (!pending || input.length + chunk.length > 262145) { fail('supervisor_frame'); return; }
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
  const enqueue = task => {
    if (queued >= 8) { fail('supervisor_queue_capacity'); return Promise.reject(failed); }
    queued++;
    const operation = tail.then(task).finally(() => { queued--; });
    tail = operation.catch(() => {}); return operation;
  };
  async function exchange(type, payload, expected) {
    try {
      check(!failed && !stopped && !pending && outgoing <= maxSequence && incoming <= maxSequence, 'supervisor_state');
      if (lastDeadline !== null) assertCurrent();
      const deadline = now() + 2000000000n, message = crypto.randomUUID();
      const frame = {version: supervisorControlVersion, type, scope, channel_id: channelId,
        sequence: String(outgoing++), message_id: message, reply_to: null, payload};
      const response = new Promise((resolve, reject) => { pending = {resolve, reject, timer: setTimeout(() => fail('supervisor_timeout'), 2000)}; });
      socket.write(canonicalize(frame) + '\n', error => { if (error) fail('supervisor_channel_closed'); });
      const bytes = await response;
      let result;
      try { result = await decodeSupervisorControl(bytes, expected); }
      catch { result = await decodeSupervisorControl(bytes, 'ERROR'); }
      check(!failed && !stopped && now() < deadline, 'supervisor_confirmation_expired');
      check(result.channel_id === channelId && result.sequence === String(incoming) && result.reply_to === message && same(result.scope, scope), 'supervisor_response_binding');
      incoming++; return {result, deadline};
    } catch (error) { fail(error instanceof SupervisorError ? error.code : 'supervisor_response_rejected'); throw failed ?? error; }
  }
  function query() {
    return enqueue(async () => {
      try {
        const {result, deadline} = await exchange('LAUNCH_QUERY', key, 'LAUNCH_RESULT');
        check(result.type === 'LAUNCH_RESULT' && same(result.payload.key, key), 'supervisor_response_binding');
        const record = result.payload.record;
        check(record && same(record.key, key) && record.supervisor_instance_id === descriptor.supervisor_instance_id && record.state === 'admitted_closed' &&
          record.creation_attempted === true && record.gate_state === 'closed' && record.retirement_evidence === null && same(record.admission_receipt, receipt), 'supervisor_receipt_binding');
        lastDeadline = deadline; latest = result;
        timer = setTimeout(() => { void query().catch(() => {}); }, 500); return result;
      } catch (error) { fail(error instanceof SupervisorError ? error.code : 'supervisor_response_rejected'); throw failed ?? error; }
    });
  }
  async function putFence(snapshot) {
    assertCurrent();
    // 在入队前复制并按SDK严格解码，调用者后续修改对象不能改变待提交快照。
    const frame = await decodeSupervisorControl(Buffer.from(canonicalize({version: supervisorControlVersion, type: 'FENCE_PUT', scope,
      channel_id: channelId, sequence: '1', message_id: 'validate', reply_to: null, payload: snapshot})), 'FENCE_PUT');
    check(same(frame.payload.scope, scope), 'supervisor_fence_scope');
    const {digest, ...body} = frame.payload;
    check('sha256:' + crypto.createHash('sha256').update(canonicalize(body)).digest('hex') === digest, 'supervisor_fence_digest');
    check(frame.payload.items.every((item, i, items) => item.launch_id !== key.launch_id && (i === 0 || items[i - 1].launch_id < item.launch_id)), 'supervisor_fence_order');
    for(const item of frame.payload.items)if(item.disposition==='deny')workerVersions.set(item.launch_id,(workerVersions.get(item.launch_id)??0)+1);
    return enqueue(async () => {
      const {result} = await exchange('FENCE_PUT', frame.payload, 'FENCE_RESULT');
      if (result.type === 'ERROR'){workerEpoch++;throw new SupervisorError('supervisor_' + result.payload.code);}
      if (result.payload.revision !== frame.payload.revision || result.payload.snapshot_digest !== digest || result.payload.journal_committed !== true) {
        fail('supervisor_fence_binding'); throw failed;
      }
      // ACK仅确认快照耐久；不更新核心回执的确认期限，也不创建RuntimeBinding。
      return result.payload;
    });
  }
  const checkedLaunchResult = (response, expected) => {
    if (response.type === 'ERROR') throw new SupervisorError('supervisor_' + response.payload.code);
    const record = response.payload.record;
    if (!same(response.payload.key, expected) || (record && (!same(record.key, expected) || record.supervisor_instance_id !== scope.supervisor_instance_id))) {
      fail('supervisor_launch_binding'); throw failed;
    }
    if(record&&expected.launch_id!==key.launch_id&&record.state!=='admitted_closed')workerVersions.set(expected.launch_id,(workerVersions.get(expected.launch_id)??0)+1);
    return record;
  };
  async function queryLaunch(launchKey) {
    assertCurrent();
    const frame = await decodeSupervisorControl(Buffer.from(canonicalize({version: supervisorControlVersion, type: 'LAUNCH_QUERY', scope,
      channel_id: channelId, sequence: '1', message_id: 'validate', reply_to: null, payload: launchKey})), 'LAUNCH_QUERY');
    return enqueue(async () => checkedLaunchResult((await exchange('LAUNCH_QUERY', frame.payload, 'LAUNCH_RESULT')).result, frame.payload));
  }
  async function observeWorker(intent) {
    assertCurrent();
    const fixed=await decodeWorkerIntent(Buffer.from(canonicalize(intent)),{authority:'controller',service_id:scope.service_id,database_instance_id:scope.database_instance_id});
    check(fixed.supervisor_instance_id===scope.supervisor_instance_id&&fixed.runtime_generation===descriptor.runtime_generation,'supervisor_worker_scope');
    const requested={launch_id:fixed.launch_id,launch_intent_digest:'sha256:'+crypto.createHash('sha256').update(canonicalize(fixed)).digest('hex')};
    const epoch=workerEpoch,version=workerVersions.get(fixed.launch_id)??0;
    return enqueue(async()=>{
      const {result,deadline}=await exchange('LAUNCH_QUERY',requested,'LAUNCH_RESULT');
      const record=checkedLaunchResult(result,requested),admission=record?.admission_receipt;
      if(!record||record.state!=='admitted_closed'||record.creation_attempted!==true||record.gate_state!=='closed'||record.retirement_evidence!==null){
        workerVersions.set(fixed.launch_id,(workerVersions.get(fixed.launch_id)??0)+1);throw new SupervisorError('supervisor_worker_unavailable');
      }
      const valid=admission&&admission.role==='worker'&&admission.gate_state==='closed'&&admission.launch_id===fixed.launch_id&&
        admission.launch_intent_digest===requested.launch_intent_digest&&admission.member_id===fixed.member_id&&
        same(admission.artifact_manifest_ref,fixed.artifact_manifest_ref)&&same(admission.containment_ref,fixed.containment_ref)&&same(admission.domain_ref,scope.domain_ref)&&
        admission.member_boot_id!==receipt.member_boot_id&&admission.bootstrap_id!==receipt.bootstrap_id&&admission.receipt_id!==receipt.receipt_id&&
        BigInt(admission.admitted_tick_ns)<=now();
      if(!valid){fail('supervisor_worker_binding');throw failed;}
      check(epoch===workerEpoch&&version===(workerVersions.get(fixed.launch_id)??0),'supervisor_worker_withdrawn');
      const observed=freeze({key:requested,descriptor:structuredClone(descriptor),receipt:admission,confirmation_deadline_ns:String(deadline)});
      workerObservations.set(observed,{epoch,version,launch:fixed.launch_id,deadline});return observed;
    });
  }
  function assertWorkerObservation(observed){
    assertCurrent();const held=workerObservations.get(observed);
    check(held&&held.epoch===workerEpoch&&held.version===(workerVersions.get(held.launch)??0)&&now()<held.deadline,'supervisor_worker_withdrawn');
  }
  async function registerWorker(intent, authorization) {
    assertCurrent();
    const fixedIntent = await decodeWorkerIntent(Buffer.from(canonicalize(intent)), {authority: 'controller', service_id: scope.service_id, database_instance_id: scope.database_instance_id});
    const fixedAuthorization = await decodeLaunchAuthorization(Buffer.from(canonicalize(authorization)));
    const digest = 'sha256:' + crypto.createHash('sha256').update(canonicalize(fixedIntent)).digest('hex');
    check(fixedIntent.supervisor_instance_id === scope.supervisor_instance_id && fixedIntent.runtime_generation === descriptor.runtime_generation &&
      fixedAuthorization.launch_id === fixedIntent.launch_id && fixedAuthorization.launch_intent_digest === digest &&
      fixedAuthorization.supervisor_instance_id === scope.supervisor_instance_id, 'supervisor_launch_authorization');
    return enqueue(async () => {
      const {result} = await exchange('LAUNCH_REGISTER', {intent: fixedIntent, authorization: fixedAuthorization}, 'LAUNCH_RESULT');
      const record = checkedLaunchResult(result, {launch_id: fixedIntent.launch_id, launch_intent_digest: digest});
      if (!record) { fail('supervisor_launch_missing'); throw failed; }
      return record;
    });
  }
  async function createWorker(payload) {
    assertCurrent();
    const frame = await decodeSupervisorControl(Buffer.from(canonicalize({version: supervisorControlVersion, type: 'LAUNCH_CREATE', scope,
      channel_id: channelId, sequence: '1', message_id: 'validate', reply_to: null, payload})), 'LAUNCH_CREATE');
    const {key: requested, authorization} = frame.payload;
    check(authorization.launch_id === requested.launch_id && authorization.launch_intent_digest === requested.launch_intent_digest &&
      authorization.supervisor_instance_id === scope.supervisor_instance_id, 'supervisor_launch_authorization');
    return enqueue(async () => {
      const {result} = await exchange('LAUNCH_CREATE', frame.payload, 'LAUNCH_RESULT');
      const record = checkedLaunchResult(result, requested);
      if (!record) { fail('supervisor_launch_missing'); throw failed; }
      return record;
    });
  }
  async function prepareWorkerMaterialization(launchKey){
    assertCurrent();const request={key:launchKey,observation_request_id:crypto.randomUUID()};
    const checked=await decodeSupervisorControl(Buffer.from(canonicalize({version:supervisorControlVersion,type:'LAUNCH_MATERIALIZE',scope,
      channel_id:channelId,sequence:'1',message_id:'validate',reply_to:null,payload:request})),'LAUNCH_MATERIALIZE');
    const deadline=now()+5000000000n;
    for(;;){
      const result=await enqueue(async()=>(await exchange('LAUNCH_MATERIALIZE',checked.payload,'MATERIALIZATION_RESULT')).result);
      if(result.type==='ERROR')throw new SupervisorError('supervisor_'+result.payload.code);
      const value=result.payload;
      if(!same(value.key,checked.payload.key)||value.observation_request_id!==checked.payload.observation_request_id){fail('supervisor_materialization_binding');throw failed;}
      check(now()<deadline,'supervisor_materialization_expired');
      if(value.status==='unavailable')throw new SupervisorError('supervisor_materialization_unavailable');
      if(value.status==='verified'){
        check(same(value.observation.lifetime.clock,scope.domain_ref)&&BigInt(value.observation.lifetime.issued_tick)<=now()&&now()<BigInt(value.observation.lifetime.deadline_tick),'supervisor_materialization_expired');
        return value;
      }
      await new Promise(resolve=>setTimeout(resolve,25));assertCurrent();
    }
  }
  async function loadWorkerContent(launchKey, materials) {
    assertCurrent();
    const fixed = await decodeWorkerLoadMaterials(Buffer.from(canonicalize(materials)));
    const bytes = Buffer.from(canonicalize(fixed)), loadId = crypto.randomUUID();
    const requested = structuredClone(launchKey);
    const proof = await prepareWorkerMaterialization(requested);
    const deadline = now() + 10000000000n;
    const call = async (operation, fields = {}) => {
      assertCurrent();
      const frame = await decodeSupervisorControl(Buffer.from(canonicalize({version: supervisorControlVersion, type: 'LAUNCH_LOAD', scope,
        channel_id: channelId, sequence: '1', message_id: 'validate', reply_to: null,
        payload: {key: requested, load_id: loadId, operation, ...fields}})), 'LAUNCH_LOAD');
      const result = await enqueue(async () => (await exchange('LAUNCH_LOAD', frame.payload, 'LOAD_RESULT')).result);
      if (result.type === 'ERROR') throw new SupervisorError('supervisor_' + result.payload.code);
      const value = result.payload;
      if (!same(value.key, requested) || value.load_id !== loadId || BigInt(value.received_bytes) > BigInt(bytes.length) ||
          (value.status === 'ready' && (value.root_identity !== fixed.root_identity || value.received_bytes !== String(bytes.length)))) {
        fail('supervisor_load_binding'); throw failed;
      }
      return value;
    };
    let releasePromise = null;
    const release = () => releasePromise ??= (async () => {
      const until = now() + 5000000000n;
      for (;;) {
        const result = await call('release');
        if (result.status === 'released') return result;
        check(result.status === 'pending' && now() < until, 'supervisor_load_release_unconfirmed');
        await new Promise(resolve => setTimeout(resolve, 25));
      }
    })();
    try {
      let result = await call('begin', {materials_digest: 'sha256:' + crypto.createHash('sha256').update(bytes).digest('hex'),
        byte_length: bytes.length, materialization_evidence_id: proof.observation.materialization_evidence_id,
        materialization_challenge_id: proof.observation.materialization_challenge_id});
      check(result.status === 'receiving' && result.received_bytes === '0', 'supervisor_load_state');
      for (let offset = 0; offset < bytes.length; offset += 49152) {
        check(now() < deadline, 'supervisor_load_expired');
        const part = bytes.subarray(offset, offset + 49152);
        result = await call('chunk', {offset, bytes: part.toString('base64')});
        check(result.status === 'receiving' && result.received_bytes === String(offset + part.length), 'supervisor_load_state');
      }
      for (;;) {
        check(now() < deadline, 'supervisor_load_expired');
        result = await call('finish');
        if (result.status === 'ready') return Object.freeze({load_id: loadId, root_identity: result.root_identity, release});
        check(result.status === 'pending', 'supervisor_load_unavailable');
        await new Promise(resolve => setTimeout(resolve, 25));
      }
    } catch (error) {
      // 失败仍请求释放；释放未确认时保留两个错误，不把通道丢失当成已释放。
      try { await release(); } catch (releaseError) { throw new AggregateError([error, releaseError], 'supervisor_load_cleanup_unconfirmed'); }
      throw error;
    }
  }
  async function retireWorker(intent, reason) {
    assertCurrent();
    const fixed = await decodeWorkerIntent(Buffer.from(canonicalize(intent)), {authority: 'controller', service_id: scope.service_id, database_instance_id: scope.database_instance_id});
    check(fixed.supervisor_instance_id === scope.supervisor_instance_id && fixed.runtime_generation === descriptor.runtime_generation, 'supervisor_retirement_scope');
    const requested = {launch_id: fixed.launch_id, launch_intent_digest: 'sha256:' + crypto.createHash('sha256').update(canonicalize(fixed)).digest('hex')};
    const frame = await decodeSupervisorControl(Buffer.from(canonicalize({version: supervisorControlVersion, type: 'RETIRE_REQUEST', scope,
      channel_id: channelId, sequence: '1', message_id: 'validate', reply_to: null,
      payload: {key: requested, containment_ref: fixed.containment_ref, reason}})), 'RETIRE_REQUEST');
    return enqueue(async () => {
      const {result} = await exchange('RETIRE_REQUEST', frame.payload, 'RETIRE_RESULT');
      if (result.type === 'ERROR') throw new SupervisorError('supervisor_' + result.payload.code);
      const evidence = result.payload;
      if (evidence.service_id !== scope.service_id || evidence.target_scope !== 'member_group' || !same(evidence.target_member_ids, [fixed.member_id]) ||
          !same(evidence.containment_ref, fixed.containment_ref) || !same(evidence.old_domain_ref, scope.domain_ref) ||
          !same(evidence.evaluator_domain_ref, scope.domain_ref) || evidence.launch_intake_closed !== true || evidence.os_observation_refs.length === 0) {
        fail('supervisor_retirement_binding'); throw failed;
      }
      return evidence;
    });
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
    assertCurrent, observeWorker, assertWorkerObservation, putFence, queryLaunch, registerWorker, prepareWorkerMaterialization, loadWorkerContent, createWorker, retireWorker,
    scope,
    current() { assertCurrent(); return latest; },
    subscribeLost(callback){check(typeof callback==='function','supervisor_listener');lostListeners.add(callback);if(failed||stopped)callback(failed??new SupervisorError('supervisor_stopped'));return ()=>lostListeners.delete(callback);},
    onLost(callback) { check(typeof callback === 'function' && listener === null, 'supervisor_listener'); listener = callback; if (failed) listener(failed); },
    close() {
      if (stopped) return; stopped = true; clearTimeout(timer);notifyLost(new SupervisorError('supervisor_stopped'));
      const call = pending; pending = null; if (call) { clearTimeout(call.timer); call.reject(new SupervisorError('supervisor_stopped')); }
      socket.destroy();
    }
  });
}
