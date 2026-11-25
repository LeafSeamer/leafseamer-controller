import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {clockInteger} from './native-clock.mjs';

const digest = text => 'sha256:' + crypto.createHash('sha256').update(text).digest('hex');
const hash = /^sha256:[0-9a-f]{64}$/;
const id = /^[A-Za-z0-9_.:-]{1,128}$/;
const matches = (pattern, value) => typeof value === 'string' && value.trim() === value && pattern.test(value);
const exact = (value, keys) => value && typeof value === 'object' && Object.keys(value).sort().join(',') === keys;
const tickText = value => String(value).padStart(20, '0');
const minimum = (a, b) => a < b ? a : b;
const maximum = (a, b) => a > b ? a : b;
const ppb = 1000000000n;
const rateCode = 0x52415445;
const maxBackoffNs = 3600000000000n;
const need = (ok, reason) => { if (!ok) throw new Error('time_provider_poll_' + reason); };

function reference(value) {
  need(exact(value, 'digest,id,revision') && matches(id, value.id) && matches(hash, value.digest) && clockInteger(value.revision) > 0n,
    'reference');
}

function decode(text, expected) {
  const body = JSON.parse(text);
  need(canonicalize(body) === text && digest(text) === expected, 'integrity');
  return body;
}

// This writer reserves the durable source slot and records the single possible
// send. Releasing a slot requires the separate capture or retirement writer.
export function timeProviderPollStore(db, bootId, binding,
  {limits, readSource, readAuthentication, assertCurrent, observeRetirement, assertRetirement, assertCollectionAllowed, allowSourceReplacement=false},
  canRelease, canRecover = false, canControl = false) {
  need(typeof readSource === 'function' && typeof readAuthentication === 'function' && typeof assertCurrent === 'function', 'authority');
  if (canRecover) need(typeof observeRetirement === 'function' && typeof assertRetirement === 'function', 'retirement_authority');
  const maxPolls = limits?.max_outstanding, maxBytes = limits?.max_reserved_bytes;
  need(Number.isSafeInteger(maxPolls) && maxPolls > 0 && maxPolls <= 4 &&
    Number.isSafeInteger(maxBytes) && maxBytes > 0, 'capacity_policy');
  const domain = decode(binding.text, binding.digest).clock_domain_descriptor;
  const liveAttempts = new WeakSet();

  function current(sourceSlot) {
    assertCurrent();
    const raw = readSource(sourceSlot);
    const interval = canRelease ? 'minimum_poll_interval_ns,' : '';
    need(exact(raw, 'approval_ref,configuration_ref,endpoint_ref,'+interval+'poll_lease_ns,reserved_bytes,source_digest,source_slot,valid_before_tick_ns') &&
      matches(hash, raw.source_digest) &&
      raw.source_slot === sourceSlot && Number.isSafeInteger(raw.reserved_bytes) && raw.reserved_bytes >= 1 &&
      raw.reserved_bytes <= 2147483647 && clockInteger(raw.poll_lease_ns) > 0n, 'source');
    if (canRelease) need(clockInteger(raw.minimum_poll_interval_ns) >= 16000000000n, 'poll_interval_policy');
    const {valid_before_tick_ns, ...facts} = JSON.parse(canonicalize(raw));
    assertCollectionAllowed?.(facts);
    for (const key of ['configuration_ref', 'approval_ref', 'endpoint_ref']) reference(facts[key]);
    const sample = readAuthentication();
    need(sample && sample.runtime_domain_ref.clock_domain_id === domain.clock_domain_id &&
      sample.runtime_domain_ref.descriptor_digest === domain.descriptor_digest, 'clock_binding');
    reference(sample.acquisition_ref);
    const tick = clockInteger(sample.tick_ns);
    const deadline = minimum(clockInteger(valid_before_tick_ns), clockInteger(sample.valid_before_tick_ns));
    need(tick < deadline, 'expired');
    assertCurrent();
    return {facts, tick, deadline, acquisition: sample.acquisition_ref, sample};
  }

  function lookup(pollId) {
    need(matches(id, pollId), 'id');
    const row = db.prepare(`SELECT r.body_jcs,r.body_digest,a.body_jcs,a.body_digest
      FROM time_provider_poll_reservation r LEFT JOIN time_provider_poll_attempt a USING(poll_id)
      WHERE r.poll_id=?`).raw().get(pollId);
    if (!row) return null;
    return {reservation: decode(row[0], row[1]), digest: row[1], attempt: row[2] === null ? null : decode(row[2], row[3])};
  }

  function recheck(sourceSlot, facts, earliest, expires) {
    const next = current(sourceSlot);
    need(canonicalize(next.facts) === canonicalize(facts), 'source_changed');
    need(next.tick >= earliest && next.tick < expires && expires <= next.deadline, 'expired');
    return {...next.sample, valid_before_tick_ns: String(expires)};
  }

  function predecessor(sourceSlot, source) {
    const row = db.prepare(`SELECT p.poll_id,p.source_slot,p.source_digest,p.service_boot_id,p.body_digest,x.next_allowed_tick,c.body_jcs,c.body_digest
      FROM time_provider_poll_reservation p LEFT JOIN time_provider_poll_release x USING(poll_id)
      LEFT JOIN time_provider_capture c USING(poll_id)
      WHERE p.source_slot=? OR p.source_digest=? ORDER BY p.rowid DESC LIMIT 1`).raw().get(sourceSlot,source);
    if (!row) return null;
    const [poll_id,source_slot,source_digest,service_boot_id,body_digest,next_allowed_tick,capture_jcs,capture_digest] = row;
    return {poll_id,source_slot,source_digest,service_boot_id,body_digest,next_allowed_tick,capture_jcs,capture_digest};
  }

  function distinctSource(prior,facts){
    return prior.source_digest!==facts.source_digest&&allowSourceReplacement&&prior.source_slot===facts.source_slot;
  }

  function storedRecovery(source) {
    const row = db.prepare('SELECT body_jcs,body_digest FROM time_provider_source_recovery WHERE receiver_boot_id=? AND source_digest=?')
      .raw().get(bootId,source);
    return row ? decode(row[0],row[1]) : null;
  }

  function readControl(filter, value) {
    const query = filter==='poll' ? 'WHERE poll_id=?' : 'WHERE source_digest=? ORDER BY rowid DESC LIMIT 1';
    const row = db.prepare(`SELECT body_jcs,body_digest FROM time_provider_poll_control ${query}`).raw().get(value);
    return row ? {body:decode(row[0],row[1]), digest:row[1]} : null;
  }

  function effectiveInterval(facts) {
    const minimum = clockInteger(facts.minimum_poll_interval_ns);
    if (!canControl) return minimum;
    const prior = readControl('source',facts.source_digest)?.body;
    if (!prior) return minimum;
    const wait = clockInteger(prior.control.wait_ns);
    return wait===0n ? null : maximum(minimum,wait);
  }

  function durationPolicy(sample) {
    const {runtime_ref,policy_ref,drift_ppb,monotonic_quantization_ns} = sample;
    reference(runtime_ref); reference(policy_ref);
    need(Number.isSafeInteger(drift_ppb) && drift_ppb >= 0 && drift_ppb <= 1000000 &&
      clockInteger(monotonic_quantization_ns) > 0n, 'recovery_clock');
    return {runtime_ref,policy_ref,drift_ppb,monotonic_quantization_ns};
  }

  function waitUntil(received, interval, policy) {
    const scale = ppb - BigInt(policy.drift_ppb);
    const elapsed = (interval * ppb + scale - 1n) / scale + 2n * clockInteger(policy.monotonic_quantization_ns);
    return clockInteger(String(clockInteger(received) + elapsed));
  }

  async function recover(sourceSlot) {
    need(matches(id,sourceSlot) && !db.inTransaction, 'input');
    const before = current(sourceSlot), source = before.facts.source_digest, previous = predecessor(sourceSlot,source);
    need(previous && (previous.source_digest===source||distinctSource(previous,before.facts)) && previous.service_boot_id!==bootId, 'retirement_required');
    const existing = storedRecovery(source);
    if (existing) return existing;
    const oldRuntime = db.prepare('SELECT body_jcs,body_digest FROM time_provider_runtime_binding WHERE service_boot_id=?')
      .raw().get(previous.service_boot_id);
    need(oldRuntime && lookup(previous.poll_id)?.reservation.runtime_digest===oldRuntime[1], 'retirement_binding');
    const observed = await observeRetirement(decode(oldRuntime[0],oldRuntime[1]));
    need(observed, 'retirement_unavailable');
    return db.transaction(() => {
      assertRetirement(observed);
      const now = current(sourceSlot), prior = predecessor(sourceSlot,source);
      need(canonicalize(now.facts)===canonicalize(before.facts) && prior?.poll_id===previous.poll_id &&
        prior.body_digest===previous.body_digest, 'source_changed');
      const duplicate = storedRecovery(source);
      if (duplicate) return duplicate;
      const received = clockInteger(observed.received_tick_ns), policy = durationPolicy(now.sample);
      need(received<=now.tick && canonicalize(observed.receiving_domain_ref)===canonicalize(now.sample.runtime_domain_ref), 'recovery_clock');
      const {reservation,attempt} = lookup(prior.poll_id);
      const oldInterval = reservation.authorization.minimum_poll_interval_ns;
      if (prior.capture_jcs!==null) decode(prior.capture_jcs,prior.capture_digest);
      const knownControl = canControl && readControl('poll',prior.poll_id);
      const effective = effectiveInterval(now.facts),replacement=distinctSource(prior,now.facts);
      const previousEffective=oldInterval===undefined?null:effectiveInterval(reservation.authorization);
      const interval = (attempt && prior.capture_jcs===null && !knownControl) || effective===null || previousEffective===null ? null :
        maximum(maximum(clockInteger(reservation.effective_poll_interval_ns??oldInterval),previousEffective),effective);
      const wait = interval===null ? null : waitUntil(observed.received_tick_ns,interval,policy);
      const body = {format:'leafseamer-time-provider-source-recovery/1',receiver_boot_id:bootId,source_digest:source,
        predecessor_poll_id:prior.poll_id,predecessor_digest:prior.body_digest,old_runtime_digest:oldRuntime[1],
        observation:observed,clock_policy:policy,minimum_interval_ns:interval===null?null:String(interval),
        wait_until_tick_ns:wait===null?null:String(wait),
        ...(replacement&&{transition:{prior_source_digest:prior.source_digest,source_slot:sourceSlot,authorization:now.facts}})};
      const text = canonicalize(body);
      need(db.prepare('INSERT INTO time_provider_source_recovery VALUES (?,?,?,?,?,?,?)').run(bootId,source,prior.poll_id,
        tickText(received),wait===null?null:tickText(wait),text,digest(text)).changes===1, 'recovery_storage');
      assertRetirement(observed);
      return body;
    }).immediate();
  }

  function sourceReadyAt(sourceSlot, now, interval) {
    const source = now.facts.source_digest;
    if (!canRelease) {
      need(!db.prepare('SELECT 1 FROM time_provider_poll_reservation WHERE source_slot=? OR source_digest=?').pluck()
        .get(sourceSlot, source), 'source_busy');
      return now.tick;
    }
    const prior = predecessor(sourceSlot,source);
    if (!prior) return now.tick;
    if (canRecover&&!allowSourceReplacement) need(!db.prepare('SELECT 1 FROM time_provider_poll_reservation WHERE source_slot=? AND source_digest<>? LIMIT 1')
      .pluck().get(sourceSlot,source), 'source_changed');
    const {source_digest:oldSource, service_boot_id:boot, next_allowed_tick:earliest, capture_jcs:capture} = prior;
    if (canRecover && boot!==bootId) {
      const proof = storedRecovery(source);
      need((oldSource===source&&!proof?.transition || distinctSource(prior,now.facts)&&
        proof?.transition?.prior_source_digest===oldSource && proof.transition.source_slot===sourceSlot &&
        canonicalize(proof.transition.authorization)===canonicalize(now.facts)) &&
        proof?.predecessor_poll_id===prior.poll_id && proof.predecessor_digest===prior.body_digest, 'retirement_required');
      need(proof.wait_until_tick_ns!==null, 'backoff_unknown');
      const policy = durationPolicy(now.sample);
      need(canonicalize(proof.clock_policy)===canonicalize(policy), 'recovery_clock');
      const wait = waitUntil(proof.observation.received_tick_ns,interval,policy);
      return maximum(clockInteger(proof.wait_until_tick_ns),wait);
    }
    const controlRelease = canControl && db.prepare('SELECT next_allowed_tick FROM time_provider_control_release WHERE poll_id=?').pluck().get(prior.poll_id);
    need(earliest !== null || controlRelease, 'source_busy');
    need(boot === bootId && oldSource === source, 'retirement_required');
    if (controlRelease) {
      const {body} = readControl('poll',prior.poll_id);
      const wait = waitUntil(body.received_tick_ns,interval,durationPolicy(now.sample));
      return maximum(BigInt(controlRelease),wait);
    }
    const m4 = clockInteger(decode(capture,prior.capture_digest).m4_tick_ns);
    const wait = canControl ? waitUntil(String(m4),interval,durationPolicy(now.sample)) : m4 + interval;
    return maximum(BigInt(earliest),wait);
  }

  function schedulePlan(sourceSlot, expected = null) {
    need(canControl && canRecover && matches(id,sourceSlot) && !db.inTransaction, 'schedule');
    const now=current(sourceSlot), source=now.facts.source_digest, prior=predecessor(sourceSlot,source);
    need(!expected || canonicalize(now.facts)===canonicalize(expected),'source_changed');
    if (prior && prior.service_boot_id!==bootId && (prior.source_digest===source||distinctSource(prior,now.facts)) && !storedRecovery(source)) {
      return {state:'retirement_required',authorization:now.facts};
    }
    const interval=effectiveInterval(now.facts);
    need(interval!==null,'backoff_stopped');
    const due=sourceReadyAt(sourceSlot,now,interval);
    return {state:due>now.tick?'waiting':'ready',authorization:now.facts,wait_ns:due>now.tick?due-now.tick:0n};
  }

  function authorizeAttempt(attempt) {
    need(liveAttempts.has(attempt), 'attempt_not_live');
    const stored = lookup(attempt.poll_ref.id);
    need(stored?.digest === attempt.poll_ref.digest && canonicalize(stored.attempt) === canonicalize(attempt), 'integrity');
    return recheck(stored.reservation.source_slot, stored.reservation.authorization, clockInteger(attempt.attempted_tick_ns),
      clockInteger(attempt.valid_before_tick_ns));
  }

  function storeControl(attempt, control) {
    need(!db.inTransaction, 'control_transaction');
    return db.transaction(() => {
      const sample = authorizeAttempt(attempt);
      const {reservation} = lookup(attempt.poll_ref.id), received = clockInteger(sample.tick_ns);
      const observed = clockInteger(control.observed_tick_ns), wait = clockInteger(control.wait_ns);
      const floor = clockInteger(reservation.effective_poll_interval_ns);
      need(exact(control,'code,observed_tick_ns,wait_ns') && Number.isInteger(control.code) && control.code>=0 && control.code<=0xffffffff &&
        observed>=clockInteger(attempt.attempted_tick_ns) && observed<=received &&
        (wait===0n || (control.code===rateCode && wait>=2n*floor && wait<=maxBackoffNs)), 'control');
      const policy = durationPolicy(sample), next = wait===0n ? null : waitUntil(String(received),wait,policy);
      const body = {format:'leafseamer-time-provider-poll-control/1',service_boot_id:bootId,runtime_digest:binding.digest,
        source_digest:reservation.authorization.source_digest,poll_ref:attempt.poll_ref,attempt_id:attempt.attempt_id,
        control,received_tick_ns:String(received),clock_policy:policy,next_allowed_tick_ns:next===null?null:String(next)};
      const text = canonicalize(body), bodyDigest = digest(text);
      need(db.prepare('INSERT INTO time_provider_poll_control VALUES (?,?,?,?,?,?,?,?)').run(attempt.poll_ref.id,body.source_digest,
        attempt.attempt_id,tickText(received),tickText(wait),next===null?null:tickText(next),text,bodyDigest).changes===1,'control_storage');
      authorizeAttempt(attempt);
      return {poll_ref:attempt.poll_ref,attempt_id:attempt.attempt_id,
        control_ref:{id:attempt.poll_ref.id,revision:'1',digest:bodyDigest},control_digest:digest(canonicalize(control))};
    }).immediate();
  }

  function releaseControl(receipt, acknowledgement) {
    need(!db.inTransaction, 'control_transaction');
    db.transaction(() => {
      assertCurrent();
      const stored = readControl('poll',receipt.poll_ref.id);
      need(stored?.digest===receipt.control_ref.digest && stored.body.attempt_id===receipt.attempt_id &&
        canonicalize(stored.body.poll_ref)===canonicalize(receipt.poll_ref) && digest(canonicalize(stored.body.control))===receipt.control_digest &&
        acknowledgement?.type==='POLL_CONTROL_STORED_ACK' && acknowledgement.binding_digest===binding.digest &&
        canonicalize(acknowledgement.receipt)===canonicalize(receipt), 'control_ack');
      const next = stored.body.next_allowed_tick_ns;
      const text = canonicalize(acknowledgement);
      need(db.prepare('INSERT INTO time_provider_control_release VALUES (?,?,?,?,?)').run(receipt.poll_ref.id,stored.digest,
        next===null?null:tickText(clockInteger(next)),text,digest(text)).changes===1,'control_release_storage');
      assertCurrent();
    }).immediate();
  }

  return Object.freeze({lookup,authorizeAttempt,referenceContext:current,...(canRecover && {recover}),
    ...(canControl && {storeControl,releaseControl,schedulePlan}),
    reserve(sourceSlot, pollId, expected = null) {
      need(matches(id, pollId) && matches(id, sourceSlot) && !db.inTransaction, 'input');
      return db.transaction(() => {
        const now = current(sourceSlot), previous = lookup(pollId);
        need(!expected || canonicalize(now.facts)===canonicalize(expected),'source_changed');
        if (previous) {
          need(previous.reservation.service_boot_id === bootId && previous.reservation.source_slot === sourceSlot, 'identity_conflict');
          return previous;
        }
        const interval = canRelease ? effectiveInterval(now.facts) : null;
        if (canControl) need(interval!==null,'backoff_stopped');
        need(now.tick>=sourceReadyAt(sourceSlot,now,interval),'interval');
        const durableControl = canControl ? 'AND NOT EXISTS (SELECT 1 FROM time_provider_control_release z WHERE z.poll_id=p.poll_id)' : '';
        const reserved = db.prepare(canRecover ? `SELECT count(*) FILTER (WHERE x.poll_id IS NULL ${durableControl} AND NOT EXISTS
          (SELECT 1 FROM time_provider_source_recovery q WHERE q.predecessor_poll_id=p.poll_id)),coalesce(sum(p.reserved_bytes),0)
          FROM time_provider_poll_reservation p LEFT JOIN time_provider_poll_release x USING(poll_id)` :
          canRelease ? `SELECT count(*)-count(x.poll_id),coalesce(sum(p.reserved_bytes),0)
          FROM time_provider_poll_reservation p LEFT JOIN time_provider_poll_release x USING(poll_id)` :
          'SELECT count(*),coalesce(sum(reserved_bytes),0) FROM time_provider_poll_reservation').raw().get();
        need(reserved[0] < maxPolls && reserved[1] <= maxBytes - now.facts.reserved_bytes, 'capacity');
        const expires = minimum(now.deadline, now.tick + clockInteger(now.facts.poll_lease_ns));
        const body = {poll_id: pollId, service_boot_id: bootId, runtime_digest: binding.digest, source_slot: sourceSlot,
          authorization: now.facts, acquisition_ref: now.acquisition, reserved_bytes: now.facts.reserved_bytes,
          issued_tick_ns: String(now.tick), expires_tick_ns: String(expires),
          ...(canControl && {effective_poll_interval_ns:String(interval)})};
        const text = canonicalize(body), value = digest(text);
        need(db.prepare('INSERT INTO time_provider_poll_reservation VALUES (?,?,?,?,?,?,?,?,?,?)').run(pollId, bootId, sourceSlot,
          now.facts.source_digest, now.acquisition.id, now.facts.reserved_bytes, tickText(now.tick), tickText(expires), text, value)
          .changes === 1, 'reservation_storage');
        recheck(sourceSlot, now.facts, now.tick, expires);
        return {reservation: body, digest: value, attempt: null};
      }).immediate();
    },
    markAttempt(pollRef) {
      need(exact(pollRef, 'digest,id') && matches(id, pollRef.id) && matches(hash, pollRef.digest) && !db.inTransaction, 'input');
      const ref = {id: pollRef.id, digest: pollRef.digest};
      const {attempt, authorization, original} = db.transaction(() => {
        assertCurrent();
        const row = lookup(ref.id);
        need(row && row.digest === ref.digest && row.reservation.service_boot_id === bootId &&
          row.reservation.runtime_digest === binding.digest, 'identity_conflict');
        need(row.attempt === null, 'already_attempted');
        const wanted = row.reservation;
        const now = current(wanted.source_slot);
        need(canonicalize(now.facts) === canonicalize(wanted.authorization), 'source_changed');
        const cutoff = minimum(clockInteger(wanted.expires_tick_ns), now.deadline);
        need(now.tick >= clockInteger(wanted.issued_tick_ns) && now.tick < cutoff, 'expired');
        const record = {attempt_id: crypto.randomUUID(), poll_ref: ref, runtime_digest: binding.digest, acquisition_ref: now.acquisition,
          attempted_tick_ns: String(now.tick), expires_tick_ns: wanted.expires_tick_ns, valid_before_tick_ns: String(cutoff)};
        const text = canonicalize(record);
        need(db.prepare('INSERT INTO time_provider_poll_attempt VALUES (?,?,?,?,?,?,?)').run(ref.id, ref.digest, record.attempt_id,
          now.acquisition.id, tickText(now.tick), text, digest(text)).changes === 1, 'attempt_storage');
        recheck(wanted.source_slot, wanted.authorization, now.tick, cutoff);
        return {attempt: record, original: wanted, authorization: cutoff};
      }).immediate();
      // If qualification is lost after COMMIT, the attempt remains consumed.
      recheck(original.source_slot, original.authorization, clockInteger(attempt.attempted_tick_ns), authorization);
      Object.freeze(attempt.poll_ref);
      Object.freeze(attempt.acquisition_ref);
      Object.freeze(attempt);
      liveAttempts.add(attempt);
      return attempt;
    }
  });
}
