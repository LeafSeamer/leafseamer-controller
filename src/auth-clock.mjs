import {ClockError, clockInteger} from './native-clock.mjs';
import {need, canonical, same, context, captureInterval, extrapolate, ref} from './auth-clock-value.mjs';

class HealthRenewed extends Error {}

// provider只能由受监督本地启动装配，不能从HTTP、环境开关或采样正文取得。
// 缺少实现时保留诊断服务，不生成环境批准或运行域身份。
export function startAuthenticationClock(source, ledger, provider = null, {schedule = true, waitForInitialEvidence = false, renewableHealth = false} = {}) {
  let stopped = false, failure = null, durable = true, binding = null;
  function tick() {
    const value = source.tick(); need(typeof value === 'bigint' && value >= 0n && value <= (1n << 64n) - 1n, 'auth_clock_tick'); return value;
  }
  function evidence(allowMissing = false) {
    need(provider !== null, 'auth_clock_provider_missing');
    const input = provider.read();
    if (allowMissing && input === null) return null;
    // 独立副本避免调用方在事务期间修改已校验对象。
    const snapshot = JSON.parse(canonical(input));
    context(snapshot, ledger.scope, source.artifactDigest, tick());
    if (binding) need(same(binding.policy, snapshot.policy) && same(binding.runtime, snapshot.runtime), 'auth_clock_context_changed');
    return snapshot;
  }
  function fail(error) {
    if (!failure) {
      failure = error instanceof ClockError ? error.code : 'auth_clock_source_or_commit_failed';
      if (binding) {
        try { ledger.fault(binding.runtime.clock_domain_id); } catch { durable = false; }
      } else durable = false;
    }
  }
  function requireStable(before, after) {
    if (same(before, after)) return;
    if (renewableHealth && same(before.policy, after.policy) && same(before.runtime, after.runtime) &&
        before.health.state === 'synchronized' && after.health.state === 'synchronized' &&
        (before.health.id !== after.health.id || before.health.revision !== after.health.revision) &&
        tick() < clockInteger(before.health.valid_before_tick_ns)) throw new HealthRenewed();
    need(false, 'auth_clock_context_changed');
  }
  function withRenewalRetry(operation) {
    try { return operation(); }
    catch (error) {
      if (!(error instanceof HealthRenewed)) throw error;
      return operation();
    }
  }
  function usable() { need(!stopped && !failure && provider !== null && binding !== null, failure ?? (stopped ? 'auth_clock_stopped' : 'auth_clock_provider_missing')); }
  function refresh() {
    if (stopped || failure || provider === null) return;
    try { withRenewalRetry(acquire); } catch (error) { fail(error); }
    function acquire() {
      const before = evidence(waitForInitialEvidence && binding === null);
      if (before === null) return;
      binding ??= before;
      const old = ledger.current(binding.runtime.clock_domain_id);
      if (old) extrapolate(old, tick());
      const captured = source.capture(), after = evidence();
      requireStable(before, after);
      const result = ledger.ingest(captured, after, source, () => {
        const latest = evidence();
        requireStable(after, latest);
        return latest;
      });
      need(result.state === 'stored', 'auth_clock_fault_latched');
      // COMMIT已完成也可能已过期限；此时保留原件但绝不交付可用结果。
      ledger.read(binding.runtime.clock_domain_id, tick(), evidence(), source.artifactDigest);
    }
  }
  function current(projection = 'plain') {
    usable();
    try { return withRenewalRetry(readCurrent); }
    catch (error) { fail(error); throw new ClockError(failure); }
    function readCurrent() {
      const before = evidence(), now = tick(), domain = binding.runtime.clock_domain_id;
      const record = ledger.current(domain); need(record !== null, 'auth_clock_missing');
      extrapolate(record, now);
      const observation = source.capture(), after = evidence();
      need(observation.continuity_available && observation.continuity === binding.runtime.continuity, 'auth_clock_context_changed');
      requireStable(before, after);
      const observed = captureInterval(observation, before.policy), predicted = extrapolate(record, clockInteger(observation.b));
      need(clockInteger(observed.upper_ns) >= clockInteger(predicted.lower_ns) && clockInteger(observed.lower_ns) <= clockInteger(predicted.upper_ns), 'auth_clock_disjoint');
      const at = tick(), value = ledger.read(domain, at, after, source.artifactDigest);
      if (projection === 'plain') return Object.freeze(value);
      const runtimeDomain = Object.freeze({clock_domain_id: domain, descriptor_digest: binding.runtime.descriptor_digest});
      const sample = {...value, tick_ns: String(at), runtime_domain_ref: runtimeDomain};
      if (projection === 'pairing') return Object.freeze(sample);
      const bounds = Object.freeze({policy_ref: Object.freeze({...record.policy_ref}),
        drift_ppb: record.drift_ppb, monotonic_quantization_ns: record.monotonic_quantization_ns});
      if (projection === 'duration') return Object.freeze({...sample, duration_bounds: bounds});
      return Object.freeze({...sample, ...bounds, acquisition_ref: Object.freeze(value.acquisition_ref),
        runtime_ref: Object.freeze(ref(after.runtime)), source_ref: Object.freeze({...after.policy.system_time_source_ref})});
    }
  }
  refresh();
  const timer = schedule && provider !== null ? setInterval(refresh, 500) : null; timer?.unref();
  return Object.freeze({refresh, current: () => current(), pairingSample: () => current('pairing'), durationSample: () => current('duration'),
    referenceTimeSample: () => current('reference-time'),
    status() {
      if (!failure && binding && !stopped) { try { current(); } catch {} }
      return Object.freeze({state: failure ? 'faulted' : binding && !stopped ? 'available' : 'unqualified',
        reason: failure ?? (stopped ? 'auth_clock_stopped' : provider === null ? 'auth_clock_provider_missing' : null),
        qualified: !stopped && !failure && binding !== null, durable});
    },
    stop() { stopped = true; if (timer) clearInterval(timer); }
  });
}
