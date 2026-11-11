import {ClockError, clockInteger} from './native-clock.mjs';
import {need, canonical, same, context, captureInterval, extrapolate} from './auth-clock-value.mjs';

// provider只能由受监督本地启动装配，不能从HTTP、环境开关或采样正文取得。
// 缺少实现时保留诊断服务，不生成环境批准或运行域身份。
export function startAuthenticationClock(source, ledger, provider = null, {schedule = true} = {}) {
  let stopped = false, failure = null, durable = true, binding = null;
  function tick() {
    const value = source.tick(); need(typeof value === 'bigint' && value >= 0n && value <= (1n << 64n) - 1n, 'auth_clock_tick'); return value;
  }
  function evidence() {
    need(provider !== null, 'auth_clock_provider_missing');
    // 独立副本避免调用方在事务期间修改已校验对象。
    const snapshot = JSON.parse(canonical(provider.read()));
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
  function usable() { need(!stopped && !failure && provider !== null && binding !== null, failure ?? (stopped ? 'auth_clock_stopped' : 'auth_clock_provider_missing')); }
  function refresh() {
    if (stopped || failure || provider === null) return;
    try {
      const before = evidence();
      binding ??= before;
      const old = ledger.current(binding.runtime.clock_domain_id);
      if (old) extrapolate(old, tick());
      const captured = source.capture(), after = evidence();
      need(same(before, after), 'auth_clock_context_changed');
      const result = ledger.ingest(captured, after, source, evidence);
      need(result.state === 'stored', 'auth_clock_fault_latched');
      // COMMIT已完成也可能已过期限；此时保留原件但绝不交付可用结果。
      ledger.read(binding.runtime.clock_domain_id, tick(), evidence(), source.artifactDigest);
    } catch (error) { fail(error); }
  }
  function current(withDomain = false) {
    usable();
    try {
      const before = evidence(), now = tick(), domain = binding.runtime.clock_domain_id;
      const record = ledger.current(domain); need(record !== null, 'auth_clock_missing');
      extrapolate(record, now);
      const observation = source.capture(), after = evidence();
      need(same(before, after) && observation.continuity_available && observation.continuity === binding.runtime.continuity, 'auth_clock_context_changed');
      const observed = captureInterval(observation, before.policy), predicted = extrapolate(record, clockInteger(observation.b));
      need(clockInteger(observed.upper_ns) >= clockInteger(predicted.lower_ns) && clockInteger(observed.lower_ns) <= clockInteger(predicted.upper_ns), 'auth_clock_disjoint');
      const at = tick(), value = ledger.read(domain, at, after, source.artifactDigest);
      return Object.freeze(withDomain ? {...value, tick_ns: String(at), runtime_domain_ref: Object.freeze({clock_domain_id: domain, descriptor_digest: binding.runtime.descriptor_digest})} : value);
    } catch (error) { fail(error); throw new ClockError(failure); }
  }
  refresh();
  const timer = schedule && provider !== null ? setInterval(refresh, 500) : null; timer?.unref();
  return Object.freeze({refresh, current: () => current(), pairingSample: () => current(true),
    status() {
      if (!failure && binding && !stopped) { try { current(); } catch {} }
      return Object.freeze({state: failure ? 'faulted' : binding && !stopped ? 'available' : 'unqualified',
        reason: failure ?? (stopped ? 'auth_clock_stopped' : provider === null ? 'auth_clock_provider_missing' : null),
        qualified: !stopped && !failure && binding !== null, durable});
    },
    stop() { stopped = true; if (timer) clearInterval(timer); }
  });
}
