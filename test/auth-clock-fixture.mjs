import crypto from 'node:crypto';
import {normalizeCapture} from '../dist/native-clock.mjs';
import {seal, ref} from '../dist/auth-clock-value.mjs';

const epoch = 116444736000000000n, wall = 1700000000000000000n;
const reference = () => ({id: crypto.randomUUID(), revision: '1', digest: 'sha256:' + 'a'.repeat(64)});
export function fixture(scope, native = null, {sampleWindowPolicy=null}={}) {
  let now = 10000000000n, w = wall, generation = '0', broken = false;
  const source = {artifactDigest: 'sha256:' + 'b'.repeat(64), tick: () => now,
    capture() {
      if (broken) throw new Error('synthetic_failure');
      return normalizeCapture({format: 'leafseamer-native-clock/1', platform: 'win32', before_100ns: String(now / 100n), after_100ns: String(now / 100n),
        wall_filetime_100ns: String(epoch + w / 100n), continuity_before: generation, continuity_after: generation, continuity_monitor: 'power_notifications'});
    },
    advance(ns) { now += ns; w += ns; }, jump(ns) { w += ns; }, resume() { generation = '1'; }, break() { broken = true; }
  };
  const p = seal({id: crypto.randomUUID(), revision: '1', service_id: scope.service_id, runtime_profile_ref: reference(), native_artifact_ref: reference(),
    system_time_source_ref: reference(), environment_approval_ref: reference(), health_profile_ref: reference(), max_system_error_ns: native?'10000000':'1000',
    wall_quantization_ns: '100', monotonic_quantization_ns: '10', drift_ppb: 1000000, capture_limit_ns: '20000000', sample_period_ns: '500000000',
    sample_ttl_ns:sampleWindowPolicy?'5000000000':'2000000000',...(sampleWindowPolicy?{sample_window_policy:sampleWindowPolicy}:{})});
  const activeSource=native?.source??source,descriptor=native?.descriptor;
  const capture=activeSource.capture(),deadline=native?String(activeSource.tick()+1000000000000n):'1000000000000';
  const r = seal({id: crypto.randomUUID(), revision: '1', ...scope, clock_domain_id: descriptor?.clock_domain_id??crypto.randomUUID(), descriptor_digest: descriptor?.descriptor_digest??'sha256:' + 'c'.repeat(64),
    policy_ref: ref(p), runtime_profile_ref: p.runtime_profile_ref, native_artifact_ref: p.native_artifact_ref, environment_approval_ref: p.environment_approval_ref,
    native_binary_digest: activeSource.artifactDigest, continuity: capture.continuity, valid_before_tick_ns: deadline});
  const h = seal({id: crypto.randomUUID(), revision: '1', ...scope, clock_domain_id: r.clock_domain_id, runtime_ref: ref(r), policy_ref: ref(p),
    health_profile_ref: p.health_profile_ref, system_time_source_ref: p.system_time_source_ref, environment_approval_ref: p.environment_approval_ref,
    state: 'synchronized', holdover_ref: null, valid_before_tick_ns: deadline});
  const evidence = {policy: p, runtime: r, health: h};
  return {source:activeSource, evidence, provider: {read: () => evidence}};
}
