import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {ClockError, clockInteger, normalizeCapture} from './native-clock.mjs';

const N = 1000000000n, MAX = (1n << 64n) - 1n;
export const need = (ok, code) => { if (!ok) throw new ClockError(code); };
const exact = (text, pattern) => typeof text === 'string' && text.trim() === text && pattern.test(text);
const uuid = value => exact(value, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
const hash = value => exact(value, /^sha256:[0-9a-f]{64}$/);
export function fields(value, names) {
  need(value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...names].sort().join(','), 'auth_clock_shape');
}
export function bounded(value) { need(value >= 0n && value <= MAX, 'auth_clock_range'); return value; }
export const ceil = (value, divisor) => (value + divisor - 1n) / divisor;
export const canonical = value => canonicalize(value);
export const digest = value => 'sha256:' + crypto.createHash('sha256').update(canonical(value)).digest('hex');
export const same = (a, b) => canonical(a) === canonical(b);
export function reference(value) {
  fields(value, ['id', 'revision', 'digest']);
  need(uuid(value.id) && clockInteger(value.revision) > 0n && hash(value.digest), 'auth_clock_ref');
  return value;
}
export function ref(value) { return reference({id: value.id, revision: value.revision, digest: value.digest}); }
export function seal(body) { return {...body, digest: digest(body)}; }
export function checked(value) {
  need(value && typeof value === 'object', 'auth_clock_object');
  const {digest: actual, ...body} = value;
  need(hash(actual) && actual === digest(body), 'auth_clock_digest'); ref(value);
  return value;
}
export function policy(value) {
  fields(value, ['id', 'revision', 'digest', 'service_id', 'runtime_profile_ref', 'native_artifact_ref', 'system_time_source_ref',
    'environment_approval_ref', 'max_system_error_ns', 'wall_quantization_ns', 'monotonic_quantization_ns', 'drift_ppb',
    'capture_limit_ns', 'sample_period_ns', 'sample_ttl_ns', 'health_profile_ref']);
  checked(value); need(uuid(value.service_id), 'auth_clock_service');
  for (const key of ['runtime_profile_ref', 'native_artifact_ref', 'system_time_source_ref', 'environment_approval_ref', 'health_profile_ref']) reference(value[key]);
  for (const key of ['max_system_error_ns', 'wall_quantization_ns', 'monotonic_quantization_ns']) need(clockInteger(value[key]) > 0n, 'auth_clock_error_bound');
  need(Number.isSafeInteger(value.drift_ppb) && value.drift_ppb >= 0 && value.drift_ppb <= 1000000, 'auth_clock_drift');
  need(value.capture_limit_ns === '20000000' && value.sample_period_ns === '500000000' && value.sample_ttl_ns === '2000000000', 'auth_clock_profile');
  return value;
}

// 调用方是受监督本地提供者；这里只核验已解析原件的绑定，不自行授予安装或环境批准。
export function context(value, scope, artifactDigest, now) {
  need(typeof now === 'bigint' && now >= 0n && now <= MAX, 'auth_clock_tick');
  fields(value, ['policy', 'runtime', 'health']);
  const p = policy(value.policy), r = checked(value.runtime), h = checked(value.health);
  fields(r, ['id', 'revision', 'digest', 'service_id', 'service_boot_id', 'clock_domain_id', 'descriptor_digest', 'policy_ref',
    'runtime_profile_ref', 'native_artifact_ref', 'environment_approval_ref', 'native_binary_digest', 'continuity', 'valid_before_tick_ns']);
  fields(h, ['id', 'revision', 'digest', 'service_id', 'service_boot_id', 'clock_domain_id', 'runtime_ref', 'policy_ref',
    'health_profile_ref', 'system_time_source_ref', 'environment_approval_ref', 'state', 'holdover_ref', 'valid_before_tick_ns']);
  need(p.service_id === scope.service_id && r.service_id === scope.service_id && r.service_boot_id === scope.service_boot_id &&
    h.service_id === scope.service_id && h.service_boot_id === scope.service_boot_id, 'auth_clock_scope');
  need((uuid(r.clock_domain_id) || r.clock_domain_id === 'clock_' + r.descriptor_digest?.slice(7)) && h.clock_domain_id === r.clock_domain_id && hash(r.descriptor_digest) &&
    r.native_binary_digest === artifactDigest && hash(artifactDigest), 'auth_clock_runtime');
  need(typeof r.continuity === 'string' && r.continuity.length > 0 && r.continuity.length <= 128, 'auth_clock_continuity');
  for (const key of ['runtime_profile_ref', 'native_artifact_ref', 'environment_approval_ref']) need(same(r[key], p[key]), 'auth_clock_binding');
  for (const key of ['health_profile_ref', 'system_time_source_ref', 'environment_approval_ref']) need(same(h[key], p[key]), 'auth_clock_binding');
  need(same(r.policy_ref, ref(p)) && same(h.policy_ref, ref(p)) && same(h.runtime_ref, ref(r)), 'auth_clock_binding');
  need(h.state === 'synchronized' && h.holdover_ref === null || h.state === 'holdover' && h.holdover_ref !== null, 'auth_clock_health');
  if (h.holdover_ref !== null) reference(h.holdover_ref);
  need(now < clockInteger(r.valid_before_tick_ns) && now < clockInteger(h.valid_before_tick_ns), 'auth_clock_evidence_expired');
  return value;
}
export function captureInterval(capture, p) {
  // 重算原始平台输入，不能相信调用方自报归一化字段。
  const c = normalizeCapture(capture.raw); need(same(c, capture), 'auth_clock_capture'); policy(p);
  const a = clockInteger(c.a), b = clockInteger(c.b), w = clockInteger(c.w);
  const E = clockInteger(p.max_system_error_ns), qw = clockInteger(p.wall_quantization_ns), qm = clockInteger(p.monotonic_quantization_ns), d = BigInt(p.drift_ppb);
  const Q = ceil(qm * (N + d), N), D = ceil((b - a + 2n * qm) * (N + d), N);
  return {lower_ns: String(bounded(w - E - qw - 2n * Q)), upper_ns: String(bounded(w + E + qw + D + 2n * Q))};
}
export function extrapolate(record, now) {
  const b = clockInteger(record.b), before = clockInteger(record.valid_before_tick_ns);
  need(typeof now === 'bigint' && now >= b && now < before, 'auth_clock_expired');
  const dt = now - b, d = BigInt(record.drift_ppb);
  return {lower_ns: String(bounded(clockInteger(record.effective_lower_ns) + dt * (N - d) / N)),
    upper_ns: String(bounded(clockInteger(record.effective_upper_ns) + ceil(dt * (N + d), N)))};
}
export function acquisition(capture, evidence, previous = null, id = crypto.randomUUID()) {
  const {policy: p, runtime: r, health: h} = evidence, bounds = captureInterval(capture, p);
  need(uuid(id) && capture.continuity_available && capture.continuity === r.continuity, 'auth_clock_continuity');
  let lower = clockInteger(bounds.lower_ns), upper = clockInteger(bounds.upper_ns);
  if (previous) {
    need(same(previous.policy_ref, ref(p)) && same(previous.runtime_ref, ref(r)) && previous.continuity === capture.continuity &&
      clockInteger(capture.b) > clockInteger(previous.b) && clockInteger(capture.a) >= clockInteger(previous.b), 'auth_clock_transition');
    const old = extrapolate(previous, clockInteger(capture.b)), lo = clockInteger(old.lower_ns), hi = clockInteger(old.upper_ns);
    need(upper >= lo && lower <= hi, 'auth_clock_disjoint');
    lower = lower > lo ? lower : lo; upper = upper > hi ? upper : hi;
  }
  return seal({format: 'authentication-clock-acquisition/1', id, revision: '1', service_id: p.service_id,
    service_boot_id: r.service_boot_id, clock_domain_id: r.clock_domain_id, descriptor_digest: r.descriptor_digest,
    policy_ref: ref(p), runtime_ref: ref(r), native_artifact_ref: p.native_artifact_ref, environment_approval_ref: p.environment_approval_ref,
    health_evidence_ref: ref(h), a: capture.a, b: capture.b, raw: capture.raw, w: capture.w, continuity: capture.continuity,
    max_system_error_ns: p.max_system_error_ns, wall_quantization_ns: p.wall_quantization_ns,
    monotonic_quantization_ns: p.monotonic_quantization_ns, drift_ppb: p.drift_ppb,
    lower_ns: bounds.lower_ns, upper_ns: bounds.upper_ns, effective_lower_ns: String(lower), effective_upper_ns: String(upper),
    valid_before_tick_ns: capture.valid_before, sequence: String(bounded(previous ? clockInteger(previous.sequence) + 1n : 1n)),
    parent_ref: previous ? ref(previous) : null});
}
