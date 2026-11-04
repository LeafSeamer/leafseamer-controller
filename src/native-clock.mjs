import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const max = (1n << 64n) - 1n, billion = 1000000000n, filetimeEpoch = 116444736000000000n;
export class ClockError extends Error { constructor(code) { super(code); this.name = 'ClockError'; this.code = code; } }
const check = (ok, code) => { if (!ok) throw new ClockError(code); };
export function clockInteger(value) {
  check(typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && value.trim() === value, 'clock_integer');
  const number = BigInt(value); check(number <= max, 'clock_integer'); return number;
}
const bounded = n => { check(n >= 0n && n <= max, 'clock_overflow'); return n; };
function fields(raw, names) { check(Object.keys(raw).sort().join(',') === names.sort().join(','), 'clock_frame'); }
export function normalizeCapture(raw) {
  check(raw && typeof raw === 'object' && raw.format === 'leafseamer-native-clock/1', 'clock_frame');
  let a, b, w, continuity;
  if (raw.platform === 'win32') {
    fields(raw, ['format', 'platform', 'before_100ns', 'wall_filetime_100ns', 'after_100ns', 'continuity_before', 'continuity_after', 'continuity_monitor']);
    a = bounded(clockInteger(raw.before_100ns) * 100n); b = bounded(clockInteger(raw.after_100ns) * 100n);
    w = bounded((clockInteger(raw.wall_filetime_100ns) - filetimeEpoch) * 100n);
    check(['power_notifications', 'unavailable'].includes(raw.continuity_monitor), 'clock_frame');
    check(clockInteger(raw.continuity_before) === clockInteger(raw.continuity_after), 'clock_continuity');
    continuity = 'win32:' + raw.continuity_monitor + ':' + raw.continuity_after;
  } else if (raw.platform === 'linux') {
    fields(raw, ['format', 'platform', 'before_sec', 'before_nsec', 'wall_sec', 'wall_nsec', 'after_sec', 'after_nsec', 'namespace_before', 'namespace_after', 'continuity_monitor']);
    const ns = prefix => {
      const fractional = clockInteger(raw[prefix + '_nsec']); check(fractional < billion, 'clock_timespec');
      return bounded(clockInteger(raw[prefix + '_sec']) * billion + fractional);
    };
    a = ns('before'); b = ns('after'); w = ns('wall');
    check(typeof raw.namespace_before === 'string' && /^[0-9]{1,20}:[0-9]{1,20}$/.test(raw.namespace_before) && raw.namespace_before.trim() === raw.namespace_before && raw.namespace_before === raw.namespace_after, 'clock_namespace');
    check(raw.continuity_monitor === 'unavailable', 'clock_frame');
    continuity = 'linux:' + raw.namespace_after;
  } else throw new ClockError('clock_platform');
  check(b >= a, 'clock_backwards'); check(b - a <= 20000000n, 'clock_capture_budget');
  return Object.freeze({a: a.toString(), b: b.toString(), w: w.toString(), valid_before: bounded(b + 2000000000n).toString(),
    continuity, continuity_available: raw.continuity_monitor !== 'unavailable', raw: Object.freeze({...raw})});
}
export function openNativeClock() {
  try {
    const filename = fileURLToPath(new URL('./native/leafseamer_clock.node', import.meta.url));
    const manifest = JSON.parse(fs.readFileSync(new URL('./native/manifest.json', import.meta.url), 'utf8'));
    check(manifest.format === 'leafseamer-native-artifact/1' && manifest.platform === process.platform && manifest.arch === process.arch && manifest.napi_version === 8, 'native_clock_artifact');
    const digest = crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
    check(digest === manifest.binary_sha256, 'native_clock_artifact');
    const native = createRequire(import.meta.url)(filename);
    return Object.freeze({artifactDigest: 'sha256:' + digest, capture: () => normalizeCapture(native.capture()), tick: () => clockInteger(native.tick())});
  } catch (error) {
    if (error instanceof ClockError) throw error;
    throw new ClockError('native_clock_unavailable');
  }
}
