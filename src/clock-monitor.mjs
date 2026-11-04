import {ClockError, clockInteger} from './native-clock.mjs';

// 采集事实不是认证资格。运行域、环境误差、健康来源尚未装载时不产生可信区间。
export function startClockMonitor(source, journal, {schedule = true} = {}) {
  let previous = null, stopped = false, durable = true;
  let fault = journal.current().state === 'faulted' ? journal.current().reason : null;
  function fail(reason) {
    if (!fault) {
      fault = reason;
      try { journal.fault(reason); } catch { durable = false; }
    }
  }
  function currentTick() {
    const now = source.tick();
    if (typeof now !== 'bigint' || now < 0n || now > (1n << 64n) - 1n) throw new ClockError('clock_integer');
    if (previous && (now < clockInteger(previous.b) || now >= clockInteger(previous.valid_before))) throw new ClockError('clock_sample_expired');
    return now;
  }
  function refresh() {
    if (stopped || fault) return;
    try {
      currentTick();
      const capture = source.capture(), now = source.tick();
      if (now < clockInteger(capture.b) || now >= clockInteger(capture.valid_before)) throw new ClockError('clock_sample_expired');
      if (previous && (clockInteger(capture.a) < clockInteger(previous.b) || capture.continuity !== previous.continuity)) throw new ClockError('clock_continuity');
      if (previous && clockInteger(capture.w) < clockInteger(previous.w)) throw new ClockError('clock_wall_regressed');
      journal.sample(capture, source.artifactDigest);
      previous = capture;
    } catch (error) { fail(error instanceof ClockError ? error.code : 'clock_source_or_journal_failure'); }
  }
  refresh();
  const timer = schedule ? setInterval(refresh, 500) : null;
  timer?.unref();
  return Object.freeze({
    refresh,
    status() {
      if (!fault && !stopped) {
        try {
          currentTick();
          const observation = source.capture();
          if (previous && observation.continuity !== previous.continuity) throw new ClockError('clock_continuity');
          if (previous && clockInteger(observation.w) < clockInteger(previous.w)) throw new ClockError('clock_wall_regressed');
          currentTick();
        } catch (error) { fail(error instanceof ClockError ? error.code : 'clock_source_or_journal_failure'); }
      }
      return Object.freeze({state: fault ? 'faulted' : 'unqualified', reason: fault ?? (stopped ? 'clock_stopped' : 'clock_approval_missing'), qualified: false, durable});
    },
    stop() { stopped = true; if (timer) clearInterval(timer); }
  });
}
