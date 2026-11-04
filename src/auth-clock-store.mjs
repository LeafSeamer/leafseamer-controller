import crypto from 'node:crypto';
import {ClockError, clockInteger} from './native-clock.mjs';
import {need, canonical, same, checked, ref, seal, context, acquisition, extrapolate} from './auth-clock-value.mjs';

// 同一Controller writer连接；调用端不拥有外层事务，不能在提交前收到成功。
export function authenticationClockStore(db, scope) {
  function body(value) { const bytes = Buffer.from(canonical(value)); need(bytes.length <= 32768, 'auth_clock_size'); return bytes; }
  function decode(row) {
    if (!row) return null;
    const value = checked(JSON.parse(row[0].toString('utf8')));
    need(row[0].equals(body(value)), 'auth_clock_noncanonical'); return value;
  }
  function faultFor(domain) {
    const value = decode(db.prepare('SELECT body FROM authentication_clock_fault WHERE service_boot_id = ? AND clock_domain_id = ?').raw().get(scope.service_boot_id, domain));
    if (value) need(value.service_boot_id === scope.service_boot_id && value.clock_domain_id === domain, 'auth_clock_columns');
    return value;
  }
  function current(domain) {
    const row = db.prepare('SELECT a.body, a.id, a.digest, a.sequence FROM authentication_clock_head h JOIN authentication_clock_acquisition a ON a.id = h.acquisition_id WHERE h.service_boot_id = ? AND h.clock_domain_id = ?').raw().get(scope.service_boot_id, domain);
    const value = decode(row);
    if (value) need(value.service_id === scope.service_id && value.service_boot_id === scope.service_boot_id && value.clock_domain_id === domain &&
      value.id === row[1] && value.digest === row[2] && value.sequence.padStart(20, '0') === row[3], 'auth_clock_columns');
    return value;
  }
  function writeEvidence(kind, value) {
    const bytes = body(value), old = db.prepare('SELECT digest, kind, body FROM authentication_clock_evidence WHERE id = ? AND revision = ?').raw().get(value.id, value.revision);
    if (old) { need(old[0] === value.digest && old[1] === kind && old[2].equals(bytes), 'auth_clock_evidence_identity'); return; }
    db.prepare('INSERT INTO authentication_clock_evidence VALUES (?, ?, ?, ?, ?)').run(value.id, value.revision, value.digest, kind, bytes);
  }
  function writeFault(domain, reason) {
    const old = faultFor(domain); if (old) return old;
    const value = seal({format: 'authentication-clock-fault/1', id: crypto.randomUUID(), revision: '1',
      service_id: scope.service_id, service_boot_id: scope.service_boot_id, clock_domain_id: domain, reason});
    db.prepare('INSERT INTO authentication_clock_fault VALUES (?, ?, ?, ?, ?)').run(scope.service_boot_id, domain, value.id, value.digest, body(value));
    return value;
  }
  function transaction(fn) { need(!db.inTransaction, 'auth_clock_outer_transaction'); return db.transaction(fn).immediate(); }
  return Object.freeze({scope: Object.freeze({...scope}),
    current,
    fault(domain, reason = 'clock_unusable') {
      need(['invalid_sample', 'acquisition_failed', 'clock_unusable'].includes(reason), 'auth_clock_fault_reason');
      return transaction(() => ref(writeFault(domain, reason)));
    },
    ingest(capture, evidence, source, readContext, id = crypto.randomUUID()) {
      // evidence来自受监督入口，在采样前后已校验；失败时只用入口域写故障，不从坏采样猜域。
      need(typeof readContext === 'function', 'auth_clock_context_reader');
      const domain = evidence.runtime.clock_domain_id;
      return transaction(() => {
        const oldFault = faultFor(domain);
        if (oldFault) return {state: 'protected', fault_ref: ref(oldFault), acquisition_ref: null};
        db.exec('SAVEPOINT auth_clock_ingest');
        try {
          const now = source.tick(); context(evidence, scope, source.artifactDigest, now);
          const old = decode(db.prepare('SELECT body FROM authentication_clock_acquisition WHERE id = ?').raw().get(id));
          if (old) {
            need(old.service_boot_id === scope.service_boot_id && old.clock_domain_id === domain && same(old.raw, capture.raw) &&
              same(old.policy_ref, ref(evidence.policy)) && same(old.runtime_ref, ref(evidence.runtime)) && same(old.health_evidence_ref, ref(evidence.health)), 'auth_clock_identity');
            db.exec('RELEASE auth_clock_ingest');
            return {state: 'stored', acquisition_ref: ref(old), fault_ref: null, replay: true};
          }
          const value = acquisition(capture, evidence, current(domain), id);
          extrapolate(value, now);
          for (const key of ['policy', 'runtime', 'health']) writeEvidence(key, evidence[key]);
          const p = value.policy_ref, r = value.runtime_ref, h = value.health_evidence_ref;
          db.prepare('INSERT INTO authentication_clock_acquisition VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
            .run(value.id, value.revision, value.digest, scope.service_boot_id, domain, value.sequence.padStart(20, '0'), value.parent_ref?.id ?? null,
              p.id, p.revision, p.digest, r.id, r.revision, r.digest, h.id, h.revision, h.digest, body(value));
          db.prepare('INSERT INTO authentication_clock_head VALUES (?, ?, ?) ON CONFLICT(service_boot_id, clock_domain_id) DO UPDATE SET acquisition_id = excluded.acquisition_id')
            .run(scope.service_boot_id, domain, value.id);
          // 提交前再读tick和提供者；新采样不得因写入延迟取得额外有效期。
          const latest = readContext(); context(latest, scope, source.artifactDigest, source.tick());
          need(same(latest, evidence), 'auth_clock_context_changed');
          extrapolate(value, source.tick());
          db.exec('RELEASE auth_clock_ingest');
          return {state: 'stored', acquisition_ref: ref(value), fault_ref: null, replay: false};
        } catch (error) {
          db.exec('ROLLBACK TO auth_clock_ingest'); db.exec('RELEASE auth_clock_ingest');
          if (!(error instanceof ClockError)) throw error;
          return {state: 'protected', acquisition_ref: null, fault_ref: ref(writeFault(domain, 'invalid_sample'))};
        }
      });
    },
    read(domain, now, evidence, artifactDigest) {
      need(!faultFor(domain), 'auth_clock_fault_latched'); context(evidence, scope, artifactDigest, now);
      const value = current(domain); need(value !== null, 'auth_clock_missing');
      need(same(value.policy_ref, ref(evidence.policy)) && same(value.runtime_ref, ref(evidence.runtime)), 'auth_clock_binding');
      // 从库中解析原件和依赖，不只比较调用方的Ref字符串。
      for (const [kind, key] of [['policy', 'policy_ref'], ['runtime', 'runtime_ref'], ['health', 'health_evidence_ref']]) {
        const wanted = value[key];
        const row = db.prepare('SELECT body, kind FROM authentication_clock_evidence WHERE id = ? AND revision = ? AND digest = ?').raw().get(wanted.id, wanted.revision, wanted.digest);
        const original = decode(row); need(original && row[1] === kind && same(ref(original), wanted), 'auth_clock_evidence_missing');
      }
      const deadline = [value.valid_before_tick_ns, evidence.runtime.valid_before_tick_ns, evidence.health.valid_before_tick_ns]
        .map(clockInteger).reduce((a, b) => a < b ? a : b);
      return {acquisition_ref: ref(value), ...extrapolate(value, now), valid_before_tick_ns: String(deadline)};
    }
  });
}
