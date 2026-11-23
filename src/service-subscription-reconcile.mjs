import {canonical, digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {validateEventTimeModel} from './sdk/event-time.mjs';

const pageSize = 16;
const need = (condition, reason) => {
  if (!condition) throw new IdentityError('subscription_reconcile_' + reason);
};

function readDocument(body, expectedDigest) {
  let value;
  try { value = JSON.parse(body); }
  catch { throw new IdentityError('subscription_reconcile_integrity'); }
  need(canonical(value) === body && digest(value) === expectedDigest, 'integrity');
  return value;
}

export function subscriptionReconcile(db) {
  function window(subscriptionId) {
    const row = db.prepare('SELECT start_sequence,end_sequence FROM service_subscription_reconcile WHERE subscription_id=?').raw().get(subscriptionId);
    need(row, 'window');
    return row;
  }

  return Object.freeze({
    reserve(subscriptionId, baselineJournal) {
      need(db.inTransaction, 'writer');
      const end = db.prepare('SELECT coalesce(max(sequence),0) FROM device_source_notification').pluck().get();
      const start = Number(baselineJournal);
      need(String(start) === baselineJournal && Number.isSafeInteger(start) && start >= 0 &&
        Number.isSafeInteger(end) && end >= start, 'journal');
      const inserted = db.prepare('INSERT INTO service_subscription_reconcile VALUES(?,?,?)').run(subscriptionId, start, end);
      need(inserted.changes === 1, 'storage');
    },

    follow(subscriptionId,generation){
      need(db.inTransaction,'writer');
      const inserted=db.prepare(`INSERT INTO service_subscription_follow
        SELECT ?,?,coalesce(max(sequence),0) FROM device_source_notification`).run(subscriptionId,generation);
      need(inserted.changes===1,'storage');
    },

    prepare(subscriptionId, afterCursor, generation, mode, limit=pageSize) {
      need(db.inTransaction, 'writer');
      need(typeof afterCursor === 'string' && /^(0|[1-9][0-9]{0,4})$/.test(afterCursor), 'cursor');
      need(Number.isInteger(limit) && limit >= 1 && limit <= pageSize, 'page_size');
      const [start] = window(subscriptionId);
      const follow=db.prepare('SELECT end_sequence FROM service_subscription_follow WHERE subscription_id=? AND connection_generation=?').pluck().get(subscriptionId,generation);
      need(follow!==undefined,'window');
      const end=mode==='live'?db.prepare('SELECT coalesce(max(sequence),0) FROM device_source_notification').pluck().get():follow;
      const after = Number(afterCursor);
      const [lastCursor,lastSequence]=db.prepare(`SELECT coalesce(max(cursor),0),coalesce(max(journal_sequence),?)
        FROM service_subscription_delivery WHERE subscription_id=?`).raw().get(start,subscriptionId);
      need(after <= lastCursor, 'cursor');

      if (after === lastCursor) {
        const rows = db.prepare(`SELECT n.sequence,n.entry_kind,n.registration_id,n.body_jcs,n.body_digest,e.origin_jcs,e.origin_digest
          FROM device_source_notification n JOIN service_event_subscription_pin p
          ON p.registration_id=n.registration_id AND p.subscription_id=?
          LEFT JOIN device_source_event e ON e.record_id=n.event_id AND e.registration_id=n.registration_id
          WHERE n.sequence>? AND n.sequence<=? ORDER BY n.sequence LIMIT ?`).raw().all(subscriptionId,lastSequence,end,limit);
        let cursor = lastCursor;
        const insert = db.prepare('INSERT INTO service_subscription_delivery VALUES(?,?,?,?,?,NULL)');
        for (const [sequence, kind, registrationId, body, hash, original, originDigest] of rows) {
          const value = readDocument(body, hash);
          let payload = value;
          if (kind === 'source.event') {
            const origin = readDocument(original, originDigest);
            need(Object.keys(value).join(',') === 'origin' && canonical(value.origin) === original && origin.source_key.registration_id === registrationId, 'integrity');
            try { validateEventTimeModel('Origin', origin); }
            catch { throw new IdentityError('subscription_reconcile_integrity'); }
            payload = {origin, origin_digest:originDigest};
          } else {
            need(kind === 'entity.upsert' && value.entity_kind === 'sources' && value.entity_id === registrationId, 'integrity');
          }
          const entry = {entry_kind:kind, payload};
          const encoded = canonical(entry);
          need(Buffer.byteLength(encoded) <= 65536, 'frame_capacity');
          need(insert.run(subscriptionId, ++cursor, sequence, encoded, digest(entry)).changes === 1, 'storage');
        }
      }

      return db.prepare(`SELECT cursor,body_jcs,body_digest FROM service_subscription_delivery
        WHERE subscription_id=? AND cursor>? ORDER BY cursor LIMIT ?`).raw().all(subscriptionId,after,limit)
        .map(([cursor, body, hash]) => ({
          cursor:String(cursor), previous_cursor:String(cursor - 1), entry:readDocument(body, hash), payload_digest:hash.slice(7)
        }));
    },

    checkpoint(subscriptionId, afterCursor, baselineSnapshotId,generation) {
      need(db.inTransaction, 'writer');
      const existing = db.prepare('SELECT 1 FROM service_subscription_delivery WHERE subscription_id=? AND checkpoint_generation=?')
        .pluck().get(subscriptionId,generation);
      if (existing) return null;
      const cursor = Number(afterCursor) + 1;
      const entry = {entry_kind:'sync.ready', payload:{baseline_snapshot_id:baselineSnapshotId}};
      const hash = digest(entry);
      const inserted = db.prepare('INSERT INTO service_subscription_delivery VALUES(?,?,NULL,?,?,?)')
        .run(subscriptionId, cursor, canonical(entry), hash,generation);
      need(inserted.changes === 1, 'storage');
      return {cursor:String(cursor),previous_cursor:afterCursor,entry,payload_digest:hash.slice(7)};
    }
  });
}
