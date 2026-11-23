import {createHash, randomUUID} from 'node:crypto';
import canonicalize from 'canonicalize';
import {referenceTimeExitStore} from './reference-time-exits.mjs';
import {commandIssueHead} from './command-issue-order.mjs';

const digest = value => 'sha256:' + createHash('sha256').update(value).digest('hex');
const causes = new Set(['authority_changed','evidence_withdrawn','provider_lost','supervisor_lost','shutdown']);

export function referenceTimeInvalidationStore(db, bootId, binding, supervisor = null, recoveryExits = null) {
  const runtime=JSON.parse(binding.text), {clock_domain_id,descriptor_digest}=runtime.clock_domain_descriptor;
  const domain_ref={clock_domain_id,descriptor_digest};
  const schema=Number(db.pragma('user_version',{simple:true}));
  const exits=recoveryExits ?? (schema>=90 ? referenceTimeExitStore(db,bootId,domain_ref,supervisor) : null);
  let pending=null, committed=null;

  function save() {
    if (!pending || committed || !db.open || db.inTransaction) return;
    try {
      committed=db.transaction(()=>{
        const {operation_id, old_anchor_ref, source_digest, source_slot, cause}=pending;
        const outstanding=db.prepare(`SELECT p.poll_id,p.body_digest,a.attempt_id FROM time_provider_poll_reservation p
          LEFT JOIN time_provider_poll_attempt a USING(poll_id) LEFT JOIN time_provider_poll_release r USING(poll_id)
          LEFT JOIN time_provider_control_release c USING(poll_id)
          WHERE p.service_boot_id=? AND p.source_digest=? AND r.poll_id IS NULL AND c.poll_id IS NULL ORDER BY p.poll_id`)
          .raw().all(bootId,source_digest).map(([id,digest,attempt_id])=>({poll_ref:{id,digest},attempt_id}));
        const body={format:'leafseamer-reference-invalidation/1',operation_id,service_boot_id:bootId,runtime_digest:binding.digest,
          domain_ref,old_anchor_ref,source_digest,source_slot,cause,old_time_generation:'1',minimum_time_generation:'2',
          state:'unavailable',outstanding};
        const text=canonicalize(body), value=digest(text), invalidation_ref={id:operation_id,revision:'1',digest:value};
        const work=canonicalize({format:'leafseamer-reference-protection-pending/1',invalidation_ref,domain_ref,minimum_time_generation:'2',
          ...(schema>=92 && {issued_cut_revision:commandIssueHead(db)})});
        const inserted=db.prepare('INSERT INTO time_provider_reference_invalidation VALUES (?,?,?,?,?,?,?,?,?)').run(
          operation_id,bootId,source_digest,source_slot,old_anchor_ref.id,old_anchor_ref.digest,cause,text,value);
        exits?.capture(invalidation_ref);
        const queued=db.prepare('INSERT INTO time_provider_reference_protection VALUES (?,?,?,?)').run(operation_id,value,work,digest(work));
        if(inserted.changes!==1 || queued.changes!==1) throw new Error('reference_time_invalidation_storage');
        return invalidation_ref;
      }).immediate();
    } catch { /* Keep the in-process denial when the durable writer is unavailable. */ }
  }

  return Object.freeze({
    deny(prior,cause) {
      if (!prior || !causes.has(cause)) return;
      if (!pending) {
        const old_anchor_ref={id:prior.body.anchor_id,revision:'1',digest:prior.digest};
        pending={operation_id:randomUUID(),old_anchor_ref,source_digest:prior.body.approval.source_digest,source_slot:prior.body.source_slot,cause};
        if(db.inTransaction) queueMicrotask(save);
      }
      save();
    },
    flush:save,
    async reconcile() { if(recoveryExits)await exits.reconcile(); else if(committed && exits) await exits.reconcile(committed.id); },
    assertCollectionAllowed(facts) {
      if (pending && (pending.source_slot===facts.source_slot || pending.source_digest===facts.source_digest)) {
        throw new Error('time_provider_poll_reference_invalidated');
      }
    },
    status() {
      return {state:pending?'unavailable':'no_invalidation',cause:pending?.cause??null,durable:committed!==null,
        operation_id:pending?.operation_id??null,invalidation_ref:committed?{...committed}:null,
        protection_state:pending?'pending':null,...(exits && {exits:committed?exits.status(committed.id):null})};
    }
  });
}
