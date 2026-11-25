import {createHash, randomUUID} from 'node:crypto';
import canonicalize from 'canonicalize';
import {referenceExitCutRef,referenceTimeExitStore} from './reference-time-exits.mjs';
import {commandIssueHead} from './command-issue-order.mjs';

const digest = value => 'sha256:' + createHash('sha256').update(value).digest('hex');
const causes = new Set(['authority_changed','evidence_withdrawn','provider_lost','supervisor_lost','shutdown']);
const ref = (id,digest) => ({id,revision:'1',digest});
const same = (a,b) => canonicalize(a)===canonicalize(b);

function original(text,checksum) {
  const value=JSON.parse(text);
  if(canonicalize(value)!==text||digest(text)!==checksum)throw new Error('reference_time_fence_source');
  return value;
}

function wireInvalidation(body,cause_ref,protection_operation_ref) {
  const value={invalidation_id:body.operation_id+'.time',revision:'1',old_binding:body.old_binding,next_time_generation:body.minimum_time_generation,
    cause_ref,deny_new_utc_permits:true,protection_operation_ref};
  return {...value,invalidation_digest:digest(canonicalize(value))};
}

export function readReferenceTimeFenceSource(db,operationId) {
  const row=db.prepare(`SELECT
    i.body_jcs,i.body_digest,p.body_jcs,p.body_digest,c.body_jcs,c.body_digest,i.service_boot_id
    FROM time_provider_reference_invalidation i
    JOIN time_provider_reference_protection p USING(operation_id)
    JOIN time_provider_reference_exit_cut c USING(operation_id) WHERE i.operation_id=?`).raw().get(operationId);
  if(!row)return null;
  const [invalidationText,invalidationDigest,workText,workDigest,cutText,cutDigest,bootId]=row;
  const work=original(workText,workDigest);
  if(!work.wire_invalidation_ref)return null;
  const causeRef=ref(operationId,invalidationDigest),cutRef=referenceExitCutRef(operationId,cutDigest);
  const body=original(invalidationText,invalidationDigest),cut=original(cutText,cutDigest);
  const invalidation=wireInvalidation(body,causeRef,cutRef);
  if(body.operation_id!==operationId||body.service_boot_id!==bootId||!body.old_binding||
    !same(work.invalidation_ref,causeRef)||!same(cut.invalidation_ref,causeRef)||!same(work.exit_cut_ref,cutRef)||
    !same(work.domain_ref,body.domain_ref)||!same(cut.domain_ref,body.domain_ref)||
    work.minimum_time_generation!==body.minimum_time_generation||
    !same(work.wire_invalidation_ref,ref(invalidation.invalidation_id,invalidation.invalidation_digest)))throw new Error('reference_time_fence_source');
  return {invalidation,issued_cut_revision:work.issued_cut_revision,targets:cut.targets};
}

export function referenceTimeInvalidationStore(db, bootId, binding, supervisor = null, recoveryExits = null) {
  const runtime=JSON.parse(binding.text), {clock_domain_id,descriptor_digest}=runtime.clock_domain_descriptor;
  const domain_ref={clock_domain_id,descriptor_digest};
  const schema=Number(db.pragma('user_version',{simple:true}));
  const exits=recoveryExits ?? (schema>=90 ? referenceTimeExitStore(db,bootId,domain_ref,supervisor) : null);
  let pending=null, committed=null;

  function oldTimeBinding(read,sourceDigest){
    if(!exits||schema<92||!read)return null;
    try{
      const value=read(),domain=value.domain;
      if(value.time_generation==='1'&&value.source_ref.digest===sourceDigest&&
          domain.authority_service_id===runtime.service_id&&domain.database_instance_id===runtime.database_instance_id&&
          domain.provider_id===runtime.launch_intent.member_id&&domain.provider_boot_id===runtime.admission_receipt.member_boot_id&&
          domain.runtime_binding_ref.id===runtime.runtime_binding_id&&domain.runtime_binding_ref.digest===binding.digest&&
          domain.clock_domain_id===clock_domain_id&&domain.descriptor_digest===descriptor_digest)return value;
    }catch{ /* An unavailable historical bundle cannot supply device IPC. */ }
    return null;
  }

  function save() {
    if (!pending || committed || !db.open || db.inTransaction) return;
    try {
      committed=db.transaction(()=>{
        const {operation_id, old_anchor_ref, source_digest, source_slot, cause, readOldBinding}=pending;
        const outstanding=db.prepare(`SELECT p.poll_id,p.body_digest,a.attempt_id FROM time_provider_poll_reservation p
          LEFT JOIN time_provider_poll_attempt a USING(poll_id) LEFT JOIN time_provider_poll_release r USING(poll_id)
          LEFT JOIN time_provider_control_release c USING(poll_id)
          WHERE p.service_boot_id=? AND p.source_digest=? AND r.poll_id IS NULL AND c.poll_id IS NULL ORDER BY p.poll_id`)
          .raw().all(bootId,source_digest).map(([id,digest,attempt_id])=>({poll_ref:{id,digest},attempt_id}));
        const old_binding=oldTimeBinding(readOldBinding,source_digest);
        const body={format:'leafseamer-reference-invalidation/1',operation_id,service_boot_id:bootId,runtime_digest:binding.digest,
          domain_ref,old_anchor_ref,source_digest,source_slot,cause,old_time_generation:'1',minimum_time_generation:'2',
          state:'unavailable',outstanding,...(old_binding&&{old_binding})};
        const text=canonicalize(body), value=digest(text), invalidation_ref=ref(operation_id,value);
        const inserted=db.prepare('INSERT INTO time_provider_reference_invalidation VALUES (?,?,?,?,?,?,?,?,?)').run(
          operation_id,bootId,source_digest,source_slot,old_anchor_ref.id,old_anchor_ref.digest,cause,text,value);
        const exit_cut_ref=exits?.capture(invalidation_ref);
        let wire_invalidation_ref=null;
        if(old_binding&&exit_cut_ref){
          const wire=wireInvalidation(body,invalidation_ref,exit_cut_ref);
          wire_invalidation_ref=ref(wire.invalidation_id,wire.invalidation_digest);
        }
        const work=canonicalize({format:'leafseamer-reference-protection-pending/1',invalidation_ref,domain_ref,minimum_time_generation:'2',
          ...(schema>=92 && {issued_cut_revision:commandIssueHead(db)}),
          ...(wire_invalidation_ref&&{wire_invalidation_ref,exit_cut_ref})});
        const queued=db.prepare('INSERT INTO time_provider_reference_protection VALUES (?,?,?,?)').run(operation_id,value,work,digest(work));
        if(inserted.changes!==1 || queued.changes!==1) throw new Error('reference_time_invalidation_storage');
        return invalidation_ref;
      }).immediate();
    } catch { /* Keep the in-process denial when the durable writer is unavailable. */ }
  }

  function fenceSource() {
    if(!committed||!db.open||schema<92)return null;
    const source=readReferenceTimeFenceSource(db,committed.id);
    if(source&&!same(source.invalidation.cause_ref,committed))throw new Error('reference_time_fence_source');
    return source;
  }

  return Object.freeze({
    deny(prior,cause,readOldBinding) {
      if (!prior || !causes.has(cause)) return;
      if (!pending) {
        const old_anchor_ref={id:prior.body.anchor_id,revision:'1',digest:prior.digest};
        pending={operation_id:randomUUID(),old_anchor_ref,source_digest:prior.body.approval.source_digest,source_slot:prior.body.source_slot,cause,readOldBinding};
        if(db.inTransaction) queueMicrotask(save);
      }
      save();
    },
    flush:save,
    fenceSource,
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
