import {createHash} from 'node:crypto';
import canonicalize from 'canonicalize';

const digest = text => 'sha256:' + createHash('sha256').update(text).digest('hex');
const same = (a,b) => canonicalize(a)===canonicalize(b);
const need = ok => { if(!ok) throw new Error('reference_time_exit_binding'); };
const ref = (id,digest) => ({id,revision:'1',digest});
export const referenceExitCutRef = (operationId,digest) => ref(operationId+'.exit-cut',digest);

function original(text,checksum) {
  const value=JSON.parse(text);
  need(canonicalize(value)===text && digest(text)===checksum);
  return value;
}

export function referenceTimeExitStore(db, bootId, domain, supervisor, receiverReceiptId = null) {
  let cursor=['',''], running=null;

  function capture(invalidation) {
    need(db.inTransaction);
    const rows=db.prepare(`SELECT b.binding_id,b.body_jcs,b.body_digest,b.writer_exit_id,b.device_id,s.ipc_session_id,r.runtime_id,
      r.body_jcs,r.body_digest,p.launch_id,p.intent_digest FROM device_execution_binding b
      JOIN execution_session s USING(ipc_session_id) JOIN worker_runtime_binding r USING(runtime_id)
      JOIN worker_launch_preparation p USING(launch_id)
      WHERE s.service_boot_id=? AND s.clock_domain_id=? AND s.descriptor_digest=? ORDER BY b.writer_exit_id COLLATE BINARY LIMIT 257`)
      .raw().all(bootId,domain.clock_domain_id,domain.descriptor_digest);
    need(rows.length<=256);
    const insert=db.prepare('INSERT INTO time_provider_reference_exit_target VALUES (?,?,?,?,?,?)');
    for(const [id,body,checksum,exit_id,device_id,ipc_session_id,runtime_id,runtimeText,runtimeDigest,launch_id,launch_intent_digest] of rows){
      const binding=original(body,checksum).binding, runtime=original(runtimeText,runtimeDigest);
      need(binding.writer_exit_id===exit_id && binding.device_id===device_id && binding.ipc_session_id===ipc_session_id &&
        binding.clock_domain_id===domain.clock_domain_id && binding.descriptor_digest===domain.descriptor_digest &&
        runtime.launch_intent.launch_id===launch_id && digest(canonicalize(runtime.launch_intent))===launch_intent_digest);
      const target={exit_id,device_id,ipc_session_id,device_binding_ref:ref(id,checksum),runtime_ref:ref(runtime_id,runtimeDigest),
        launch_key:{launch_id,launch_intent_digest}};
      const text=canonicalize(target);
      need(insert.run(invalidation.id,exit_id,id,ipc_session_id,text,digest(text)).changes===1);
    }
    const targets=db.prepare('SELECT exit_id,body_digest FROM time_provider_reference_exit_target WHERE operation_id=? ORDER BY exit_id COLLATE BINARY')
      .raw().all(invalidation.id).map(([id,digest])=>ref(id,digest));
    const cut={format:'leafseamer-reference-exit-cut/1',invalidation_ref:invalidation,domain_ref:domain,targets};
    const text=canonicalize(cut);
    const checksum=digest(text);
    need(db.prepare('INSERT INTO time_provider_reference_exit_cut VALUES (?,?,?,?,?)').run(invalidation.id,invalidation.digest,
      targets.length,text,checksum).changes===1);
    return referenceExitCutRef(invalidation.id,checksum);
  }

  function status(operationId) {
    if(!db.open) return null;
    const count=db.prepare('SELECT target_count FROM time_provider_reference_exit_cut WHERE operation_id=?').pluck().get(operationId);
    if(count===undefined) return null;
    const retired=db.prepare('SELECT count(*) FROM time_provider_reference_exit_retired WHERE operation_id=?').pluck().get(operationId);
    if(Number(db.pragma('user_version',{simple:true}))>=112){
      const acknowledged=db.prepare("SELECT count(*) FROM execution_time_fence_frame WHERE operation_id=? AND phase='ack'").pluck().get(operationId);
      return {target_count:count,retired_count:retired,acknowledged_count:acknowledged};
    }
    return {target_count:count,retired_count:retired};
  }

  async function observe(operationId = null) {
    if(!db.open || db.inTransaction || !supervisor) return;
    const next=db.prepare(`SELECT t.operation_id,t.exit_id,t.body_jcs,t.body_digest,
      r.body_jcs,r.body_digest,s.service_boot_id,s.clock_domain_id,s.descriptor_digest,c.receipt_jcs
      FROM time_provider_reference_exit_target t JOIN time_provider_reference_protection p USING(operation_id)
      JOIN execution_session s USING(ipc_session_id) JOIN worker_runtime_binding r USING(runtime_id)
      JOIN core_runtime_binding c ON c.service_boot_id=s.service_boot_id
      LEFT JOIN time_provider_reference_exit_retired a USING(operation_id,exit_id)
      WHERE (? IS NULL OR t.operation_id=?) AND a.exit_id IS NULL
      ORDER BY ((t.operation_id,t.exit_id)<=(?,?)),t.operation_id,t.exit_id LIMIT 1`).raw().get(operationId,operationId,...cursor);
    if(!next) return;
    const [operation_id,exitId,targetText,targetDigest,runtimeText,runtimeDigest,serviceBootId,clock_domain_id,descriptor_digest,coreReceiptText]=next;
    cursor=[operation_id,exitId];
    const target=original(targetText,targetDigest), runtime=original(runtimeText,runtimeDigest), intent=runtime.launch_intent;
    const targetDomain={clock_domain_id,descriptor_digest};
    const historical=serviceBootId!==bootId, coreReceipt=JSON.parse(coreReceiptText);
    need(target.exit_id===exitId && target.runtime_ref.digest===runtimeDigest && same(domain,supervisor.scope.domain_ref) &&
      target.launch_key.launch_id===intent.launch_id && target.launch_key.launch_intent_digest===digest(canonicalize(intent)) &&
      intent.object_scope.device_ids.includes(target.device_id) && same(coreReceipt.domain_ref,targetDomain) &&
      same(runtime.admission_receipt.domain_ref,targetDomain));
    let record, observation;
    try {
      if(historical){
        if(!receiverReceiptId)return;
        observation=await supervisor.observeWorkerRetirement(coreReceipt,intent,runtime.admission_receipt);
        record=observation?.record.worker_record;
      } else {
        need(same(targetDomain,domain) && intent.supervisor_instance_id===supervisor.scope.supervisor_instance_id);
        record=await supervisor.queryLaunch(target.launch_key);
      }
      supervisor.assertCurrent();
    }
    catch { return; }
    if(!db.open || record?.state!=='retired' || record.retirement_evidence?.result!=='confirmed_empty') return;
    const evidence=record.retirement_evidence;
    need(same(record.key,target.launch_key) && record.creation_attempted===true && record.gate_state==='closed' &&
      record.supervisor_instance_id===intent.supervisor_instance_id && same(record.admission_receipt,runtime.admission_receipt) &&
      evidence.service_id===intent.service_id && evidence.target_scope==='member_group' && same(evidence.target_member_ids,[intent.member_id]) &&
      same(evidence.containment_ref,intent.containment_ref) && same(evidence.old_domain_ref,targetDomain) && same(evidence.evaluator_domain_ref,targetDomain) &&
      evidence.launch_intake_closed===true && Array.isArray(evidence.os_observation_refs) && evidence.os_observation_refs.length>0);
    db.transaction(()=>{
      supervisor.assertCurrent();
      const adopted={format:'leafseamer-reference-exit-retired/1',operation_id,target_ref:ref(exitId,targetDigest),record};
      if(observation){
        supervisor.assertWorkerRetirement(observation);
        const {format,receiving_domain_ref,received_tick_ns}=observation, {core_exit,core_receipt}=observation.record;
        adopted.historical_observation={format,receiving_domain_ref,received_tick_ns,core_exit,core_receipt,
          receiving_service_boot_id:bootId,receiving_core_receipt_id:receiverReceiptId};
      }
      const text=canonicalize(adopted);
      need(db.prepare('INSERT INTO time_provider_reference_exit_retired VALUES (?,?,?,?,?)')
        .run(operation_id,exitId,targetDigest,text,digest(text)).changes===1);
      supervisor.assertCurrent();
      if(observation)supervisor.assertWorkerRetirement(observation);
    }).immediate();
  }

  return Object.freeze({capture,status,reconcile(operationId){
    running??=observe(operationId).finally(()=>{running=null;});
    return running;
  }});
}
