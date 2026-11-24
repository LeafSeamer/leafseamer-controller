import canonicalize from 'canonicalize';
import {controlNeed as need,controlSame as same,controlHash as hash,controlRead as document} from './device-control-value.mjs';

export function historicalWorkerTarget(db,target){
 const row=db.prepare(`SELECT p.intent_jcs,p.intent_digest,r.runtime_id,r.body_jcs,r.body_digest,c.receipt_id,c.receipt_jcs,c.descriptor_jcs
  FROM worker_launch_preparation p JOIN worker_runtime_binding r USING(launch_id)
  JOIN core_runtime_binding c ON c.service_boot_id=p.service_boot_id
  WHERE p.launch_id=? AND p.service_boot_id=? AND p.intent_digest=?`)
  .raw().get(target.launch_id,target.service_boot_id,target.launch_intent_digest);
 if(!row)return null;
 const [text,digest,runtimeId,runtimeText,runtimeDigest,receiptId,coreText,descriptorText]=row;
 const intent=document(text,digest),runtime=document(runtimeText,runtimeDigest),coreReceipt=JSON.parse(coreText),descriptor=JSON.parse(descriptorText);
 const {clock_domain_id,descriptor_digest}=descriptor,domain={clock_domain_id,descriptor_digest};
 need(canonicalize(coreReceipt)===coreText&&canonicalize(descriptor)===descriptorText&&coreReceipt.receipt_id===receiptId&&
  coreReceipt.role==='core'&&same(coreReceipt.domain_ref,domain)&&coreReceipt.launch_id!==intent.launch_id&&
  runtime.runtime_binding_id===runtimeId&&runtime.service_boot_id===target.service_boot_id&&same(runtime.launch_intent,intent)&&
  intent.launch_id===target.launch_id&&intent.supervisor_instance_id===descriptor.supervisor_instance_id&&
  intent.runtime_generation===descriptor.runtime_generation&&same(runtime.clock_domain_descriptor,descriptor)&&
  runtime.admission_receipt.launch_intent_digest===digest&&same(runtime.admission_receipt.domain_ref,domain),
  'historical_exit_binding');
 return {intent,coreReceipt,runtimeId,workerReceipt:runtime.admission_receipt};
}

export function checkHistoricalControlReceipt(db,target,base,receipt){
 const historical=historicalWorkerTarget(db,target),observation=receipt.historical_observation;
 const {service_boot_id,...key}=target;
 need(historical&&observation&&base.service_boot_id!==service_boot_id&&
  observation.format==='leafseamer-worker-retirement-observation/1'&&
  observation.receiving_service_boot_id===base.service_boot_id&&same(observation.receiving_domain_ref,base.domain_ref)&&
  !same(observation.receiving_domain_ref,historical.coreReceipt.domain_ref)&&same(observation.core_receipt,historical.coreReceipt)&&
  typeof observation.received_tick_ns==='string'&&/^(?:0|[1-9][0-9]{0,19})$/.test(observation.received_tick_ns)&&
  BigInt(observation.received_tick_ns)<=18446744073709551615n&&same(key,receipt.key),'historical_exit_binding');
 const receiving=db.prepare('SELECT receipt_id,receipt_jcs FROM core_runtime_binding WHERE service_boot_id=?').raw().get(base.service_boot_id);
 need(receiving&&receiving[0]===observation.receiving_core_receipt_id&&same(JSON.parse(receiving[1]).domain_ref,base.domain_ref),'historical_exit_receiver');
 const {core_exit:exit}=observation,{record,retirement}=receipt,{intent,workerReceipt}=historical,old=workerReceipt.domain_ref;
 need(exit?.active_processes===0&&Number.isInteger(exit.exit_code)&&exit.exit_code>=0&&exit.exit_code<=0xffffffff&&typeof exit.forced==='boolean'&&
  record?.state==='retired'&&record.creation_attempted===true&&record.gate_state==='closed'&&same(record.key,key)&&
  record.supervisor_instance_id===intent.supervisor_instance_id&&same(record.admission_receipt,workerReceipt)&&
  retirement?.result==='confirmed_empty'&&same(record.retirement_evidence,retirement)&&retirement.service_id===intent.service_id&&
  retirement.target_scope==='member_group'&&same(retirement.target_member_ids,[intent.member_id])&&
  same(retirement.containment_ref,intent.containment_ref)&&same(retirement.old_domain_ref,old)&&same(retirement.evaluator_domain_ref,old)&&
  retirement.launch_intake_closed===true&&Array.isArray(retirement.os_observation_refs)&&retirement.os_observation_refs.length>0,
  'old_exit_unresolved');
 return {id:retirement.evidence_id,revision:'1',digest:hash(retirement)};
}
