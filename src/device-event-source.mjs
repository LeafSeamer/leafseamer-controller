import crypto from 'node:crypto';
import {canonical,digest} from './auth-clock-value.mjs';
import {moduleNeed as need} from './sdk/device-module.mjs';
import {validateEventTimeModel} from './sdk/event-time.mjs';
import {qualifyDeviceEventFrame} from './device-event-qualification.mjs';
import {deviceSourceProjectionStore} from './device-source-projection.mjs';
const same=(a,b)=>canonical(a)===canonical(b);
const read=(body,hash)=>{const value=JSON.parse(body);need(canonical(value)===body&&digest(value)===hash,'source_integrity');return value;};
const payloadSchema={type:'object',additionalProperties:false,properties:{value:{type:'integer',minimum:-2147483648,maximum:2147483647},write_sequence:{type:'string',pattern:'^[1-9][0-9]{0,19}$(?![\\s\\S])'}},required:['value','write_sequence']};
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};

function sourceTimeEvidence(record,origin,qualified,moduleFrame,projection){
 const {authority_service_id,database_instance_id}=origin.source_key;
 const {provider_id,provider_boot_id}=origin.binding_ref;
 const {object_id:id,revision,digest:runtimeDigest}=qualified.runtime_binding_ref;
 const body={id:record,revision:'1',source_key:origin.source_key,binding_ref:origin.binding_ref,event_id:origin.event_id,
  source_sequence:origin.source_sequence,payload_digest:digest(origin.payload),capture_semantics:'event_occurrence',
  capture_evidence_ref:moduleFrame,capture_domain:{authority_service_id,database_instance_id,provider_id,provider_boot_id,
   runtime_binding_ref:{id,revision,digest:runtimeDigest},...projection.runtime_domain_ref,clock_generation:'1'},
  capture_start_tick_ns:projection.before_tick_ns,capture_end_tick_ns:projection.after_tick_ns,
  elapsed_profile_ref:projection.elapsed_profile_ref,reference_context_ref:projection.reference_context_ref??null,
  utc_interval:projection.reference_context_ref?{lower_ns:projection.lower_utc_ns,upper_ns:projection.upper_utc_ns}:null};
 const value={...body,digest:digest(body)};validateEventTimeModel('SourceTimeEvidence',value);return value;
}

export function readDeviceSourceTime(db,reference){
 const row=db.prepare(`SELECT o.body_jcs,e.origin_jcs,e.origin_digest,e.module_event_jcs,f.message_id,f.frame_digest,f.frame_jcs,s.body_jcs,s.body_digest
  FROM device_source_event_outbox o JOIN device_source_event e USING(record_id,transaction_id)
  JOIN device_module_frame f ON f.message_id=e.module_message_id JOIN device_event_source s USING(registration_id)
  WHERE e.record_id=?`).raw().get(reference.id);
 if(!row)return null;
 const [outboxText,originText,originDigest,moduleEvent,frameId,frameDigest,frameText,sourceText,sourceDigest]=row;
 const origin=read(originText,originDigest),expected=origin.source_time_ref;
 if(expected?.object_id!==reference.id||expected.revision!==reference.revision||expected.digest!==reference.digest)return null;
 const outbox=JSON.parse(outboxText),source=read(sourceText,sourceDigest),frame=read(frameText,frameDigest),original=outbox.reference_capture;
 const capture=original?.body,projection=capture?.projection,interval=JSON.parse(moduleEvent).capture_interval;
 need(canonical(outbox)===outboxText&&outbox.record_id===reference.id&&outbox.origin_digest===originDigest&&same(outbox.origin,origin)&&
  capture?.format==='leafseamer-source-reference-capture/1'&&original.digest===digest(capture)&&capture.origin_digest===originDigest&&
  same(capture.module_frame_ref,{id:frameId,revision:'1',digest:frameDigest})&&
  frame.type==='EVENT_BATCH'&&frame.request_id===frameId&&frame.body.result.batch.events.some(event=>canonical(event)===moduleEvent)&&
  same(capture.worker_runtime_ref,source.qualification.runtime_binding_ref)&&same(capture.capture_review_ref,source.qualification.review_ref)&&
  projection?.before_tick_ns===interval.before_tick_ns&&projection?.after_tick_ns===interval.after_tick_ns,'source_time_integrity');
 const {id:anchorId,revision:anchorRevision,digest:anchorDigest}=projection.anchor_ref;
 const anchorRow=db.prepare('SELECT body_jcs,body_digest FROM time_provider_reference_anchor WHERE anchor_id=? AND body_digest=?').raw().get(anchorId,anchorDigest);
 const {clock_domain_id,descriptor_digest}=source.qualification.clock_domain_descriptor;
 need(anchorRevision==='1'&&anchorRow,'source_time_integrity');
 const anchor=read(...anchorRow);
 need(same(anchor.approval.profile_ref,projection.elapsed_profile_ref)&&
  (!projection.reference_context_ref||same(projection.reference_context_ref,{id:anchorId,revision:'1',digest:anchor.reference_bundle?.digest}))&&
  same(projection.runtime_domain_ref,{clock_domain_id,descriptor_digest}),'source_time_integrity');
 const value=sourceTimeEvidence(reference.id,origin,source.qualification,capture.module_frame_ref,projection);
 need(same(value,outbox.source_time_evidence)&&value.digest===reference.digest,'source_time_integrity');
 return value;
}

// 核心闭包装配；来源资格、原消息及当前运行均来自同库，不接受调用方提交注册或时间证明。
export function deviceEventSourceStore({db,current,catalog,projectReferenceCapture}){
 const timeEvidence=Number(db.pragma('user_version',{simple:true}))>=94;
 const projections=Number(db.pragma('user_version',{simple:true}))>=67?deviceSourceProjectionStore(db):null;
 let channel=null;
 const tail=id=>db.prepare('SELECT source_sequence FROM device_source_event WHERE registration_id=? ORDER BY length(source_sequence) DESC,source_sequence DESC LIMIT 1').pluck().get(id)??'0';
 function check(){const runtime=current();need(runtime.current_boot&&!runtime.withdrawal,'source_runtime');return runtime;}
 function frameRecord(frame){const row=db.prepare('SELECT frame_jcs,frame_digest FROM device_module_frame WHERE message_id=? AND direction=\'w2c\'').raw().get(frame.request_id);need(row&&same(read(...row),frame),'source_frame');}
 function source(frame){const row=db.prepare('SELECT body_jcs,body_digest FROM device_event_source WHERE channel_id=? AND capture_id=?').raw().get(frame.binding.ipc_session_id,frame.body.capture_id);need(row,'source_missing');const value=read(...row);
  need(value.qualification.device_id===frame.body.device_id&&value.qualification.device_session_id===frame.body.device_session_id,'source_session');return value;}
 function qualification(value,frame){
  const runtime=check(),q=value.qualification,approved=catalog.current(q.channel_id,q.device_id,q.device_session_id).approval;
  const row=db.prepare('SELECT frame_jcs,frame_digest FROM device_module_frame WHERE message_id=?').raw().get(q.capture_message_id);need(row,'source_start');
  const started=read(...row),actual=qualifyDeviceEventFrame({approved,runtime,frame,started:frame.type==='EVENT_BATCH'?started:null});
  need(same(actual,q),'source_qualification');return actual;
 }
 function fault(value,reason,body){
  db.prepare('INSERT OR IGNORE INTO device_source_fault VALUES(?,?,?)').run(value.registration_id,reason,canonical({registration_id:value.registration_id,reason,last_committed_sequence:tail(value.registration_id),...body}));
  need(db.prepare('SELECT 1 FROM device_source_fault WHERE registration_id=?').pluck().get(value.registration_id),'source_storage');
 }
 return Object.freeze({
  start(frame){
   check();frameRecord(frame);const q=catalog.currentEventCapture(frame.binding.ipc_session_id,frame.body.device_id,frame.body.device_session_id);
   need(q.capture_message_id===frame.request_id,'source_start');channel=q.channel_id;
   return db.transaction(()=>{
    check();const old=db.prepare('SELECT body_jcs,body_digest FROM device_event_source WHERE started_message_id=?').raw().get(frame.request_id);if(old)return frozen(read(...old));
    need(db.prepare('SELECT count(*) FROM device_event_source').pluck().get()<1024,'source_capacity');
    const registration=crypto.randomUUID(),runtime=current(),scope={authority_service_id:runtime.binding.service_id,database_instance_id:runtime.binding.database_instance_id};
    const source_key={...scope,registration_id:registration,source_stream_id:q.device_id,source_epoch:q.capture.capture_id};
    const binding_ref={registration_id:registration,revision:'1',owner_service_id:scope.authority_service_id,database_instance_id:scope.database_instance_id,
     provider_id:runtime.binding.launch_intent.member_id,provider_boot_id:runtime.binding.admission_receipt.member_boot_id,capture_policy_id:'fixed_simulator_write_capture',capture_policy_revision:'1',delivery_semantics:'discrete',
     target:{kind:'device',device_id:q.device_id,trigger_id:'simulator_value_written',capability_version:'1.0.0'}};
    validateEventTimeModel('SourceBinding',binding_ref);
    const value={format:'leafseamer-device-event-source/1',registration_id:registration,revision:'1',source_key,binding_ref,qualification:q,
     canonical_delivery:'ordered_subscription',payload_schema_ref:{kind:'schema',scope,object_id:'simulator_value_written_payload',revision:'1',digest:digest(payloadSchema)},payload_schema:payloadSchema};
    need(db.prepare('INSERT INTO device_event_source VALUES(?,?,?,?,?,?,?,?,?)').run(registration,q.channel_id,q.capture.capture_id,q.device_id,q.device_session_id,q.catalog_approval_ref.id,frame.request_id,canonical(value),digest(value)).changes===1,'source_storage');
    qualification(value,frame);projections?.publish(value);return frozen(value);
   }).immediate();
  },
  accept(frame){
   return db.transaction(()=>{
    check();frameRecord(frame);const value=source(frame),qualified=qualification(value,frame);const result=frame.body.result,batch=result.batch,id=value.registration_id;
    const previous=db.prepare('SELECT body_jcs FROM device_source_batch WHERE message_id=?').pluck().get(frame.request_id);if(previous)return frozen(JSON.parse(previous));
    const priorFault=db.prepare('SELECT reason,body_jcs FROM device_source_fault WHERE registration_id=?').raw().get(id);
    if(priorFault){const old=JSON.parse(priorFault[1]);need(priorFault[0]==='capture_failed'&&same(old.failure,result.failure)&&old.highest_sequence===result.highest_sequence,'source_closed');}
    let sequence=BigInt(tail(id));need(BigInt(batch.after_sequence)<=sequence,'source_gap');const records=[];
    for(const event of batch.events){
     const originBody={source_key:value.source_key,binding_ref:value.binding_ref,event_id:event.event_id,source_sequence:event.sequence,
      payload:{schema_ref:value.payload_schema_ref,value:event.payload}};
     const moduleEvent=canonical(event),old=db.prepare('SELECT record_id,origin_jcs,origin_digest,module_event_jcs FROM device_source_event WHERE registration_id=? AND (event_id=? OR source_sequence=?)').raw().all(id,event.event_id,event.sequence);
     if(old.length){
      need(old.length===1&&old[0][3]===moduleEvent,'source_conflict');
      const original=read(old[0][1],old[0][2]);validateEventTimeModel('Origin',original);
      const {source_time_ref,...fields}=original;
      need(same(fields,originBody),'source_conflict');records.push(old[0][0]);continue;
     }
     need(BigInt(event.sequence)===sequence+1n,'source_gap');
     const record=crypto.randomUUID(),transaction=crypto.randomUUID();
     const {clock_domain_id,descriptor_digest}=qualified.clock_domain_descriptor;
     const projection=projectReferenceCapture?.({domain:{clock_domain_id,descriptor_digest},...event.capture_interval});
     const moduleFrame={id:frame.request_id,revision:'1',digest:digest(frame)};
     const valueTime=projection&&timeEvidence?sourceTimeEvidence(record,originBody,qualified,moduleFrame,projection):null;
     const scope=value.payload_schema_ref.scope;
     const origin={...originBody,source_time_ref:valueTime?{kind:'source_time_evidence',scope,object_id:valueTime.id,revision:valueTime.revision,digest:valueTime.digest}:null};
     validateEventTimeModel('Origin',origin);
     const body=canonical(origin),hash=digest(origin);
     const capacity=db.prepare('SELECT count(*),coalesce(sum(length(CAST(origin_jcs AS BLOB))),0) FROM device_source_event').raw().get();
     need(capacity[0]<16384&&capacity[1]+Buffer.byteLength(body)<=33554432,'source_capacity');
     const outbox={record_id:record,origin,origin_digest:hash};
     if(projection){
      const capture={format:'leafseamer-source-reference-capture/1',origin_digest:hash,module_frame_ref:moduleFrame,
       worker_runtime_ref:qualified.runtime_binding_ref,capture_review_ref:qualified.review_ref,projection};
      const bytes=canonical(capture);need(Buffer.byteLength(bytes)<=4096,'source_capture_capacity');
      outbox.reference_capture={body:capture,digest:digest(capture)};
     }
     if(valueTime)outbox.source_time_evidence=valueTime;
     need(db.prepare('INSERT INTO device_source_event VALUES(?,?,?,?,?,?,?,?,?)').run(record,id,event.event_id,event.sequence,body,hash,frame.request_id,moduleEvent,transaction).changes===1,'source_storage');
     need(db.prepare('INSERT INTO device_source_event_outbox VALUES(?,?,?)').run(record,transaction,canonical(outbox)).changes===1,'source_storage');
     records.push(record);sequence=BigInt(event.sequence);
    }
    if(result.state==='failed')fault(value,'capture_failed',{module_message_id:frame.request_id,failure:result.failure,highest_sequence:result.highest_sequence});
    const receipt={format:'leafseamer-source-batch-commit/1',registration_id:id,module_message_id:frame.request_id,batch_digest:result.batch_digest,through_sequence:batch.through_sequence,record_ids:records};
    need(db.prepare('INSERT INTO device_source_batch VALUES(?,?,?,?,?)').run(frame.request_id,id,result.batch_digest,batch.through_sequence,canonical(receipt)).changes===1,'source_storage');
    projections?.publish(value,records);check();return frozen(receipt);
   }).immediate();
  },
  stop(frame){db.transaction(()=>{check();frameRecord(frame);const value=source(frame);fault(value,'capture_stopped',{module_message_id:frame.request_id,closed:frame.body.closed});projections?.publish(value);}).immediate();},
  disconnect(frame){db.transaction(()=>{check();frameRecord(frame);for(const row of db.prepare('SELECT body_jcs,body_digest FROM device_event_source WHERE channel_id=? AND device_id=? AND device_session_id=?').raw().all(frame.binding.ipc_session_id,frame.body.device_id,frame.body.device_session_id)){const value=read(...row);fault(value,'channel_closed',{module_message_id:frame.request_id,loss_extent:'unknown'});projections?.publish(value);}}).immediate();},
  close(){if(channel)db.transaction(()=>{for(const row of db.prepare('SELECT body_jcs,body_digest FROM device_event_source WHERE channel_id=?').raw().all(channel)){const value=read(...row);fault(value,'channel_closed',{loss_extent:'unknown'});projections?.publish(value);}}).immediate();},
  read(frame,after='0',limit=32){
   need(typeof after==='string'&&/^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(after)&&Number.isInteger(limit)&&limit>=1&&limit<=32,'source_cursor');
   return db.transaction(()=>{check();const value=source(frame);qualification(value,frame);const faultRow=db.prepare('SELECT body_jcs FROM device_source_fault WHERE registration_id=?').pluck().get(value.registration_id);
    const events=db.prepare('SELECT origin_jcs,origin_digest FROM device_source_event WHERE registration_id=? AND (length(source_sequence)>length(?) OR (length(source_sequence)=length(?) AND source_sequence>?)) ORDER BY length(source_sequence),source_sequence LIMIT ?').raw().all(value.registration_id,after,after,after,limit).map(([body,hash])=>({origin:read(body,hash),origin_digest:hash}));
    return frozen({registration:value,highest_committed_sequence:tail(value.registration_id),fault:faultRow?JSON.parse(faultRow):null,events});
   }).immediate();
  }
 });
}
