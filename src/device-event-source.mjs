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

// 核心闭包装配；来源资格、原消息及当前运行均来自同库，不接受调用方提交注册或时间证明。
export function deviceEventSourceStore({db,current,catalog}){
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
    check();frameRecord(frame);const value=source(frame);qualification(value,frame);const result=frame.body.result,batch=result.batch,id=value.registration_id;
    const previous=db.prepare('SELECT body_jcs FROM device_source_batch WHERE message_id=?').pluck().get(frame.request_id);if(previous)return frozen(JSON.parse(previous));
    const priorFault=db.prepare('SELECT reason,body_jcs FROM device_source_fault WHERE registration_id=?').raw().get(id);
    if(priorFault){const old=JSON.parse(priorFault[1]);need(priorFault[0]==='capture_failed'&&same(old.failure,result.failure)&&old.highest_sequence===result.highest_sequence,'source_closed');}
    let sequence=BigInt(tail(id));need(BigInt(batch.after_sequence)<=sequence,'source_gap');const records=[];
    for(const event of batch.events){
     const origin={source_key:value.source_key,binding_ref:value.binding_ref,event_id:event.event_id,source_sequence:event.sequence,
      payload:{schema_ref:value.payload_schema_ref,value:event.payload},source_time_ref:null};validateEventTimeModel('Origin',origin);
     const body=canonical(origin),hash=digest(origin),old=db.prepare('SELECT record_id,origin_jcs,origin_digest,module_event_jcs FROM device_source_event WHERE registration_id=? AND (event_id=? OR source_sequence=?)').raw().all(id,event.event_id,event.sequence);
     if(old.length){need(old.length===1&&old[0][1]===body&&old[0][2]===hash&&old[0][3]===canonical(event),'source_conflict');records.push(old[0][0]);continue;}
     need(BigInt(event.sequence)===sequence+1n,'source_gap');
     const capacity=db.prepare('SELECT count(*),coalesce(sum(length(CAST(origin_jcs AS BLOB))),0) FROM device_source_event').raw().get();
     need(capacity[0]<16384&&capacity[1]+Buffer.byteLength(body)<=33554432,'source_capacity');
     const record=crypto.randomUUID(),transaction=crypto.randomUUID();
     need(db.prepare('INSERT INTO device_source_event VALUES(?,?,?,?,?,?,?,?,?)').run(record,id,event.event_id,event.sequence,body,hash,frame.request_id,canonical(event),transaction).changes===1,'source_storage');
     need(db.prepare('INSERT INTO device_source_event_outbox VALUES(?,?,?)').run(record,transaction,canonical({record_id:record,origin,origin_digest:hash})).changes===1,'source_storage');
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
