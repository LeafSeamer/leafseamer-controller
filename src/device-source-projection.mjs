import {canonical,digest,same} from './auth-clock-value.mjs';
import {moduleNeed as need} from './sdk/device-module.mjs';
const hash=value=>digest(value).slice(7),written=result=>need(result.changes===1,'source_projection_storage');
const unpack=(body,expected)=>{const value=JSON.parse(body);need(canonical(value)===body&&digest(value)===expected,'source_projection_integrity');return value;};
export function sourceBindingObjectRef(source){return {authority_service_id:source.source_key.authority_service_id,database_instance_id:source.source_key.database_instance_id,
 entity_kind:'source_binding',entity_id:source.registration_id,entity_epoch:source.source_key.source_epoch,revision:source.binding_ref.revision,content_digest:hash(source.binding_ref)};}
function view(source,sequence,fault){
 let highest=sequence;const gaps=[];
 const gap=(extent,first=null,last=null)=>gaps.push({gap_id:source.registration_id+'_gap',loss_extent:extent,first_missing:first,last_missing:last,resolution_state:'open'});
 if(fault){
  const end=fault.highest_sequence??fault.closed?.last_sequence;
  if(end!==undefined&&BigInt(end)>BigInt(highest))highest=end;
  if(fault.reason==='channel_closed')gap('unknown');
  else if(BigInt(highest)>BigInt(sequence))gap('known',String(BigInt(sequence)+1n),highest);
  else if(fault.failure?.loss_extent==='known'){const missing=fault.failure.missing_sequence;need(BigInt(missing)>BigInt(sequence),'source_projection_gap');highest=missing;gap('known',missing,missing);}
 }
 return {source_key:source.source_key,binding_ref:sourceBindingObjectRef(source),state:fault?(fault.reason==='capture_failed'?'desynchronized':'closed'):'baseline_required',
  contiguous_sequence:sequence,highest_seen_sequence:highest,baseline_ref:null,gaps};
}
export function deviceSourceProjectionStore(db){
 const available=()=>need(db.open&&db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=67,'source_projection_writer');
 function notify(kind,source,event,revision,body){
  const encoded=canonical(body),capacity=db.prepare('SELECT count(*),coalesce(sum(length(CAST(body_jcs AS BLOB))),0) FROM device_source_notification').raw().get();
  need(capacity[0]<65536&&capacity[1]+Buffer.byteLength(encoded)<=67108864,'source_projection_capacity');
  const result=db.prepare('INSERT INTO device_source_notification(entry_kind,registration_id,event_id,projection_revision,body_jcs,body_digest) VALUES(?,?,?,?,?,?)').run(kind,source,event,revision,encoded,digest(body));written(result);return Number(result.lastInsertRowid);
 }
 return Object.freeze({
  publish(source,events=[]){available();const id=source.registration_id;
   for(const event of events){const row=db.prepare('SELECT record_id,origin_jcs,origin_digest FROM device_source_event WHERE record_id=? AND registration_id=?').raw().get(event,id);need(row,'source_projection_event');
    const origin=unpack(row[1],row[2]);const existing=db.prepare("SELECT body_jcs,body_digest FROM device_source_notification WHERE entry_kind='source.event' AND event_id=?").raw().get(row[0]);
    if(existing)need(same(unpack(...existing),{origin}),'source_projection_conflict');else notify('source.event',id,row[0],null,{origin});
   }
   const sequence=db.prepare('SELECT source_sequence FROM device_source_event WHERE registration_id=? ORDER BY length(source_sequence) DESC,source_sequence DESC LIMIT 1').pluck().get(id)??'0';
   const count=db.prepare('SELECT count(*) FROM device_source_event WHERE registration_id=?').pluck().get(id);need(String(count)===sequence,'source_projection_gap');
   const faultText=db.prepare('SELECT body_jcs FROM device_source_fault WHERE registration_id=?').pluck().get(id),current=view(source,sequence,faultText?JSON.parse(faultText):null);
   const old=db.prepare('SELECT r.revision,r.record_jcs,r.record_digest FROM device_source_projection r JOIN device_source_projection_head h USING(registration_id,revision) WHERE registration_id=?').raw().get(id);
   if(old&&same(unpack(old[1],old[2]).view,current))return;
   const revision=old?old[0]+1:1,record={entity_kind:'sources',entity_id:id,entity_epoch:source.source_key.source_epoch,entity_revision:String(revision),view:current},journal=notify('entity.upsert',id,null,revision,record);
   written(db.prepare('INSERT INTO device_source_projection VALUES(?,?,?,?,?)').run(id,revision,canonical(record),digest(record),journal));
   written(old?db.prepare('UPDATE device_source_projection_head SET revision=? WHERE registration_id=? AND revision=?').run(revision,id,old[0]):db.prepare('INSERT INTO device_source_projection_head VALUES(?,?)').run(id,revision));
  },
  current(id){available();const row=db.prepare('SELECT r.record_jcs,r.record_digest FROM device_source_projection r JOIN device_source_projection_head h USING(registration_id,revision) WHERE registration_id=?').raw().get(id);need(row,'source_projection_missing');return unpack(...row);}
 });
}

// 独立只读连接固定同一SQLite快照；调用者负责writer中的当前授权和读后释放门。
export function readSourceProjectionCut(db,registration){
 need(db.open&&!db.inTransaction&&db.readonly,'source_projection_reader');
 need(db.pragma('read_uncommitted',{simple:true})===0,'source_projection_isolation');
 return db.transaction(()=>{
  const journal=db.prepare('SELECT coalesce(max(sequence),0) FROM device_source_notification').pluck().get(),records=[],watermarks=[];
  need(registration.sources.length>=1&&registration.sources.length<=32,'source_projection_scope');
  for(const member of registration.sources){
   const id=member.source_key.registration_id,row=db.prepare('SELECT r.record_jcs,r.record_digest,r.journal_sequence FROM device_source_projection r JOIN device_source_projection_head h USING(registration_id,revision) WHERE registration_id=?').raw().get(id);
   need(row&&row[2]<=journal,'source_projection_missing');const record=unpack(row[0],row[1]),sourceRow=db.prepare('SELECT body_jcs,body_digest FROM device_event_source WHERE registration_id=?').raw().get(id);need(sourceRow,'source_projection_missing');const source=unpack(...sourceRow);
   need(same(record.view.source_key,member.source_key)&&same(source.source_key,member.source_key)&&same(source.binding_ref,member.binding_ref)&&same(record.view.binding_ref,sourceBindingObjectRef(source)),'source_projection_binding');
   const sequence=db.prepare('SELECT count(*) FROM device_source_event WHERE registration_id=?').pluck().get(id);need(String(sequence)===record.view.contiguous_sequence,'source_projection_frontier');
   records.push(record);watermarks.push({source_key:record.view.source_key,binding_ref:record.view.binding_ref,baseline_sequence:record.view.contiguous_sequence,source_state_revision:record.entity_revision,baseline_ref:record.view.baseline_ref,gap_summary:record.view.gaps});
  }
  records.sort((a,b)=>a.entity_id<b.entity_id?-1:a.entity_id>b.entity_id?1:0);watermarks.sort((a,b)=>a.source_key.registration_id<b.source_key.registration_id?-1:1);
  need(new Set(records.map(r=>r.entity_id)).size===records.length,'source_projection_duplicate');
  return {journal_sequence:String(journal),records,source_watermarks:watermarks};
 })();
}
