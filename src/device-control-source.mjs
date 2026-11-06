import canonicalize from 'canonicalize';
import {protectControlAuthorization} from './device-authorization-state.mjs';
import {assertInitialReadyTransition} from './device-initial-ready.mjs';
import {controlNeed as need,controlHash as hash,controlRead as read,controlSeal as seal,controlSame as same} from './device-control-value.mjs';
const counter=/^(0|[1-9][0-9]{0,19})$/;
const reference=value=>({id:value.change_id,revision:value.revision,digest:value.record_digest});
function body(record,id,kind,domain){
 need(domain&&typeof domain.tick==='string'&&counter.test(domain.tick)&&/^clock_[0-9a-f]{64}$/.test(domain.ref?.clock_domain_id)&&
  /^sha256:[0-9a-f]{64}$/.test(domain.ref.descriptor_digest),'source_domain');
 return seal({format_version:'control-storage-body/1',change_id:id,revision:record.revision,scope:record.scope,device_id:record.device_id,change_kind:kind,
  control_epoch:record.control_epoch,effective_version:record.effective_version,reserved_version:record.reserved_version,mode:record.mode,
  holder:record.holder?{kind:'human',...record.holder}:null,pending_operation_id:record.pending_change?.operation_id??null,gate_state:record.gate_state,
  clock_domain_id:domain.ref.clock_domain_id,descriptor_digest:domain.ref.descriptor_digest,observed_tick_ns:domain.tick},'record_digest');
}
export {body as controlSourceBody};
export function saveControlSources(db,commit,kind,domain){
 need(db.inTransaction,'source_writer');
 const records=db.prepare('SELECT device_id,revision,body_jcs,body_digest FROM control_record_revision WHERE commit_id=?').raw().all(commit);
 if(!records.length)return;
 need(records.length===1&&typeof domain==='function','source_domain');const observed=domain();
 for(const [device,revision,text,digest] of records){const record=read(text,digest),value=body(record,commit,kind,observed);
  const {record_digest,...unsigned}=record;need(hash(unsigned)===record_digest&&record.device_id===device&&record.revision===String(revision),'source_integrity');
  need(db.prepare('INSERT INTO control_state_source VALUES(?,?,?,?,?,?,?,?,?)').run(commit,device,revision,kind,value.clock_domain_id,value.descriptor_digest,
   value.observed_tick_ns.padStart(20,'0'),canonicalize(value),value.record_digest).changes===1,'source_storage');
  if(kind==='ready')assertInitialReadyTransition(db,value);
  else if(kind==='gate_protect'){
   const revision=db.prepare("SELECT revision FROM control_state_source WHERE device_id=? AND change_kind NOT IN ('ready','gate_protect') ORDER BY revision DESC LIMIT 1").pluck().get(device);
   need(revision!==undefined,'source_missing');
   protectControlAuthorization(db,readControlSource(db,device,String(revision)).value,observed,'source_unavailable');
  }else if(Number(db.pragma('user_version',{simple:true}))>=34)protectControlAuthorization(db,value);
 }
}
export function readControlSource(db,device,revision){
 need(db.inTransaction,'source_writer');
 const row=db.prepare(`SELECT s.source_id,s.change_kind,s.clock_domain_id,s.descriptor_digest,s.observed_tick,s.body_jcs,s.body_digest,r.body_jcs,r.body_digest,c.kind
  FROM control_state_source s JOIN control_record_revision r USING(device_id,revision) JOIN control_change_commit c ON c.commit_id=s.source_id
  WHERE s.device_id=? AND s.revision=? AND r.commit_id=s.source_id`).raw().get(device,Number(revision));
 need(row,'source_missing');const record=read(row[7],row[8]),value=JSON.parse(row[5]),{record_digest,...unsigned}=value;
 const {record_digest:publicDigest,...publicBody}=record;
 need(canonicalize(value)===row[5]&&hash(publicBody)===publicDigest&&record.device_id===device&&record.revision===String(revision)&&
  hash(unsigned)===record_digest&&record_digest===row[6]&&same(value,body(record,row[0],row[1],{ref:{clock_domain_id:row[2],descriptor_digest:row[3]},tick:String(BigInt(row[4]))}))&&row[9]===row[1],'source_integrity');
 return {value,ref:reference(value)};
}
export function currentControlSource(db,device){
 need(db.inTransaction,'source_writer');const revision=db.prepare('SELECT revision FROM control_record_head WHERE device_id=?').pluck().get(device);
 need(revision!==undefined,'source_missing');const current=readControlSource(db,device,revision);
 const authority=db.prepare("SELECT s.revision FROM control_state_source s JOIN control_change_commit c ON c.commit_id=s.source_id WHERE s.device_id=? AND s.change_kind NOT IN ('ready','gate_protect') ORDER BY s.revision DESC LIMIT 1").pluck().get(device);
 need(authority!==undefined,'source_missing');return {current,authority:readControlSource(db,device,authority)};
}
