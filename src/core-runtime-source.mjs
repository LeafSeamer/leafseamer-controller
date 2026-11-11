import {sourceWindowContains} from './authority-source-window.mjs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {seal,ref,same,checked} from './auth-clock-value.mjs';
import {IdentityError} from './identity-crypto.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('core_runtime_source_'+code);};
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
// 持久记录仅从当前受监督连接取得，完整观察持有身份仍由该连接复核；历史原件不恢复运行资格。
export function coreRuntimeSource({db,service,bootId,core,connected,observe,assertObservation,domain}){
 const held=new Map();
 function currentObservation(observation){
  try{assertObservation(observation);}catch(error){
   // 旧观察过期是资格拒绝；真实通道丢失等错误仍交给上层终止服务。
   if(error?.code==='supervisor_core_observation')need(false,'not_current');throw error;
  }
 }
 function currentSources(){
  need(db.inTransaction,'writer');connected();const parent=core(),observation=observe();currentObservation(observation);const now=domain();
  const request=observation.request,response=observation.response;
  need(sourceWindowContains(observation,observation.issued_tick_ns,observation.expires_tick_ns),'window');
  need(request.type==='LAUNCH_QUERY'&&response.type==='LAUNCH_RESULT'&&response.reply_to===request.message_id&&
   request.channel_id===response.channel_id&&same(request.scope,response.scope)&&same(request.payload,response.payload.key)&&
   same(response.payload.record.admission_receipt,parent.receipt)&&request.scope.service_id===service.service_id&&
   request.scope.database_instance_id===service.database_instance_id&&same(request.scope.domain_ref,now.ref)&&
   same(parent.receipt.domain_ref,now.ref)&&request.payload.launch_id===parent.intent.launch_id&&
   BigInt(observation.issued_tick_ns)<=BigInt(observation.received_tick_ns)&&BigInt(observation.received_tick_ns)<=BigInt(now.tick)&&
   BigInt(now.tick)<BigInt(observation.expires_tick_ns),'binding');
  return {parent,observation,now};
 }
 function original(reference){
  need(reference?.revision==='1','reference');const row=db.prepare(`SELECT s.service_boot_id,s.response_id,s.body_jcs,s.body_digest,c.audit_jcs,s.selected_tick,s.expires_tick
   FROM core_runtime_source s JOIN core_runtime_source_commit c USING(source_id) WHERE s.source_id=? AND c.body_digest=s.body_digest`).raw().get(reference.id);
  need(row,'missing');const value=checked(JSON.parse(row[2]));
  need(canonicalize(value)===row[2]&&value.digest===row[3]&&same(ref(value),reference)&&value.service_boot_id===row[0]&&
   value.observation.response.message_id===row[1]&&value.format==='leafseamer-core-runtime-source/1'&&
   value.selected_tick_ns.padStart(20,'0')===row[5]&&value.expires_tick_ns.padStart(20,'0')===row[6]&&
   row[4]===canonicalize({kind:'core_runtime_source',source_ref:reference}),'integrity');return value;
 }
 function current(reference){
  need(db.inTransaction,'writer');const value=original(reference),observation=held.get(value.id);need(observation,'not_current');
  connected();const parent=core(),now=domain();
  need(value.service_boot_id===bootId&&same(value.scope,{authority_service_id:service.service_id,database_instance_id:service.database_instance_id})&&
   same(value.core,parent)&&same(value.observation,observation)&&same(value.domain_ref,now.ref)&&
   BigInt(value.selected_tick_ns)<=BigInt(now.tick)&&BigInt(now.tick)<BigInt(value.expires_tick_ns),'not_current');
  need(sourceWindowContains(observation,observation.issued_tick_ns,observation.expires_tick_ns)&&value.expires_tick_ns===observation.expires_tick_ns,'window');
  currentObservation(observation);return freeze({ref:reference,value});
 }
 return Object.freeze({current,
  select(){
   const {parent,observation,now}=currentSources();
   for(const [id,item] of held)if(BigInt(item.expires_tick_ns)<=BigInt(now.tick)||!db.prepare('SELECT 1 FROM core_runtime_source WHERE source_id=?').pluck().get(id))held.delete(id);
   const prior=db.prepare('SELECT source_id,body_digest FROM core_runtime_source WHERE service_boot_id=? AND response_id=?').raw().get(bootId,observation.response.message_id);
   if(prior)return current({id:prior[0],revision:'1',digest:prior[1]});
   need(db.prepare('SELECT count(*) FROM core_runtime_source').pluck().get()<4096,'capacity');
   const value=seal({format:'leafseamer-core-runtime-source/1',id:crypto.randomUUID(),revision:'1',
    scope:{authority_service_id:service.service_id,database_instance_id:service.database_instance_id},service_boot_id:bootId,core:parent,observation,
    domain_ref:now.ref,selected_tick_ns:now.tick,expires_tick_ns:observation.expires_tick_ns});
   const reference=ref(value);need(Buffer.byteLength(canonicalize(value))<=65536,'capacity');
   need(db.prepare('INSERT INTO core_runtime_source VALUES(?,?,?,?,?,?,?)').run(value.id,bootId,observation.response.message_id,
    value.selected_tick_ns.padStart(20,'0'),value.expires_tick_ns.padStart(20,'0'),canonicalize(value),value.digest).changes===1,'storage');
   need(db.prepare('INSERT INTO core_runtime_source_commit VALUES(?,?,?)').run(value.id,value.digest,canonicalize({kind:'core_runtime_source',source_ref:reference})).changes===1,'storage');
   // 事务回滚后的对象不能凭此映射通过current，仍须同时存在完整可靠原件。
   held.set(value.id,observation);return current(reference);
  }
 });
}
