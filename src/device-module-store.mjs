import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {moduleNeed as need,validateDeviceModuleFrame} from './sdk/device-module.mjs';
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');

// 模块通道日志保留原请求与候选响应，不把CAPTURED升级为已批准事件或年龄证据。
export function deviceModuleJournal(db,current){
 let channel=null;
 function check(){const selected=current();need(selected.current_boot&&!selected.withdrawal,'module_runtime');return selected;}
 return Object.freeze({
  open(binding){
   need(Number(db.pragma('user_version',{simple:true}))>=46,'module_migration');
   const selected=check();need(binding.runtime_binding_ref.digest===selected.ref.digest&&binding.runtime_binding_ref.object_id===selected.ref.object_id,'module_runtime');
   db.transaction(()=>{
    need(db.prepare('SELECT count(*) FROM device_module_channel').pluck().get()<4096,'module_capacity');
    const body=canonicalize(binding),digest=hash(binding);
    need(db.prepare('INSERT INTO device_module_channel VALUES(?,?,?,?,?)').run(binding.ipc_session_id,selected.ref.object_id,body,digest,
     canonicalize({kind:'device_module_channel',channel_id:binding.ipc_session_id,runtime_binding_ref:selected.ref,binding_digest:digest})).changes===1,'module_storage');
   }).immediate();channel=binding.ipc_session_id;
  },
  record(direction,frame){
   check();validateDeviceModuleFrame(frame);need(channel===frame.binding.ipc_session_id&&['c2w','w2c'].includes(direction),'module_channel');
   const body=canonicalize(frame),digest=hash(frame),transaction=crypto.randomUUID();
   db.transaction(()=>{
    const count=db.prepare('SELECT count(*),coalesce(sum(length(CAST(frame_jcs AS BLOB))),0) FROM device_module_frame').raw().get();
    need(count[0]<16384&&count[1]+Buffer.byteLength(body)<=67108864,'module_capacity');
    need(db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?,?,?,?,?)').run(channel,direction,frame.sequence,frame.request_id,frame.reply_to,frame.type,body,digest,transaction).changes===1,'module_storage');
    need(db.prepare('INSERT INTO device_module_frame_commit VALUES(?,?,?)').run(transaction,frame.request_id,
     canonicalize({kind:direction==='c2w'?'module_request_reserved':'module_candidate_received',channel_id:channel,sequence:frame.sequence,message_id:frame.request_id,frame_digest:digest})).changes===1,'module_storage');
   }).immediate();
  }
 });
}
