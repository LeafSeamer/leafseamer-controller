import net from 'node:net';
import crypto from 'node:crypto';
import {createDeviceExecutionCodec} from './sdk/device-execution.mjs';
import {contractSelection} from './sdk/index.mjs';
const codec=createDeviceExecutionCodec(contractSelection),limit=262144,bufferLimit=4*(limit+4);
export class DeviceExecutionError extends Error{constructor(code){super(code);this.name='DeviceExecutionError';this.code=code;}}
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
// 一次worker启动只对应一个执行会话。两端从监督器/已采用运行的同一身份计算，
// 不通过首帧信任陌生session，也不允许断线后给原worker另发session恢复旧许可。
export function executionSessionIdentity(value){
 const keys=['authority_service_id','database_instance_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'];
 need(value&&Object.keys(value).sort().join(',')===[...keys].sort().join(','),'execution_identity');
 const copy=Object.fromEntries(keys.map(key=>[key,value[key]]));
 for(const key of keys.slice(0,4))need(typeof copy[key]==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$(?![\s\S])/.test(copy[key]),'execution_identity');
 need(copy.controller_boot_id!==copy.worker_boot_id&&/^clock_[0-9a-f]{64}$(?![\s\S])/.test(copy.clock_domain_id)&&
  /^sha256:[0-9a-f]{64}$(?![\s\S])/.test(copy.descriptor_digest),'execution_identity');
 const bytes=crypto.createHash('sha256').update(JSON.stringify(['leafseamer-execution-session/1',...keys.map(key=>copy[key])])).digest().subarray(0,16);
 bytes[6]=(bytes[6]&15)|128;bytes[8]=(bytes[8]&63)|128;const hex=bytes.toString('hex');
 return Object.freeze({...copy,ipc_session_id:hex.slice(0,8)+'-'+hex.slice(8,12)+'-'+hex.slice(12,16)+'-'+hex.slice(16,20)+'-'+hex.slice(20)});
}
export function executionSocket(memberBoot,side){
 need(process.platform==='win32'&&/^[0-9a-f]{32}$(?![\s\S])/.test(memberBoot)&&['core','worker'].includes(side),'execution_endpoint');
 return net.createConnection('\\\\.\\pipe\\LeafSeamer.Execution.'+memberBoot+'.'+side);
}
export async function decodeExecutionPayload(bytes,direction){
 need(bytes instanceof Uint8Array&&bytes.byteLength>0&&bytes.byteLength<=limit,'execution_frame_size');
 const copy=Buffer.from(bytes);
 // 此处type只选择校验根；完整原字节仍经SDK的重复键、数字、深度及Schema检查。
 let type;try{type=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(copy)).type;}catch{need(false,'execution_frame');}
 return {frame:await codec.decode(copy,direction,type),payload:copy};
}
export function executionWire(payload){
 need(payload instanceof Uint8Array&&payload.byteLength>0&&payload.byteLength<=limit,'execution_frame_size');
 const wire=Buffer.allocUnsafe(4+payload.byteLength);wire.writeUInt32BE(payload.byteLength);wire.set(payload,4);return wire;
}

// 仅处理有序字节；方向、会话、seq、领域原件和WriteAttempt由业务发送器/日志核验。
// 不重连、不重发、不在内部排队设备动作；send只允许一个写入调用在途。
export function executionTransport(socket,{incoming,receive,failed}){
 need(['c2w','w2c'].includes(incoming)&&typeof receive==='function'&&typeof failed==='function','execution_configuration');
 const outgoing=incoming==='c2w'?'w2c':'c2w';
 let input=Buffer.alloc(0),draining=false,writing=false,closed=false,writeReject=null;
 function close(error=new DeviceExecutionError('execution_closed')){
  if(closed)return;closed=true;input=Buffer.alloc(0);socket.destroy();
  const reject=writeReject;writeReject=null;reject?.(new DeviceExecutionError('execution_write_uncertain'));
  try{failed(error);}catch{}
 }
 async function drain(){
  if(draining||closed)return;draining=true;socket.pause();
  try{
   while(!closed&&input.length>=4){
    const length=input.readUInt32BE();need(length>0&&length<=limit,'execution_frame_size');if(input.length<4+length)break;
    const wire=Buffer.from(input.subarray(0,4+length));input=Buffer.from(input.subarray(4+length));
    const decoded=await decodeExecutionPayload(wire.subarray(4),incoming);if(closed)return;
    await receive(Object.freeze({...decoded,wire}));
   }
  }catch(error){close(error);}finally{draining=false;if(!closed)socket.resume();}
 }
 socket.on('data',chunk=>{
  if(closed)return;
  if(input.length+chunk.length>bufferLimit){close(new DeviceExecutionError('execution_receive_capacity'));return;}
  input=Buffer.concat([input,chunk]);void drain();
 });
 socket.on('error',close);socket.on('end',()=>close());socket.on('close',()=>close());
 return Object.freeze({
  close,
  async send(payload,{beforeWrite}={}){
   need(!closed&&!socket.destroyed,'execution_closed');need(!writing,'execution_write_busy');writing=true;
   try{
    const decoded=await decodeExecutionPayload(payload,outgoing),wire=executionWire(decoded.payload);
    need(!closed&&!socket.destroyed,'execution_closed');
    if(beforeWrite!==undefined){need(typeof beforeWrite==='function','execution_write_check');
     const checked=beforeWrite();need(!checked||typeof checked.then!=='function','execution_write_check_async');
     if(checked===false)return Object.freeze({wire_length:0,not_started:true});}
    need(!closed&&!socket.destroyed,'execution_closed');
    await new Promise((resolve,reject)=>{writeReject=reject;socket.write(wire,error=>{
     if(error){close(error);return;}if(closed)return;writeReject=null;resolve();
    });});
    return Object.freeze({wire_length:wire.length});
   }catch(error){close(error);throw error;}finally{writing=false;}
  }
 });
}
