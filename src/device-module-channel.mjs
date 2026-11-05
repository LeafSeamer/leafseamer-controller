import net from 'node:net';
import canonicalize from './runtime/canonicalize.mjs';
import {validateDeviceModuleFrame,moduleNeed,DeviceModuleError} from './sdk/device-module.mjs';

export const moduleDigestEqual=(a,b)=>canonicalize(a)===canonicalize(b);
export function moduleSocket(memberBoot,side){
 moduleNeed(process.platform==='win32'&&/^[0-9a-f]{32}$(?![\s\S])/.test(memberBoot)&&['core','worker'].includes(side),'module_endpoint');
 return net.createConnection('\\\\.\\pipe\\LeafSeamer.Module.'+memberBoot+'.'+side);
}
function data(value,depth=0,budget={nodes:0}){
 moduleNeed(depth<=48&&++budget.nodes<=65536,'module_capacity');
 if(value===null||typeof value==='boolean')return;
 if(typeof value==='number'){moduleNeed(Number.isFinite(value),'module_number');return;}
 if(typeof value==='string'){moduleNeed(value.length<=524288&&!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value),'module_string');return;}
 moduleNeed(value&&typeof value==='object'&&(Array.isArray(value)||Object.getPrototypeOf(value)===Object.prototype),'module_json');
 for(const [key,item] of Object.entries(value)){data(key,depth+1,budget);data(item,depth+1,budget);}
}
export function moduleFrameBytes(frame){
 data(frame);validateDeviceModuleFrame(frame);const bytes=Buffer.from(canonicalize(frame)+'\n');moduleNeed(bytes.length<=1048576,'module_capacity');return bytes;
}
// 单个有界入站帧。禁止混入第二条未受理消息；丢连接不重连、不重发。
export function moduleTransport(socket,{receive,failed}){
 let input=Buffer.alloc(0),busy=false,closed=false;
 const close=()=>{if(closed)return;closed=true;socket.destroy();try{failed(new DeviceModuleError('module_channel_closed'));}catch{}};
 socket.on('error',close);socket.on('close',close);socket.on('end',close);
 socket.on('data',chunk=>{
  if(closed)return;
  try{
   moduleNeed(!busy&&input.length+chunk.length<=1048576,'module_capacity');input=Buffer.concat([input,chunk]);const end=input.indexOf(10);if(end<0)return;
   moduleNeed(end===input.length-1,'module_order');const text=new TextDecoder('utf-8',{fatal:true}).decode(input.subarray(0,end));input=Buffer.alloc(0);
   const frame=JSON.parse(text);data(frame);moduleNeed(canonicalize(frame)===text,'module_canonical');validateDeviceModuleFrame(frame);busy=true;
   Promise.resolve().then(()=>receive(frame)).then(()=>{busy=false;},close);
  }catch{close();}
 });
 return Object.freeze({close,send(frame){moduleNeed(!closed&&!socket.destroyed,'module_channel_closed');const bytes=moduleFrameBytes(frame);
  return new Promise((resolve,reject)=>socket.write(bytes,error=>{if(error){close();reject(new DeviceModuleError('module_channel_closed'));}else resolve();}));}});
}
