import crypto from 'node:crypto';
import {openNativeClock} from './native-clock.mjs';
import {moduleNeed as need,DeviceModuleError,deviceModuleProtocol} from './sdk/device-module.mjs';
import {moduleSocket,moduleTransport,moduleFrameBytes,moduleDigestEqual as same} from './device-module-channel.mjs';

// 核心内部调用；current/invalidate绑定同库当前运行原件，HTTP调用方不能提供这些函数。
export async function connectDeviceModule({current,invalidate,configuration,journal,catalog,onClose}){
 const initial=current(),clock=openNativeClock(),sessions=new Map();
 const binding=Object.freeze({runtime_binding_ref:initial.ref,ipc_session_id:crypto.randomUUID(),member_boot_id:initial.binding.admission_receipt.member_boot_id});
 const devices=initial.binding.launch_intent.object_scope.device_ids;
 let transport,stopped=false,sequence=1n,pending=null,timer=null,monitor=null;
 const fail=()=>{if(stopped)return;stopped=true;clearTimeout(timer);clearInterval(monitor);const call=pending;pending=null;
  transport?.close();try{invalidate();}catch{}try{onClose?.();}catch{}call?.reject(new DeviceModuleError('module_channel_closed'));};
 const check=()=>{need(!stopped,'module_closed');const actual=current();need(actual.current_boot&&!actual.withdrawal&&same(actual.ref,initial.ref),'module_binding');return actual;};
 journal.open(binding);
 transport=moduleTransport(moduleSocket(binding.member_boot_id,'core'),{failed:fail,receive(frame){
  check();const call=pending;need(call&&frame.type===call.response&&frame.sequence===call.request.sequence&&frame.reply_to===call.request.request_id&&same(frame.binding,binding)&&
   frame.issued_tick_ns===call.request.issued_tick_ns&&frame.deadline_tick_ns===call.request.deadline_tick_ns,'module_reply');
  const now=clock.tick();need(now>=BigInt(frame.issued_tick_ns)&&now<BigInt(frame.deadline_tick_ns),'module_expired');
  for(const key of ['device_id','device_session_id','capture_id'])if(Object.hasOwn(call.request.body,key))need(frame.body[key]===call.request.body[key],'module_reply');
  journal.record('w2c',frame);check();need(clock.tick()<BigInt(frame.deadline_tick_ns),'module_expired');clearTimeout(timer);pending=null;call.resolve(frame);
 }});
 async function request(type,body,response){
  check();need(!pending&&sequence<=99999999999999999999n,'module_busy');const issued=clock.tick();
  const frame={version:deviceModuleProtocol,type,sequence:String(sequence++),request_id:crypto.randomUUID(),reply_to:null,binding,
   issued_tick_ns:String(issued),deadline_tick_ns:String(issued+2000000000n),body};
  let resolve,reject;const result=new Promise((yes,no)=>{resolve=yes;reject=no;});result.catch(()=>{});pending={request:frame,response,resolve,reject};timer=setTimeout(fail,2000);
  try{moduleFrameBytes(frame);journal.record('c2w',frame);check();need(clock.tick()<BigInt(frame.deadline_tick_ns),'module_expired');await transport.send(frame);const answer=await result;check();return answer;}
  catch(error){fail();await result.catch(()=>{});throw error;}
 }
 try{
  monitor=setInterval(()=>{try{check();}catch{fail();}},100);monitor.unref();
  const loaded=await request('LOAD',{runtime:initial.binding,configuration},'LOADED');need(loaded.body.entry_id===initial.binding.launch_intent.extension_binding.entry_id,'module_entry');
 }catch(error){fail();throw error;}
 return Object.freeze({binding,
  async connectReadOnly(deviceId){
   check();need(!pending,'module_busy');need(devices.includes(deviceId)&&!sessions.has(deviceId),'module_device');const session=crypto.randomUUID();sessions.set(deviceId,{session,state:'connecting'});
   const frame=await request('CONNECT',{device_id:deviceId,device_session_id:session},'CONNECTED');sessions.set(deviceId,{session,state:'connected'});return frame;
  },
  async captureBaseline(deviceId){
   check();const selected=sessions.get(deviceId);need(selected?.state==='connected','module_session');
   return request('CAPTURE',{device_id:deviceId,device_session_id:selected.session,capture_id:crypto.randomUUID()},'CAPTURED');
  },
  async stopReadOnly(deviceId){
   check();need(!pending,'module_busy');const selected=sessions.get(deviceId);need(selected?.state==='connected','module_session');sessions.set(deviceId,{...selected,state:'disconnecting'});
   const frame=await request('DISCONNECT',{device_id:deviceId,device_session_id:selected.session},'DISCONNECTED');sessions.delete(deviceId);return frame;
  },
  currentBaseline(deviceId){
   check();need(!pending,'module_busy');const selected=sessions.get(deviceId);need(selected?.state==='connected','module_session');
   try{return catalog.current(binding.ipc_session_id,deviceId,selected.session);}catch(error){fail();throw error;}
  },
  close:fail
 });
}
