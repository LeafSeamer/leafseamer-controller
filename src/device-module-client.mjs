import crypto from 'node:crypto';
import {openNativeClock} from './native-clock.mjs';
import {moduleNeed as need,DeviceModuleError,deviceModuleProtocol,deviceModuleEventProtocol} from './sdk/device-module.mjs';
import canonicalize from './runtime/canonicalize.mjs';
import {moduleSocket,moduleTransport,moduleFrameBytes,moduleDigestEqual as same} from './device-module-channel.mjs';

// 核心内部调用；current/invalidate绑定同库当前运行原件，HTTP调用方不能提供这些函数。
export async function connectDeviceModule({current,invalidate,configuration,journal,catalog,onClose,events=false,eventSource=null,socket}){
 need(typeof events==='boolean','module_version');const protocol=events?deviceModuleEventProtocol:deviceModuleProtocol,captures=new Map();
 const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
 const initial=current(),clock=openNativeClock(),sessions=new Map();
 const binding=Object.freeze({runtime_binding_ref:initial.ref,ipc_session_id:crypto.randomUUID(),member_boot_id:initial.binding.admission_receipt.member_boot_id});
 const devices=initial.binding.launch_intent.object_scope.device_ids;
 let transport,stopped=false,sequence=1n,pending=null,timer=null,monitor=null;
 const fail=()=>{if(stopped)return;stopped=true;clearTimeout(timer);clearInterval(monitor);const call=pending;pending=null;
  transport?.close();try{invalidate();}catch{}try{onClose?.();}catch{}call?.reject(new DeviceModuleError('module_channel_closed'));};
 const check=()=>{need(!stopped,'module_closed');const actual=current();need(actual.current_boot&&!actual.withdrawal&&same(actual.ref,initial.ref),'module_binding');return actual;};
 journal.open(binding);
 transport=moduleTransport(socket??moduleSocket(binding.member_boot_id,'core'),{failed:fail,receive(frame){
  check();const call=pending;need(call&&frame.version===protocol&&frame.type===call.response&&frame.sequence===call.request.sequence&&frame.reply_to===call.request.request_id&&same(frame.binding,binding)&&
   frame.issued_tick_ns===call.request.issued_tick_ns&&frame.deadline_tick_ns===call.request.deadline_tick_ns,'module_reply');
  const now=clock.tick();need(now>=BigInt(frame.issued_tick_ns)&&now<BigInt(frame.deadline_tick_ns),'module_expired');
  for(const key of ['device_id','device_session_id','capture_id'])if(Object.hasOwn(call.request.body,key))need(frame.body[key]===call.request.body[key],'module_reply');
  journal.record('w2c',frame);check();need(clock.tick()<BigInt(frame.deadline_tick_ns),'module_expired');clearTimeout(timer);pending=null;call.resolve(frame);
 }});
 async function request(type,body,response){
  check();need(!pending&&sequence<=99999999999999999999n,'module_busy');const issued=clock.tick();
  const frame={version:protocol,type,sequence:String(sequence++),request_id:crypto.randomUUID(),reply_to:null,binding,
   issued_tick_ns:String(issued),deadline_tick_ns:String(issued+2000000000n),body};
  let resolve,reject;const result=new Promise((yes,no)=>{resolve=yes;reject=no;});result.catch(()=>{});pending={request:frame,response,resolve,reject};timer=setTimeout(fail,2000);
  try{moduleFrameBytes(frame);journal.record('c2w',frame);check();need(clock.tick()<BigInt(frame.deadline_tick_ns),'module_expired');await transport.send(frame);const answer=await result;check();return answer;}
  catch(error){fail();await result.catch(()=>{});throw error;}
 }
 function eventSession(deviceId,existing=true,readCommitted=false){
  check();const capture=captures.get(deviceId);
  // 订阅读取只使用已提交前缀，无需占用模块管道。停采从发出请求起停止该采集的读取。
  need(events&&(!pending||readCommitted)&&!capture?.stopping,'module_event_unavailable');
  const selected=sessions.get(deviceId);need(selected?.state==='connected','module_session');
  need(existing?capture:!capture,'module_event_capture');return {selected,capture};
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
   try{const frame=await request('DISCONNECT',{device_id:deviceId,device_session_id:selected.session},'DISCONNECTED');eventSource?.disconnect(frame);sessions.delete(deviceId);captures.delete(deviceId);return frame;}catch(error){fail();throw error;}
  },
  currentBaseline(deviceId){
   check();need(!pending,'module_busy');const selected=sessions.get(deviceId);need(selected?.state==='connected','module_session');
   try{return catalog.current(binding.ipc_session_id,deviceId,selected.session);}catch(error){fail();throw error;}
  },
  bindExecution(deviceId){
   check();need(!pending,'module_busy');const selected=sessions.get(deviceId);need(selected?.state==='connected','module_session');
   try{return catalog.bindExecution(binding.ipc_session_id,deviceId,selected.session);}catch(error){fail();throw error;}
  },
  async configureExecution(deviceId){
   check();need(!pending,'module_busy');const selected=sessions.get(deviceId);need(selected?.state==='connected','module_session');
   try{
    const execution=catalog.bindExecution(binding.ipc_session_id,deviceId,selected.session);
    const answer=await request('BIND_EXECUTION',{device_id:deviceId,device_session_id:selected.session,execution},'EXECUTION_BOUND');
    need(same(answer.body.execution_ref,execution.ref),'module_execution_binding');return execution;
   }catch(error){fail();throw error;}
  },
  async startEvents(deviceId){
   const {selected}=eventSession(deviceId,false),body={device_id:deviceId,device_session_id:selected.session,capture_id:crypto.randomUUID()};
   try{const frame=await request('EVENT_START',body,'EVENT_STARTED');eventSource?.start(frame);captures.set(deviceId,{body,started:frame,descriptor:frame.body.capture,acknowledged:'0',highest:'0',lastTick:frame.body.capture.started_tick_ns,pending:null,lastAck:null,failure:null});return frame;}catch(error){fail();throw error;}
  },
  async readEvents(deviceId,maxEvents=32){
   const {capture:c}=eventSession(deviceId);need(Number.isInteger(maxEvents)&&maxEvents>=1&&maxEvents<=32&&(!c.pending||c.pending.limit===maxEvents),'module_event_batch');
   try{
    const frame=await request('EVENT_READ',{...c.body,after_sequence:c.acknowledged,max_events:maxEvents},'EVENT_BATCH'),r=frame.body.result,b=r.batch;
    need(same(b.capture,c.descriptor)&&b.after_sequence===c.acknowledged&&b.events.length<=maxEvents&&hash(b)===r.batch_digest&&BigInt(r.highest_sequence)>=BigInt(c.highest),'module_event_batch');
    if(c.pending)need(same(b,c.pending.batch)&&r.batch_digest===c.pending.digest,'module_event_batch');
    if(c.failure)need(same(r.failure,c.failure),'module_event_failure');
    if(b.events.length)need(BigInt(b.events[0].capture_interval.before_tick_ns)>=BigInt(c.lastTick),'module_event_clock');
    eventSource?.accept(frame);c.pending={batch:b,digest:r.batch_digest,limit:maxEvents};c.highest=r.highest_sequence;c.failure=r.failure;return frame;
   }catch(error){fail();throw error;}
  },
  publishedEvents(deviceId,after='0',limit=32){
   const {capture}=eventSession(deviceId,true,true);need(eventSource,'module_event_source_unavailable');
   try{return eventSource.read(capture.started,after,limit);}catch(error){fail();throw error;}
  },
  qualifiedEventCapture(deviceId){
   const {selected,capture}=eventSession(deviceId);
   try{const value=catalog.currentEventCapture(binding.ipc_session_id,deviceId,selected.session);
    need(same(value.capture,capture.descriptor),'module_event_source_binding');return value;
   }catch(error){fail();throw error;}
  },
  async acknowledgeEvents(deviceId,receipt){
   const {capture:c}=eventSession(deviceId);need(receipt&&Object.keys(receipt).sort().join(',')==='batch_digest,through_sequence','module_event_ack');
   const match=c.pending&&c.pending.digest===receipt.batch_digest&&c.pending.batch.through_sequence===receipt.through_sequence;
   need(match||c.lastAck&&same(receipt,c.lastAck),'module_event_ack');
   try{const frame=await request('EVENT_ACK',{...c.body,...receipt},'EVENT_ACKED');need(frame.body.through_sequence===receipt.through_sequence&&frame.body.batch_digest===receipt.batch_digest,'module_event_ack');
    if(match){c.lastTick=c.pending.batch.events.at(-1)?.capture_interval.after_tick_ns??c.lastTick;c.acknowledged=receipt.through_sequence;c.pending=null;c.lastAck={...receipt};}return frame;
   }catch(error){fail();throw error;}
  },
  async stopEvents(deviceId){
   const {capture:c}=eventSession(deviceId);c.stopping=true;
   try{const frame=await request('EVENT_STOP',c.body,'EVENT_STOPPED'),closed=frame.body.closed;
    need(closed.acknowledged_sequence===c.acknowledged&&BigInt(closed.last_sequence)>=BigInt(c.highest)&&(!c.failure||same(closed.failure,c.failure)),'module_event_stop');eventSource?.stop(frame);captures.delete(deviceId);return frame;
   }catch(error){fail();throw error;}
  },
  close:fail
 });
}
