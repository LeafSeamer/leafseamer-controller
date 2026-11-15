import {createHash,randomUUID} from 'node:crypto';

const action='leafseamer.simulator.value.set',primitive='simulator_value_set',minimum=-2147483648,maximum=2147483647,maxCounter=99999999999999999999n;
const identity=Object.freeze({kind:'virtual',model:'leafseamer.simulator.control',revision:'1'});
const need=(ok,reason)=>{if(!ok)throw new Error('simulator_'+reason);};
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const ordered=value=>value&&typeof value==='object'?Array.isArray(value)?value.map(ordered):Object.fromEntries(Object.keys(value).sort().map(key=>[key,ordered(value[key])])):value;
const hash=value=>'sha256:'+createHash('sha256').update(JSON.stringify(ordered(value))).digest('hex');
export const simulatorEventLimits=Object.freeze({device_events:128,module_events:512,batch_events:32,captures:4096,record_bytes:1024});
const document={type:'object',additionalProperties:false,properties:{value:{type:'integer',minimum,maximum},
 sample_sequence:{type:'string',pattern:'^[1-9][0-9]{0,19}$(?![\\s\\S])'},
 write_sequence:{type:'string',pattern:'^(?:0|[1-9][0-9]{0,19})$(?![\\s\\S])'}},required:['value','sample_sequence','write_sequence']};
const stateSchema={schema_id:'leafseamer.simulator.control.state.1',dialect:'https://json-schema.org/draft/2020-12/schema',
 document,digest:'sha256:'+createHash('sha256').update(JSON.stringify(ordered(document))).digest('hex')};
export function simulatorControlCatalog(){return structuredClone({catalog_revision:'1',state_schema:stateSchema,action_ids:[action],trigger_ids:[]});}

// 每个模块实例拥有有限个纯内存虚拟设备，不访问网络、串口、文件或真实设备。
// execution只供固定worker的I/O仲裁器使用，不在只读模块IPC中增加写消息。
export function createDeviceModule(context){
 need(Array.isArray(context.device_ids)&&context.device_ids.length>0&&context.device_ids.length<=256&&
  new Set(context.device_ids).size===context.device_ids.length&&context.device_ids.every(id=>typeof id==='string'&&id.length>0&&id.length<=128)&&
  context.signal instanceof AbortSignal&&exact(context.configuration,[]),'configuration');
 const signal=context.signal,devices=new Map(context.device_ids.map(id=>[id,{value:0,writes:0n,session:null,samples:0n,capture:null}])),usedSessions=new Set(),usedCaptures=new Set();let retained=0;
 function tick(){need(typeof context.tick==='function','event_clock');const value=context.tick();need(typeof value==='bigint'&&value>=0n&&value<=maxCounter,'event_clock');return value;}
 function eventCapture(input){const device=live(input),capture=device.capture;need(capture&&capture.id===input.capture_id,'event_capture');return {device,capture};}
 function closeCapture(device){const capture=device.capture;if(!capture)return null;const result={capture_id:capture.id,last_sequence:String(capture.sequence),acknowledged_sequence:String(capture.acknowledged),discarded_events:capture.records.length,failure:capture.failure};retained-=capture.records.length;device.capture=null;return structuredClone(result);}
 function live(input,connected=true){
  need(!signal.aborted&&input.signal instanceof AbortSignal&&!input.signal.aborted,'unavailable');
  const device=devices.get(input.device_id);need(device,'device');
  need(typeof input.device_session_id==='string'&&input.device_session_id.length>0&&input.device_session_id.length<=128,'session');
  if(connected)need(device.session===input.device_session_id,'session');return device;
 }
 function decode(bytes){
  need(bytes instanceof Uint8Array&&bytes.byteLength===8,'packet');
  const copy=Uint8Array.from(bytes);
  need(copy[0]===76&&copy[1]===83&&copy[2]===77&&copy[3]===49,'packet');
  return new DataView(copy.buffer).getInt32(4,false);
 }
 return Object.freeze({api_version:'leafseamer-device-module/2',
  async connectReadOnly(input){
   const device=live(input,false);need(device.session===null&&!usedSessions.has(input.device_session_id),'session');need(usedSessions.size<4096,'capacity');
   usedSessions.add(input.device_session_id);device.session=input.device_session_id;device.samples=0n;return {...identity};
  },
  async proposeCatalog(input){
   live(input);need(exact(input.identity,['kind','model','revision'])&&Object.entries(identity).every(([key,value])=>input.identity[key]===value),'identity');
   return simulatorControlCatalog();
  },
  async captureBaseline(input){
   const device=live(input);need(device.samples<maxCounter,'capacity');device.samples++;
   return {value:device.value,sample_sequence:String(device.samples),write_sequence:String(device.writes)};
  },
  async stopReadOnly(input){const device=live(input);closeCapture(device);device.session=null;},
  // 该有界内存接口只供未来受信采集装配使用；批次确认仅释放模块缓存，不宣称持久摄取。
  // 目录仍不广告触发器，当前模块IPC也不自动启用此接口。
  events:Object.freeze({api_version:'leafseamer-device-event-capture/1',
   start(input){
    const device=live(input);need(typeof input.capture_id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$(?![\s\S])/.test(input.capture_id),'event_capture');
    need(!device.capture&&!usedCaptures.has(input.capture_id)&&usedCaptures.size<simulatorEventLimits.captures,'event_capture');const started=tick();
    const descriptor={format:'leafseamer-module-event-capture/1',capture_id:input.capture_id,device_id:input.device_id,device_session_id:input.device_session_id,
     event_type:'leafseamer.simulator.value.written',started_tick_ns:String(started),baseline:{write_sequence:String(device.writes)}};
    usedCaptures.add(input.capture_id);device.capture={id:input.capture_id,descriptor,sequence:0n,acknowledged:0n,lastTick:started,records:[],pending:null,lastAck:null,failure:null};return structuredClone(descriptor);
   },
   read(input){
    const {capture}=eventCapture(input);need(input.after_sequence===String(capture.acknowledged)&&Number.isInteger(input.max_events)&&input.max_events>0&&input.max_events<=simulatorEventLimits.batch_events,'event_cursor');
    if(capture.pending)need(capture.pending.limit===input.max_events,'event_batch_pending');
    else{
     const events=capture.records.slice(0,input.max_events),through=events.at(-1)?.sequence??String(capture.acknowledged);
     const body={format:'leafseamer-module-event-batch/1',capture:structuredClone(capture.descriptor),after_sequence:input.after_sequence,through_sequence:through,events:structuredClone(events)};
     capture.pending={limit:input.max_events,body,digest:hash(body)};
    }
    return structuredClone({state:capture.failure?'failed':'active',highest_sequence:String(capture.sequence),failure:capture.failure,batch:capture.pending.body,batch_digest:capture.pending.digest});
   },
   acknowledge(input){
    const {capture}=eventCapture(input),receipt={capture_id:capture.id,through_sequence:input.through_sequence,batch_digest:input.batch_digest};
    const pending=capture.pending;
    if(!pending||pending.digest!==input.batch_digest||pending.body.through_sequence!==input.through_sequence){need(capture.lastAck&&JSON.stringify(capture.lastAck)===JSON.stringify(receipt),'event_ack');return structuredClone(receipt);}
    const count=pending.body.events.length;capture.records.splice(0,count);retained-=count;capture.acknowledged=BigInt(input.through_sequence);capture.pending=null;capture.lastAck=receipt;return structuredClone(receipt);
   },
   stop(input){const {device}=eventCapture(input);return closeCapture(device);}
  }),
  execution:Object.freeze({api_version:'leafseamer-device-primitives/1',
   async encodePrimitive(input){
    live(input);need(input.primitive_id===primitive,'primitive');need(exact(input.parameters,['value']),'parameters');const value=input.parameters.value;
    need(Number.isInteger(value)&&!Object.is(value,-0)&&value>=minimum&&value<=maximum,'parameters');
    const bytes=new Uint8Array(8);bytes.set([76,83,77,49]);new DataView(bytes.buffer).setInt32(4,value,false);return bytes;
   },
   async writePrimitive(input){
    const device=live(input),value=decode(input.bytes);need(device.writes<maxCounter,'capacity');
    const capture=device.capture;let before,event;
    if(capture){
     need(!capture.failure,'event_failed');
     if(capture.records.length>=simulatorEventLimits.device_events||retained>=simulatorEventLimits.module_events||capture.sequence>=maxCounter){capture.failure={reason:'capacity',loss_extent:'none',missing_sequence:null};need(false,'event_capacity');}
     try{before=tick();need(before>=capture.lastTick,'event_clock');}catch(error){capture.failure={reason:'clock',loss_extent:'none',missing_sequence:null};throw error;}
     event={event_id:randomUUID(),sequence:String(capture.sequence+1n),event_type:'leafseamer.simulator.value.written',payload:{value,write_sequence:String(device.writes+1n)},
      capture_interval:{before_tick_ns:String(before),after_tick_ns:'99999999999999999999'}};
     need(Buffer.byteLength(JSON.stringify(event))<=simulatorEventLimits.record_bytes,'event_capacity');
    }
    // 从完整包校验到状态变更没有await。一次调用对应一次实际写；不隐藏重试、去重或排队。
    device.value=value;device.writes++;
    if(capture){
     capture.sequence++;
     try{const after=tick();need(after>=before,'event_clock');event.capture_interval.after_tick_ns=String(after);capture.lastTick=after;capture.records.push(event);retained++;}
     catch(error){capture.failure={reason:'clock',loss_extent:'known',missing_sequence:String(capture.sequence)};throw error;}
    }
    return {bytes_written:8,response:{value,write_sequence:String(device.writes)}};
   }
  })
 });
}
