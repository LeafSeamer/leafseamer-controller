import {createHash} from 'node:crypto';

const action='leafseamer.simulator.value.set',primitive='simulator_value_set',minimum=-2147483648,maximum=2147483647,maxCounter=99999999999999999999n;
const identity=Object.freeze({kind:'virtual',model:'leafseamer.simulator.control',revision:'1'});
const need=(ok,reason)=>{if(!ok)throw new Error('simulator_'+reason);};
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const ordered=value=>value&&typeof value==='object'?Array.isArray(value)?value.map(ordered):Object.fromEntries(Object.keys(value).sort().map(key=>[key,ordered(value[key])])):value;
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
 const signal=context.signal,devices=new Map(context.device_ids.map(id=>[id,{value:0,writes:0n,session:null,samples:0n}])),usedSessions=new Set();
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
  async stopReadOnly(input){const device=live(input);device.session=null;},
  execution:Object.freeze({api_version:'leafseamer-device-primitives/1',
   async encodePrimitive(input){
    live(input);need(input.primitive_id===primitive,'primitive');need(exact(input.parameters,['value']),'parameters');const value=input.parameters.value;
    need(Number.isInteger(value)&&!Object.is(value,-0)&&value>=minimum&&value<=maximum,'parameters');
    const bytes=new Uint8Array(8);bytes.set([76,83,77,49]);new DataView(bytes.buffer).setInt32(4,value,false);return bytes;
   },
   async writePrimitive(input){
    const device=live(input),value=decode(input.bytes);need(device.writes<maxCounter,'capacity');
    // 从完整包校验到状态变更没有await。一次调用对应一次实际写；不隐藏重试、去重或排队。
    device.value=value;device.writes++;
    return {bytes_written:8,response:{value,write_sequence:String(device.writes)}};
   }
  })
 });
}
