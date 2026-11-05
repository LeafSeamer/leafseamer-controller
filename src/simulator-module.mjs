// 可作为固定扩展入口发布的虚拟设备模块。每次采样读取当前会话状态并推进独立样本号。
export function createDeviceModule(context){
 const sessions=new Map(),devices=new Set(context.device_ids);
 const live=input=>{if(context.signal.aborted||input.signal.aborted||!devices.has(input.device_id))throw new Error('simulator_unavailable');};
 return Object.freeze({api_version:'leafseamer-device-module/1',
  async connectReadOnly(input){live(input);if(sessions.has(input.device_id))throw new Error('simulator_session');
   sessions.set(input.device_id,{id:input.device_session_id,value:0,ordinal:0n});return {kind:'virtual',model:'leafseamer.simulator',revision:'1'};},
  async captureBaseline(input){live(input);const session=sessions.get(input.device_id);if(session?.id!==input.device_session_id)throw new Error('simulator_session');
   if(session.ordinal>=99999999999999999999n)throw new Error('simulator_capacity');session.ordinal++;
   return {value:session.value,sample_sequence:String(session.ordinal)};},
  async stopReadOnly(input){live(input);const session=sessions.get(input.device_id);if(session?.id!==input.device_session_id)throw new Error('simulator_session');sessions.delete(input.device_id);}
 });
}
