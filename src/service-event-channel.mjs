import {createDecoder} from './sdk/runtime/panel-wire/decoder.mjs';
import {createHttpAdapter} from './sdk/http.mjs';
import {contractSelection as selection} from './sdk/selection.mjs';
export const eventChannelProtocol='leafseamer.contract.'+selection.contract_id+'.'+selection.contract_digest.slice(7);
const smallResponseDecode=Object.freeze({yieldNow:()=>Promise.resolve()});
export function serviceEventChannel(store){
 const decoder=createDecoder(selection),http=createHttpAdapter(selection),client=decoder.websocket('controller','internalOpenEvents','client'),server=decoder.websocket('controller','internalOpenEvents','server');
 return Object.freeze({protocol:eventChannelProtocol,
  prepare(headers){if(!store.channels)throw Error('subscription_channel_unavailable');http.prepareRequest('controller','GET','/internal/events',headers);},
  open(binding,socket){const handle=store.channels.open(binding,socket);let selected=false;
   return {async receive(bytes){const input=(await decoder.decode(bytes,client)).value;if(input.type==='client.snapshot.applied'||input.type==='client.ack'){
     if(!selected)throw Error('subscription_attach_required');
     if(input.type==='client.ack')store.channels.ack(handle,input);else store.channels.applied(handle,input);
     return {messages:[],beforeSend:()=>store.channels.check(handle)};
    }if(input.type!=='client.attach')throw Error('subscription_frame_unavailable');
    const result=store.channels.attach(handle,input),values=selected?[result.attached]:[result.ready,result.attached],messages=[];
    for(const value of values){const body=Buffer.from(JSON.stringify(value));await decoder.decode(body,server);messages.push(body);}selected=true;
    return {messages,beforeSend:()=>store.channels.check(handle)};
   },async next(idle=false){
    if(!selected||!store.channels.deliversReconcile)return null;
    if(idle&&!store.channels.hasLiveWork(handle))return null;
    const frame=store.channels.nextReconcile(handle);
    if(!frame)return null;
    const body=Buffer.from(JSON.stringify(frame));
    // 小型服务端帧来自当前已核验的持久条目，避免定时器调度消耗原扫描期限。
    await decoder.decode(body,server,body.length<=16384?smallResponseDecode:undefined);
    return {body,beforeSend:()=>store.channels.checkDelivery(handle,frame),afterSend:()=>store.channels.transmitted(handle,frame)};
   },check:()=>selected&&store.channels.poll(handle),close:()=>store.channels.close(handle)};
  }
 });
}
