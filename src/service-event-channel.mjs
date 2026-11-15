import {createDecoder} from './sdk/runtime/panel-wire/decoder.mjs';
import {createHttpAdapter} from './sdk/http.mjs';
import {contractSelection as selection} from './sdk/selection.mjs';
export const eventChannelProtocol='leafseamer.contract.'+selection.contract_id+'.'+selection.contract_digest.slice(7);
export function serviceEventChannel(store){
 const decoder=createDecoder(selection),http=createHttpAdapter(selection),client=decoder.websocket('controller','internalOpenEvents','client'),server=decoder.websocket('controller','internalOpenEvents','server');
 return Object.freeze({protocol:eventChannelProtocol,
  prepare(headers){if(!store.channels)throw Error('subscription_channel_unavailable');http.prepareRequest('controller','GET','/internal/events',headers);},
  open(binding,socket){const handle=store.channels.open(binding,socket);let selected=false;
   return {async receive(bytes){const input=(await decoder.decode(bytes,client)).value;if(input.type==='client.snapshot.applied'){if(!selected)throw Error('subscription_attach_required');store.channels.applied(handle,input);return {messages:[],beforeSend:()=>store.channels.check(handle)};}if(input.type!=='client.attach')throw Error('subscription_frame_unavailable');
    const result=store.channels.attach(handle,input),values=selected?[result.attached]:[result.ready,result.attached],messages=[];
    for(const value of values){const body=Buffer.from(JSON.stringify(value));await decoder.decode(body,server);messages.push(body);}selected=true;
    return {messages,beforeSend:()=>store.channels.check(handle)};
   },check:()=>{if(selected)store.channels.poll(handle);},close:()=>store.channels.close(handle)};
  }
 });
}
