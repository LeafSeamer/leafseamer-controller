import {TLSSocket} from 'node:tls';
import {createPeerWebsocketServer} from './peer-event-websocket.mjs';
import {eventChannelProtocol} from './service-event-channel.mjs';
import {createDecoder} from './sdk/runtime/panel-wire/decoder.mjs';
import {createHttpAdapter} from './sdk/http.mjs';
import {contractSelection} from './sdk/selection.mjs';

const ticketPrefix='leafseamer.ticket.';
const path='/api/v1/events';
const responseOptions={yieldNow:()=>Promise.resolve()};
const fail=()=>{throw Error('subscription_websocket');};

export function createHumanEventWebsocket({subscriptions,origin,stable}){
 const {tickets,channels}=subscriptions;
 const host=new URL(origin).host,decoder=createDecoder(contractSelection),http=createHttpAdapter(contractSelection);
 const client=decoder.websocket('controller','openEvents','client'),server=decoder.websocket('controller','openEvents','server');
 const websocket=createPeerWebsocketServer({protocol:eventChannelProtocol});
 async function response(value,beforeSend){
  const body=Buffer.from(JSON.stringify(value));
  await decoder.decode(body,server,responseOptions);
  return {messages:[body],beforeSend};
 }
 function open(grant,socket){
  const handle=channels.openHuman(grant,socket);
  let attached=false;
  return {
   initial:()=>response({type:'contract.ready',channel:grant.original.binding.channel},()=>tickets.checkAlive(grant)),
   async receive(bytes){
    const input=(await decoder.decode(bytes,client)).value;
    if(input.type!=='client.attach')fail();
    const result=channels.attach(handle,input);
    attached=true;
    return response(result.attached,()=>channels.check(handle));
   },
   check(){
    if(attached)channels.check(handle);
    else tickets.checkAlive(grant);
    return false;
   },
   close:()=>channels.close(handle)
  };
 }
 return Object.freeze({
  upgrade(request,socket,head){
   if(request.url!==path)return false;
   let status='400 Bad Request';
   try{
    stable();
    const pairs=[];
    for(let i=0;i<request.rawHeaders.length;i+=2)pairs.push([request.rawHeaders[i],request.rawHeaders[i+1]]);
    const single=name=>pairs.filter(([key])=>key.toLowerCase()===name);
    if(request.method!=='GET'||!(socket instanceof TLSSocket)||!socket.encrypted||!['TLSv1.2','TLSv1.3'].includes(socket.getProtocol())||
     request.headers.host!==host||single('host').length!==1||single('origin').length!==1||request.headers.origin!==origin||
     request.headers['sec-fetch-site']==='cross-site'||request.headers.authorization!==undefined||
     request.headers['content-length']!==undefined||request.headers['transfer-encoding']!==undefined)fail();
    http.prepareRequest('controller','GET',path,pairs);
    const offered=single('sec-websocket-protocol');
    if(offered.length!==1||request.headers['sec-websocket-version']!=='13'||
     !/^[A-Za-z0-9+/]{22}==$/.test(request.headers['sec-websocket-key']??''))fail();
    const protocols=offered[0][1].split(',').map(value=>value.trim());
    if(protocols.length!==2||!protocols.includes(eventChannelProtocol))fail();
    const ticket=protocols.find(value=>value!==eventChannelProtocol);
    if(!ticket?.startsWith(ticketPrefix)||!/^[A-Za-z0-9_-]{43}$/.test(ticket.slice(ticketPrefix.length)))fail();
    status='403 Forbidden';
    const grant=tickets.consume(ticket.slice(ticketPrefix.length),origin);
    // 已核对并消费凭据，传输层只需协商并回显公开契约 token。
    request.headers['sec-websocket-protocol']=eventChannelProtocol;
    websocket.accept(request,socket,head,{open:()=>open(grant,socket),stable});
   }catch{
    if(socket.writable)socket.end('HTTP/1.1 '+status+'\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n');
    else socket.destroy();
   }
   return true;
  },
  sweep:websocket.sweep,
  close:websocket.close
 });
}
