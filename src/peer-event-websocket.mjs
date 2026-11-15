import WebSocket,{WebSocketServer} from 'ws';
const limit=65536;
const guard=ok=>{if(!ok)throw Error('subscription_websocket');};
export function createPeerWebsocketServer({protocol}){
 const server=new WebSocketServer({noServer:true,perMessageDeflate:false,maxPayload:limit,maxFragments:16,maxBufferedChunks:16,handleProtocols:offered=>offered.size===1&&offered.has(protocol)?protocol:false});
 const active=new Set();
 return Object.freeze({
  accept(request,socket,head,{open,stable}){guard(active.size<16);server.handleUpgrade(request,socket,head,ws=>{
   let app;try{stable();app=open();}catch{ws.terminate();return;}let queued=0,chain=Promise.resolve(),ended=false;const timer=setTimeout(()=>ws.terminate(),5000);timer.unref();
   const stop=()=>{if(ended)return;ended=true;clearTimeout(timer);active.delete(connection);try{app.close();}catch{}};
   const connection={ws,check(){try{stable();app.check();}catch{ws.terminate();stop();}}};active.add(connection);ws.on('error',()=>{ws.terminate();stop();});ws.on('close',stop);
   ws.on('message',(bytes,binary)=>{if(binary||++queued>4){ws.terminate();stop();return;}chain=chain.then(async()=>{guard(!ended);stable();const result=await app.receive(Buffer.from(bytes));
    for(const body of result.messages){guard(!ended&&ws.readyState===WebSocket.OPEN&&ws.bufferedAmount+body.length<=limit&&body.length<=limit);stable();result.beforeSend();ws.send(body,{binary:false});}
    clearTimeout(timer);
   }).catch(()=>{ws.terminate();stop();}).finally(()=>{queued--;});});
  });},
  sweep(){for(const connection of active)connection.check();},
  close(){for(const {ws}of active)ws.terminate();return new Promise(resolve=>server.close(()=>resolve()));}
 });
}
export function openPeerWebsocket(url,protocol,options,{stable,onFrame,onClose}){
 return new Promise((resolve,reject)=>{let opened=false,ended=false,queued=0,chain=Promise.resolve(),peerSocket;const ws=new WebSocket(url,protocol,{...options,perMessageDeflate:false,maxPayload:limit,maxFragments:16,maxBufferedChunks:16,handshakeTimeout:5000,followRedirects:false});
  const stop=error=>{if(ended)return;ended=true;if(!opened)reject(error??Error('subscription_closed'));try{onClose?.(error);}catch{}};
  ws.on('error',error=>{ws.terminate();stop(error);});ws.on('close',()=>stop());
  ws.on('upgrade',response=>{try{peerSocket=response.socket;stable(peerSocket);guard(response.headers['sec-websocket-protocol']===protocol);}catch(error){ws.terminate();stop(error);}});
  ws.on('open',()=>{try{stable(peerSocket);guard(ws.protocol===protocol);opened=true;resolve(Object.freeze({
   send(bytes){guard(!ended&&Buffer.isBuffer(bytes)&&bytes.length<=limit&&ws.readyState===WebSocket.OPEN&&ws.bufferedAmount+bytes.length<=limit);stable(peerSocket);ws.send(bytes,{binary:false});},
   check(){guard(!ended&&ws.readyState===WebSocket.OPEN);stable(peerSocket);},checkInTransaction(){guard(!ended&&ws.readyState===WebSocket.OPEN);stable(peerSocket,true);},close(){ws.terminate();stop();}
  }));}catch(error){ws.terminate();stop(error);}});
  ws.on('message',(bytes,binary)=>{if(binary||++queued>4){ws.terminate();stop(Error('subscription_frame'));return;}chain=chain.then(async()=>{guard(!ended);stable(peerSocket);await onFrame(Buffer.from(bytes));stable(peerSocket);}).catch(error=>{ws.terminate();stop(error);}).finally(()=>{queued--;});});
 });
}
