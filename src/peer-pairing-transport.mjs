import https from 'node:https';
import crypto from 'node:crypto';
import {TLSSocket} from 'node:tls';
import {isIP} from 'node:net';
import {digest, same,canonical} from './auth-clock-value.mjs';
import {pairingNeed as need,pairingCertificate,pairingReference} from './peer-pairing-value.mjs';
import {decodeSessionDenial,sessionDenialNotice,sessionDenialReceipt} from './peer-session-denial.mjs';
import {startSessionDenialDelivery} from './session-denial-delivery.mjs';
import {createPeerWebsocketServer,openPeerWebsocket} from './peer-event-websocket.mjs';
import {authorizeDeviceBindings,deviceBindingsRequest,deviceBindingsReply,decodeDeviceBindings,deviceBindingsLimit} from './peer-device-bindings.mjs';
import {authorizeDeviceEvents,deviceEventsRequest,deviceEventsReply,decodeDeviceEvents,deviceEventsLimit,deviceEventSourceRef} from './peer-device-events.mjs';
const day=86400000000000n,sha=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
function certificate(pem,ca=false){
 const x=new crypto.X509Certificate(pem),duration=BigInt(x.validToDate.getTime()-x.validFromDate.getTime())*1000000n;
 need(x.ca===ca&&x.publicKey.asymmetricKeyType==='ec'&&x.publicKey.asymmetricKeyDetails?.namedCurve==='prime256v1'&&
  x.signatureAlgorithmOid==='1.2.840.10045.4.3.2'&&duration>0n&&duration<=(ca?1827n:90n)*day,'certificate_profile');
 if(!ca)need(x.keyUsage?.includes('1.3.6.1.5.5.7.3.1')&&x.keyUsage.includes('1.3.6.1.5.5.7.3.2'),'certificate_usage');return x;
}
function inTime(x,clock){const current=clock.pairingSample();need(BigInt(current.lower_ns)>=BigInt(x.validFromDate.getTime())*1000000n&&BigInt(current.upper_ns)<BigInt(x.validToDate.getTime())*1000000n,'certificate_expired');}
function name(x,host){need(typeof host==='string'&&host.length>0&&host.length<=253,'certificate_name');
 need(isIP(host)?x.checkIP(host)===host:x.checkHost(host,{subject:'never',wildcards:false,partialWildcards:false,multiLabelWildcards:false,singleLabelSubdomains:false})===host,'certificate_name');}
function endpoint(origin,serverName){const url=new URL(origin);need(url.protocol==='https:'&&!url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==='/'&&url.origin===origin,'endpoint');
 return {origin:url.origin,server_name:serverName};}

// 独立内部监听。pending只交付具名配对状态；普通核验另需显式处理器、active及用途授权。
export async function startPeerPairingTransport({pairings,clock,identity,cert,key,ca,host='127.0.0.1',port=0,serverName=host,introspection=null,sessionDenial=null,sessionDenials=null,deviceBindings=null,deviceEvents=null,subscriptions=null}){
 need(['127.0.0.1','::1'].includes(host)&&Number.isInteger(port)&&port>=0&&port<=65535,'listen');
 need(pairings&&typeof clock?.pairingSample==='function','configuration');
 need(sessionDenials===null||(identity.service_kind==='controller'&&typeof sessionDenials.scan==='function'&&typeof sessionDenials.deliverPending==='function'),'session_denial_delivery');
 const local=certificate(cert),roots=(Array.isArray(ca)?ca:[ca]).map(pem=>certificate(pem,true));
 need(roots.length>0&&roots.length<=8&&roots.some(root=>local.checkIssued(root)&&local.verify(root.publicKey))&&local.checkPrivateKey(crypto.createPrivateKey(key)),'certificate_chain');name(local,serverName);
 const localRoot=roots.find(root=>local.checkIssued(root)&&local.verify(root.publicKey));
 const trustDigest=digest(roots.map(root=>sha(root.raw)).sort());let peers=null,closed=false;
 const validate=(socket,peer)=>{
  need(socket instanceof TLSSocket&&socket.encrypted&&socket.authorized&&socket.getProtocol()==='TLSv1.3'&&!socket.isSessionReused(),'tls');
  const remote=socket.getPeerX509Certificate();need(remote&&same(pairingCertificate(remote.raw),pairingCertificate(peer.cert)),'certificate_binding');
  const checked=certificate(remote.raw);name(checked,peer.server_name);inTime(checked,clock);inTime(local,clock);inTime(localRoot,clock);
  const issuer=roots.find(root=>checked.checkIssued(root)&&checked.verify(root.publicKey));need(issuer,'certificate_chain');inTime(issuer,clock);
 };
 const current=(bindingId,socket,reference=null)=>{need(!closed&&peers,'configuration_missing');const record=reference?pairings.requireActivatedInTransaction(reference):pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);
  need(peer,'peer');validate(socket,peer);const party=record.transcript.parties.find(p=>p.service_id===peer.identity.service_id);
  need(same(pairingCertificate(socket.getPeerX509Certificate().raw),{certificate_der_sha256:party.certificate_der_sha256,spki_sha256:party.spki_sha256}),'certificate_binding');return record;};
 const server=https.createServer({key,cert,ca:roots.map(root=>root.toString()),requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',
  secureOptions:crypto.constants.SSL_OP_NO_TICKET,maxHeaderSize:8192,requestTimeout:5000,headersTimeout:5000,handshakeTimeout:5000,keepAliveTimeout:1000},async(req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  try{
   if(req.url==='/internal/subscriptions'||/^\/internal\/subscriptions\/[A-Za-z0-9_-]{1,128}(?:(?:\/snapshot|\/snapshots\/[A-Za-z0-9_-]{1,128}\/pages\/[0-9]{1,3})\?expected_connection_generation=[0-9]{1,20}|\/snapshot-context|\/connections\/[A-Za-z0-9_-]{1,128}|\?expected_revision=[0-9]{1,20})?$/.test(req.url)){
    need(subscriptions&&identity.service_kind==='controller'&&(req.url==='/internal/subscriptions'||req.url.endsWith('/snapshot-context')?req.method==='POST':['GET','DELETE'].includes(req.method)),'route');
    need(req.headers.authorization===undefined&&req.headers.cookie===undefined,'purpose');const bindingId=req.headers['x-leafseamer-pairing'];
    const authorized=()=>{const record=current(bindingId,req.socket),peer=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);need(record.state==='activated'&&peer.permissions.includes('event.internal.subscribe'),'purpose');return record;};
    const initial=authorized();need(req.headers['transfer-encoding']===undefined,'body');
    if(req.method!=='POST')need(!req.headers['content-length']||req.headers['content-length']==='0','body');
    else need(req.headers['content-type']==='application/json'&&/^[1-9][0-9]{0,4}$/.test(req.headers['content-length'])&&Number(req.headers['content-length'])<=16384,'body');
    const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;need(size<=16384,'capacity');chunks.push(chunk);}need(same(authorized(),initial),'changed');
    const headers=[];for(let i=0;i<req.rawHeaders.length;i+=2)headers.push([req.rawHeaders[i],req.rawHeaders[i+1]]);
    const reply=await subscriptions.handle({bindingId,socket:req.socket,method:req.method,path:req.url,headers,body:Buffer.concat(chunks)});
    need(Buffer.isBuffer(reply.body)&&reply.body.length<=(req.url.includes('/snapshot?')?8388608:262144)&&same(authorized(),initial),'changed');reply.beforeSend();res.writeHead(reply.status,Object.fromEntries(reply.headers));res.end(reply.body);return;
   }
   if(req.url==='/internal/auth/introspect'){
    need(typeof introspection==='function'&&identity.service_kind==='controller'&&req.method==='POST','route');
    const bindingId=req.headers['x-leafseamer-pairing'];
    const authorized=()=>{const record=current(bindingId,req.socket),peer=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
     need(record.state==='activated'&&peer.permissions.includes('auth.introspect'),'purpose');return record;};
    const record=authorized();
    need(req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&/^[1-9][0-9]{0,4}$/.test(req.headers['content-length'])&&Number(req.headers['content-length'])<=16384,'body');
    const parts=[];let size=0;for await(const part of req){size+=part.length;need(size<=16384,'capacity');parts.push(part);}
    need(same(authorized(),record),'changed');
    const headers=[];for(let i=0;i<req.rawHeaders.length;i+=2)headers.push([req.rawHeaders[i],req.rawHeaders[i+1]]);
    const reply=await introspection({bindingId,socket:req.socket,headers,body:Buffer.concat(parts)});
    need(Buffer.isBuffer(reply.body)&&reply.body.length<=16384&&same(authorized(),record),'changed');reply.beforeSend();
    need([200,403,409,503].includes(reply.status),'response');res.writeHead(reply.status,Object.fromEntries(reply.headers));res.end(reply.body);return;
   }
   const events=/^\/internal\/pairings\/([0-9a-f-]{36})\/device-events$/.exec(req.url);
   if(events){
    need(req.method==='POST'&&identity.service_kind==='controller'&&typeof deviceEvents==='function','route');
    const initial=current(events[1],req.socket);need(initial.state==='activated','purpose');
    need(req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&/^[1-9][0-9]{0,4}$/.test(req.headers['content-length'])&&Number(req.headers['content-length'])<=16384,'body');
    const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;need(size<=16384,'capacity');chunks.push(chunk);}
    const request=deviceEventsRequest(decodeDeviceEvents(Buffer.concat(chunks),16384));
    const authorized=()=>{const record=current(events[1],req.socket);need(same(record,initial),'changed');authorizeDeviceEvents(record,request,identity.service_id,record.peer_service_id);return record;};
    const record=authorized(),bundle=deviceEvents(request.device_id,request.expected_source_ref,request.after_sequence,request.limit),reply={format:'leafseamer.device-events-response/1',
     challenge_id:request.challenge_id,controller_id:identity.service_id,seamer_id:record.peer_service_id,transcript_digest:record.transcript_digest,bundle_digest:digest(bundle),bundle};
    deviceEventsReply(reply,request,record,identity.service_id,record.peer_service_id);const bytes=Buffer.from(canonical(reply));need(bytes.length<=deviceEventsLimit,'capacity');
    need(same(deviceEvents(request.device_id,deviceEventSourceRef(bundle.registration),request.after_sequence,request.limit),bundle),'changed');authorized();
    res.writeHead(200,{'Content-Type':'application/json','Content-Length':bytes.length});res.end(bytes);return;
   }
   const bindings=/^\/internal\/pairings\/([0-9a-f-]{36})\/device-bindings$/.exec(req.url);
   if(bindings){
    need(req.method==='POST'&&identity.service_kind==='controller'&&typeof deviceBindings==='function','route');
    const initial=current(bindings[1],req.socket);need(initial.state==='activated','purpose');
    need(req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&/^[1-9][0-9]{0,4}$/.test(req.headers['content-length'])&&Number(req.headers['content-length'])<=16384,'body');
    const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;need(size<=16384,'capacity');chunks.push(chunk);}
    const request=deviceBindingsRequest(decodeDeviceBindings(Buffer.concat(chunks),16384));
    const authorized=()=>{const record=current(bindings[1],req.socket);need(same(record,initial),'changed');authorizeDeviceBindings(record,request,identity.service_id,record.peer_service_id);return record;};
    const record=authorized(),bundle=deviceBindings(request.device_id,request.expected_registration_ref),reply={format:'leafseamer.device-bindings-response/1',
     challenge_id:request.challenge_id,controller_id:identity.service_id,seamer_id:record.peer_service_id,transcript_digest:record.transcript_digest,bundle_digest:digest(bundle),bundle};
    deviceBindingsReply(reply,request,record,identity.service_id,record.peer_service_id);const bytes=Buffer.from(canonical(reply));need(bytes.length<=deviceBindingsLimit,'capacity');
    // 同步提供者在发送前复核原注册与当前运行；远端收到后仍不取得发布或执行许可。
    need(same(deviceBindings(request.device_id,bundle.registration_ref),bundle),'changed');authorized();
    res.writeHead(200,{'Content-Type':'application/json','Content-Length':bytes.length});res.end(bytes);return;
   }
   const denial=/^\/internal\/pairings\/([0-9a-f-]{36})\/session-denials$/.exec(req.url);
   if(denial){
    need(req.method==='POST'&&identity.service_kind==='seamer'&&typeof sessionDenial==='function','route');
    const authorized=()=>{const record=current(denial[1],req.socket),peer=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
     need(record.state==='activated'&&peer.service_kind==='controller'&&peer.permissions.includes('auth.revoke'),'purpose');return record;};
    const record=authorized();need(req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&/^[1-9][0-9]{0,4}$/.test(req.headers['content-length'])&&Number(req.headers['content-length'])<=16384,'body');
    const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;need(size<=16384,'capacity');chunks.push(chunk);}
    need(same(authorized(),record),'changed');const notice=decodeSessionDenial(Buffer.concat(chunks));
    const receipt=sessionDenialReceipt(sessionDenial(denial[1],req.socket,notice),notice),body=Buffer.from(canonical(receipt));
    need(body.length<=16384&&same(authorized(),record),'changed');res.writeHead(200,{'Content-Type':'application/json','Content-Length':body.length});res.end(body);return;
   }
   const match=/^\/internal\/pairings\/([0-9a-f-]{36})\/(status|challenges|proofs)$/.exec(req.url);
   need(match&&(match[2]==='status'?req.method==='GET':req.method==='POST'),'route');
   let input=null;const record=current(match[1],req.socket);
   if(match[2]==='status')need(req.headers['transfer-encoding']===undefined&&(!req.headers['content-length']||req.headers['content-length']==='0'),'body');
   else{
    need(req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&/^[1-9][0-9]{0,4}$/.test(req.headers['content-length'])&&Number(req.headers['content-length'])<=16384,'body');
    const parts=[];let size=0;for await(const part of req){size+=part.length;need(size<=16384,'capacity');parts.push(part);}
    const bytes=Buffer.concat(parts);input=JSON.parse(bytes);need(Buffer.from(canonical(input)).equals(bytes),'body');current(match[1],req.socket);
   }
   const value=match[2]==='status'?{format:'leafseamer.peer-pairing-status/1',pair_attempt_id:record.transcript.pair_attempt_id,
     binding_ref:pairingReference(record),transcript_digest:record.transcript_digest,state:record.state,proof_refs:record.proof_refs,proofs:pairings.peerProofs(match[1],req.socket)}:
    match[2]==='challenges'?pairings.challenge(match[1],req.socket,input):pairings.consumeProof(match[1],req.socket,input);
   const body=Buffer.from(canonical(value));need(body.length<=16384,'capacity');current(match[1],req.socket);
   res.writeHead(200,{'Content-Type':'application/json','Content-Length':body.length});res.end(body);
  }catch{if(!res.headersSent){res.writeHead(403,{'Content-Length':0,Connection:'close'});res.end();}else res.destroy();}
 });
 const websocketServer=subscriptions?.channel?createPeerWebsocketServer({protocol:subscriptions.channel.protocol}):null,websocketClients=new Set();
 server.on('upgrade',(req,socket,head)=>{try{
  need(!closed&&websocketServer&&req.method==='GET'&&req.url==='/internal/events'&&req.headers.authorization===undefined&&req.headers.cookie===undefined&&req.headers.origin===undefined&&req.headers['content-length']===undefined&&req.headers['transfer-encoding']===undefined,'route');
  const binding=req.headers['x-leafseamer-pairing'],initial=current(binding,socket),party=initial.transcript.parties.find(p=>p.service_id===initial.peer_service_id);need(initial.state==='activated'&&party.permissions.includes('event.internal.subscribe'),'purpose');
  const headers=[];for(let i=0;i<req.rawHeaders.length;i+=2)headers.push([req.rawHeaders[i],req.rawHeaders[i+1]]);subscriptions.channel.prepare(headers);
  websocketServer.accept(req,socket,head,{open:()=>subscriptions.channel.open(binding,socket),stable:()=>need(same(current(binding,socket),initial),'changed')});
 }catch{socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');}});
 server.maxConnections=16;server.maxRequestsPerSocket=32;server.on('tlsClientError',()=>{});server.on('clientError',(_error,socket)=>socket.destroy());
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});
 const address=server.address(),origin='https://'+(isIP(host)===6?'['+host+']':host)+':'+address.port,localEndpoint=endpoint(origin,serverName);
 const describe=(value,pem,ep,trust=trustDigest)=>({...value,...pairingCertificate(pem),trust_bundle_digest:trust,endpoint_config_digest:digest(ep)});
 const localConfiguration=describe(identity,cert,localEndpoint);
 async function remote(bindingId,operation,body=null,received=value=>value){
  need(!closed&&peers,'configuration_missing');const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);need(peer,'peer');
  const target=record.transcript.parties.find(p=>p.service_id===peer.identity.service_id),bytes=body===null?null:Buffer.from(canonical(body));
  if(operation==='session-denials'){
   sessionDenialNotice(body);const localParty=record.transcript.parties.find(p=>p.service_id===identity.service_id);
   need(record.state==='activated'&&identity.service_kind==='controller'&&target.service_kind==='seamer'&&localParty.permissions.includes('auth.revoke')&&bytes.length<=16384,'purpose');
  }
  return new Promise((resolve,reject)=>{
   const request=https.request(peer.origin+'/internal/pairings/'+target.binding_id+'/'+operation,{method:bytes?'POST':'GET',agent:false,key,cert,ca:roots.map(root=>root.toString()),
    headers:bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{},servername:isIP(peer.server_name)?undefined:peer.server_name,
    minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true,timeout:5000},response=>{
    try{validate(response.socket,peer);need(response.statusCode===200&&response.headers['content-type']==='application/json','response');}catch(error){response.destroy();reject(error);return;}
    const socket=response.socket,chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>16384)response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});
    response.on('error',reject);response.on('end',()=>{try{validate(socket,peer);need(pairings.currentPending(bindingId).transcript_digest===record.transcript_digest,'changed');
     const bytes=Buffer.concat(chunks),value=JSON.parse(bytes);need(Buffer.from(canonical(value)).equals(bytes),'response');
     if(operation==='session-denials'){need(same(pairings.currentPending(bindingId),record),'changed');sessionDenialReceipt(value,body);}
     else need(value.pair_attempt_id===record.transcript.pair_attempt_id&&value.transcript_digest===record.transcript_digest,'response_binding');
     if(operation==='status')need(value.format==='leafseamer.peer-pairing-status/1'&&value.binding_ref?.id===target.binding_id&&Array.isArray(value.proofs)&&value.proofs.length<=2,'response_binding');
     resolve(received(value,socket));
    }catch(error){reject(error);}});
   });request.on('error',reject);request.on('timeout',()=>request.destroy(new Error('peer_pairing_timeout')));
   if(operation==='session-denials'){
    const timer=setTimeout(()=>request.destroy(new Error('peer_pairing_timeout')),5000);request.on('close',()=>clearTimeout(timer));
    request.on('socket',socket=>socket.once('secureConnect',()=>{try{need(same(current(bindingId,socket),record),'changed');request.end(bytes);}catch(error){request.destroy(error);}}));
   }else request.end(bytes);
  });
 }
 let delivery=null,stopping=null;
 const subscriptionMonitor=subscriptions?setInterval(()=>{try{subscriptions.sweep();websocketServer?.sweep();}catch{websocketServer?.sweep();}},250):null;subscriptionMonitor?.unref();
 const api=Object.freeze({origin,configuration:structuredClone(localConfiguration),
  bindPeers(values){need(!peers&&Array.isArray(values)&&values.length<=64,'configuration');const next=values.map(p=>{
   const x=certificate(p.cert),ep=endpoint(p.origin,p.server_name);name(x,ep.server_name);need(roots.some(root=>x.checkIssued(root)&&x.verify(root.publicKey))&&/^sha256:[0-9a-f]{64}$/.test(p.trust_bundle_digest),'certificate_chain');
   return {...structuredClone(p),...ep};});
   need(new Set([localConfiguration.spki_sha256,...next.map(p=>pairingCertificate(p.cert).spki_sha256)]).size===next.length+1,'certificate_service_alias');
   need(!closed,'closed');pairings.bindConfiguration({local:localConfiguration,peers:next.map(p=>describe(p.identity,p.cert,endpoint(p.origin,p.server_name),p.trust_bundle_digest))});peers=next;
   if(sessionDenials)delivery=startSessionDenialDelivery({store:sessionDenials,transport:api});
  },
  sessionDenialStatus:()=>delivery?.status()??null,
  status:bindingId=>remote(bindingId,'status'),
  deliverSessionDenial:(bindingId,notice)=>remote(bindingId,'session-denials',notice),
  async openSubscriptionChannel(bindingId,{protocol,onFrame,onClose}){
   need(!closed&&peers&&identity.service_kind==='seamer'&&websocketClients.size<8,'subscription_request');const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id),local=record.transcript.parties.find(p=>p.service_id===identity.service_id),target=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
   need(peer&&record.state==='activated'&&local.permissions.includes('event.internal.subscribe'),'purpose');const stable=(socket,inside=false)=>{need(!closed,'closed');validate(socket,peer);need(same(current(bindingId,socket,inside?{id:record.binding_id,revision:record.revision,digest:record.digest}:null),record),'changed');};
   const abort=new AbortController(),pending={close:()=>abort.abort()};websocketClients.add(pending);let channel;
   const opening=openPeerWebsocket(peer.origin.replace('https:','wss:')+'/internal/events',protocol,{agent:false,signal:abort.signal,key,cert,ca:roots.map(root=>root.toString()),headers:{'X-LeafSeamer-Pairing':target.binding_id},servername:isIP(peer.server_name)?undefined:peer.server_name,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true},{stable,onFrame,onClose:error=>{websocketClients.delete(channel);onClose?.(error);}});
   pending.finished=opening.catch(()=>{});try{channel=await opening;}finally{websocketClients.delete(pending);}
   if(closed){channel.close();throw Error('peer_pairing_closed');}websocketClients.add(channel);return channel;
  },
  requestSubscription(bindingId,{method,path,headers,body}){
   need(!closed&&peers&&identity.service_kind==='seamer'&&['POST','GET','DELETE'].includes(method)&&/^\/internal\/subscriptions(?:\/[A-Za-z0-9_-]{1,128}(?:(?:\/snapshot|\/snapshots\/[A-Za-z0-9_-]{1,128}\/pages\/[0-9]{1,3})\?expected_connection_generation=[0-9]{1,20}|\/snapshot-context|\/connections\/[A-Za-z0-9_-]{1,128}|\?expected_revision=[0-9]{1,20})?)?$/.test(path)&&Buffer.isBuffer(body)&&body.length<=16384,'subscription_request');
   const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id),local=record.transcript.parties.find(p=>p.service_id===identity.service_id),target=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
   need(peer&&record.state==='activated'&&local.permissions.includes('event.internal.subscribe'),'purpose');
   const stable=socket=>{validate(socket,peer);need(same(current(bindingId,socket),record),'changed');};
   return new Promise((resolve,reject)=>{let timer;const done=(error,value)=>{clearTimeout(timer);error?reject(error):resolve(value);};
    const outgoing=https.request(peer.origin+path,{method,agent:false,key,cert,ca:roots.map(root=>root.toString()),headers:{...Object.fromEntries(headers),'X-LeafSeamer-Pairing':target.binding_id},servername:isIP(peer.server_name)?undefined:peer.server_name,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true},response=>{
     const socket=response.socket;try{stable(socket);need(response.headers['cache-control']==='no-store','response');}catch(error){response.destroy();done(error);return;}
     const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>(path.includes('/snapshot?')?8388608:262144))response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});response.on('error',done);
     response.on('end',()=>{try{stable(socket);const headers=[];for(let i=0;i<response.rawHeaders.length;i+=2)headers.push([response.rawHeaders[i],response.rawHeaders[i+1]]);done(null,{status:response.statusCode,headers,body:Buffer.concat(chunks)});}catch(error){done(error);}});
    });timer=setTimeout(()=>outgoing.destroy(new Error('peer_pairing_timeout')),5000);outgoing.on('error',done);outgoing.on('socket',socket=>socket.once('secureConnect',()=>{try{stable(socket);outgoing.end(body);}catch(error){outgoing.destroy(error);}}));
   });
  },
  readDeviceEvents(bindingId,input){
   const request=deviceEventsRequest(structuredClone(input));need(!closed&&peers&&identity.service_kind==='seamer','configuration_missing');
   const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);
   const target=authorizeDeviceEvents(record,request,record.peer_service_id,identity.service_id);need(peer,'peer');
   const bytes=Buffer.from(canonical(request));need(bytes.length<=16384,'capacity');
   const stable=socket=>{validate(socket,peer);need(same(current(bindingId,socket),record),'changed');};
   return new Promise((resolve,reject)=>{
    let timer;const done=(error,value)=>{clearTimeout(timer);error?reject(error):resolve(value);};
    const outgoing=https.request(peer.origin+'/internal/pairings/'+target.binding_id+'/device-events',{method:'POST',agent:false,key,cert,ca:roots.map(root=>root.toString()),
     headers:{'Content-Type':'application/json','Content-Length':bytes.length},servername:isIP(peer.server_name)?undefined:peer.server_name,
     minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true},response=>{
     const socket=response.socket;try{stable(socket);need(response.statusCode===200&&response.headers['content-type']==='application/json'&&response.headers['cache-control']==='no-store','response');}catch(error){response.destroy();done(error);return;}
     const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>deviceEventsLimit)response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});
     response.on('error',error=>done(error));response.on('end',()=>{try{stable(socket);done(null,deviceEventsReply(decodeDeviceEvents(Buffer.concat(chunks)),request,record,record.peer_service_id,identity.service_id));}catch(error){done(error);}});
    });
    timer=setTimeout(()=>outgoing.destroy(new Error('peer_pairing_timeout')),5000);outgoing.on('error',error=>done(error));
    outgoing.on('socket',socket=>socket.once('secureConnect',()=>{try{stable(socket);outgoing.end(bytes);}catch(error){outgoing.destroy(error);}}));
   });
  },
  readDeviceBindings(bindingId,input){
   const request=deviceBindingsRequest(structuredClone(input));need(!closed&&peers&&identity.service_kind==='seamer','configuration_missing');
   const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);
   const target=authorizeDeviceBindings(record,request,record.peer_service_id,identity.service_id);need(peer,'peer');
   const bytes=Buffer.from(canonical(request));need(bytes.length<=16384,'capacity');
   const stable=socket=>{validate(socket,peer);need(same(current(bindingId,socket),record),'changed');};
   return new Promise((resolve,reject)=>{
    let timer;const done=(error,value)=>{clearTimeout(timer);error?reject(error):resolve(value);};
    const outgoing=https.request(peer.origin+'/internal/pairings/'+target.binding_id+'/device-bindings',{method:'POST',agent:false,key,cert,ca:roots.map(root=>root.toString()),
     headers:{'Content-Type':'application/json','Content-Length':bytes.length},servername:isIP(peer.server_name)?undefined:peer.server_name,
     minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true},response=>{
     const socket=response.socket;try{stable(socket);need(response.statusCode===200&&response.headers['content-type']==='application/json','response');}catch(error){response.destroy();done(error);return;}
     const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>deviceBindingsLimit)response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});
     response.on('error',error=>done(error));response.on('end',()=>{try{stable(socket);done(null,deviceBindingsReply(decodeDeviceBindings(Buffer.concat(chunks)),request,record,record.peer_service_id,identity.service_id));}catch(error){done(error);}});
    });
    timer=setTimeout(()=>outgoing.destroy(new Error('peer_pairing_timeout')),5000);outgoing.on('error',error=>done(error));
    outgoing.on('socket',socket=>socket.once('secureConnect',()=>{try{stable(socket);outgoing.end(bytes);}catch(error){outgoing.destroy(error);}}));
   });
  },
  exchangeIntrospection(bindingId,packet){
   need(packet?.authority==='controller'&&packet.method==='POST'&&packet.target==='/internal/auth/introspect','route');
   need(!closed&&peers,'configuration_missing');const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);
   const localParty=record.transcript.parties.find(p=>p.service_id===identity.service_id),target=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
   need(peer&&record.state==='activated'&&localParty.permissions.includes('auth.introspect'),'purpose');
   const headers=structuredClone(packet.headers),selected=headers.filter(([name])=>name.toLowerCase()==='x-leafseamer-pairing');
   need(selected.length===1&&selected[0][1]===target.binding_id,'binding');const bytes=Buffer.from(packet.body);need(bytes.length<=16384,'capacity');
   const stable=socket=>{validate(socket,peer);need(same(pairings.currentPending(bindingId),record),'changed');};
   return new Promise((resolve,reject)=>{
    let timer;const done=(error,value)=>{clearTimeout(timer);error?reject(error):resolve(value);};
    const request=https.request(peer.origin+'/internal/auth/introspect',{method:'POST',agent:false,key,cert,ca:roots.map(root=>root.toString()),
     headers:{...Object.fromEntries(headers),'content-length':bytes.length},servername:isIP(peer.server_name)?undefined:peer.server_name,
     minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true},response=>{
     const socket=response.socket;try{stable(socket);}catch(error){response.destroy();done(error);return;}
     const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>16384)response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});
     response.on('error',error=>done(error));response.on('end',()=>{try{
      stable(socket);const responseHeaders=[];for(let i=0;i<response.rawHeaders.length;i+=2)responseHeaders.push([response.rawHeaders[i],response.rawHeaders[i+1]]);
      done(null,{status:String(response.statusCode),headers:responseHeaders,body:Buffer.concat(chunks)});
     }catch(error){done(error);}});
    });
    timer=setTimeout(()=>request.destroy(new Error('peer_pairing_timeout')),5000);
    request.on('error',error=>done(error));
    // 秘密正文只在平台TLS验证和固定对端证书核对完成后发送。
    request.on('socket',socket=>socket.once('secureConnect',()=>{try{stable(socket);request.end(bytes);}catch(error){request.destroy(error);}}));
   });
  },
  async prove(bindingId){
   const existing=await remote(bindingId,'status',null,(value,socket)=>{const proof=value.proofs.find(p=>p.direction==='inbound');return proof?pairings.recordOutbound(bindingId,socket,proof):null;});
   if(existing)return existing;
   const value=pairings.currentPending(bindingId),identity={pair_attempt_id:value.transcript.pair_attempt_id,transcript_digest:value.transcript_digest};
   const challenge=await remote(bindingId,'challenges',identity);
   need(challenge.format==='leafseamer.peer-pairing-challenge/1'&&typeof challenge.challenge==='string'&&typeof challenge.challenge_id==='string','response_binding');
   return remote(bindingId,'proofs',{...identity,challenge_id:challenge.challenge_id,challenge:challenge.challenge},(proof,socket)=>pairings.recordOutbound(bindingId,socket,proof));
  },
  close(){if(!stopping){closed=true;clearInterval(subscriptionMonitor);const clientDrains=[...websocketClients].map(channel=>channel.finished);for(const channel of websocketClients)channel.close();const drained=delivery?.close();stopping=Promise.all([...clientDrains,drained,websocketServer?.close(),new Promise((resolve,reject)=>{server.close(error=>error?reject(error):resolve());server.closeAllConnections();})]).then(()=>{});}return stopping;}
 });
 return api;
}
