import https from 'node:https';
import crypto from 'node:crypto';
import {TLSSocket} from 'node:tls';
import {isIP} from 'node:net';
import {digest, same,canonical} from './auth-clock-value.mjs';
import {pairingNeed as need,pairingCertificate,pairingReference} from './peer-pairing-value.mjs';
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

// 独立内部监听。它只交付具名配对状态，不代理普通HTTP，不开放时钟、令牌或设备接口。
export async function startPeerPairingTransport({pairings,clock,identity,cert,key,ca,host='127.0.0.1',port=0,serverName=host}){
 need(['127.0.0.1','::1'].includes(host)&&Number.isInteger(port)&&port>=0&&port<=65535,'listen');
 need(pairings&&typeof clock?.pairingSample==='function','configuration');
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
 const current=(bindingId,socket)=>{need(!closed&&peers,'configuration_missing');const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);
  need(peer,'peer');validate(socket,peer);const party=record.transcript.parties.find(p=>p.service_id===peer.identity.service_id);
  need(same(pairingCertificate(socket.getPeerX509Certificate().raw),{certificate_der_sha256:party.certificate_der_sha256,spki_sha256:party.spki_sha256}),'certificate_binding');return record;};
 const server=https.createServer({key,cert,ca:roots.map(root=>root.toString()),requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',
  secureOptions:crypto.constants.SSL_OP_NO_TICKET,maxHeaderSize:8192,requestTimeout:5000,headersTimeout:5000,handshakeTimeout:5000,keepAliveTimeout:1000},async(req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  try{
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
 server.maxConnections=16;server.maxRequestsPerSocket=32;server.on('tlsClientError',()=>{});server.on('clientError',(_error,socket)=>socket.destroy());
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});
 const address=server.address(),origin='https://'+(isIP(host)===6?'['+host+']':host)+':'+address.port,localEndpoint=endpoint(origin,serverName);
 const describe=(value,pem,ep,trust=trustDigest)=>({...value,...pairingCertificate(pem),trust_bundle_digest:trust,endpoint_config_digest:digest(ep)});
 const localConfiguration=describe(identity,cert,localEndpoint);
 async function remote(bindingId,operation,body=null,received=value=>value){
  need(!closed&&peers,'configuration_missing');const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);need(peer,'peer');
  const target=record.transcript.parties.find(p=>p.service_id===peer.identity.service_id),bytes=body===null?null:Buffer.from(canonical(body));
  return new Promise((resolve,reject)=>{
   const request=https.request(peer.origin+'/internal/pairings/'+target.binding_id+'/'+operation,{method:bytes?'POST':'GET',agent:false,key,cert,ca:roots.map(root=>root.toString()),
    headers:bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{},servername:isIP(peer.server_name)?undefined:peer.server_name,
    minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true,timeout:5000},response=>{
    try{validate(response.socket,peer);need(response.statusCode===200&&response.headers['content-type']==='application/json','response');}catch(error){response.destroy();reject(error);return;}
    const socket=response.socket,chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>16384)response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});
    response.on('error',reject);response.on('end',()=>{try{validate(socket,peer);need(pairings.currentPending(bindingId).transcript_digest===record.transcript_digest,'changed');
     const bytes=Buffer.concat(chunks),value=JSON.parse(bytes);need(Buffer.from(canonical(value)).equals(bytes),'response');
     need(value.pair_attempt_id===record.transcript.pair_attempt_id&&value.transcript_digest===record.transcript_digest,'response_binding');
     if(operation==='status')need(value.format==='leafseamer.peer-pairing-status/1'&&value.binding_ref?.id===target.binding_id&&Array.isArray(value.proofs)&&value.proofs.length<=2,'response_binding');
     resolve(received(value,socket));
    }catch(error){reject(error);}});
   });request.on('error',reject);request.on('timeout',()=>request.destroy(new Error('peer_pairing_timeout')));request.end(bytes);
  });
 }
 return Object.freeze({origin,configuration:structuredClone(localConfiguration),
  bindPeers(values){need(!peers&&Array.isArray(values)&&values.length<=64,'configuration');const next=values.map(p=>{
   const x=certificate(p.cert),ep=endpoint(p.origin,p.server_name);name(x,ep.server_name);need(roots.some(root=>x.checkIssued(root)&&x.verify(root.publicKey))&&/^sha256:[0-9a-f]{64}$/.test(p.trust_bundle_digest),'certificate_chain');
   return {...structuredClone(p),...ep};});
   need(new Set([localConfiguration.spki_sha256,...next.map(p=>pairingCertificate(p.cert).spki_sha256)]).size===next.length+1,'certificate_service_alias');
   pairings.bindConfiguration({local:localConfiguration,peers:next.map(p=>describe(p.identity,p.cert,endpoint(p.origin,p.server_name),p.trust_bundle_digest))});peers=next;
  },
  status:bindingId=>remote(bindingId,'status'),
  async prove(bindingId){
   const existing=await remote(bindingId,'status',null,(value,socket)=>{const proof=value.proofs.find(p=>p.direction==='inbound');return proof?pairings.recordOutbound(bindingId,socket,proof):null;});
   if(existing)return existing;
   const value=pairings.currentPending(bindingId),identity={pair_attempt_id:value.transcript.pair_attempt_id,transcript_digest:value.transcript_digest};
   const challenge=await remote(bindingId,'challenges',identity);
   need(challenge.format==='leafseamer.peer-pairing-challenge/1'&&typeof challenge.challenge==='string'&&typeof challenge.challenge_id==='string','response_binding');
   return remote(bindingId,'proofs',{...identity,challenge_id:challenge.challenge_id,challenge:challenge.challenge},(proof,socket)=>pairings.recordOutbound(bindingId,socket,proof));
  },
  close(){closed=true;return new Promise((resolve,reject)=>{server.close(error=>error?reject(error):resolve());server.closeAllConnections();});}
 });
}
