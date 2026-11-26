import https from 'node:https';
import crypto from 'node:crypto';
import {TLSSocket} from 'node:tls';
import {signFirstPairingAuthorization} from './first-pairing-authorization.mjs';
import {isIP} from 'node:net';
import {digest, same,canonical} from './auth-clock-value.mjs';
import {pairingNeed as need,pairingCertificate,pairingReference,pairingUuid} from './peer-pairing-value.mjs';
import {decodeSessionDenial,sessionDenialNotice,sessionDenialReceipt} from './peer-session-denial.mjs';
import {startSessionDenialDelivery} from './session-denial-delivery.mjs';
import {createPeerWebsocketServer,openPeerWebsocket} from './peer-event-websocket.mjs';
import {authorizeDeviceBindings,deviceBindingsRequest,deviceBindingsReply,decodeDeviceBindings,deviceBindingsLimit} from './peer-device-bindings.mjs';
import {authorizeDeviceEvents,deviceEventsRequest,deviceEventsReply,decodeDeviceEvents,deviceEventsLimit,deviceEventSourceRef} from './peer-device-events.mjs';
import {automationApprovalRequest,automationApprovalReply} from './peer-automation-approval.mjs';
import {peerScope,proposalReference,proposalReadRequest,proposalReadReply,proposalWindowEnd,runProposalResponseLimit} from './peer-run-approval-proposal.mjs';
import {endorsementReference,endorsementReadRequest,endorsementReadReply,endorsementControlReadReply} from './peer-run-approval-endorsement.mjs';
import {runApprovalReference,runApprovalReadRequest,runApprovalReadReply} from './peer-run-approval.mjs';
import {runArmOperationReference,runRecoveryOperationReference,runInitiatorReadRequest,runInitiatorReadReply,runRecoveryInitiatorReadReply} from './peer-run-initiator.mjs';
import {armPlanReference,recoveryPlanReference,armPlanReadRequest,armPlanReadReply,recoveryPlanReadReply,armPreparationRequest} from './peer-run-arm-plan.mjs';
import {armPreparationEligibilityRequest,armPreparationEligibilityReply,armPreparationLookup,armPreparationReply,preparationProtocol,preparationRequestLimit,preparationResponseLimit,
 recoveryPreparationProtocol,runEligibilityObservationMs,runEligibilityObservationNs} from './peer-run-preparation.mjs';
import {actionAdmissionRequest,actionBindingPath,actionBindingReply,actionBindingRequestLimit,actionBindingResponseLimit,
 actionBindingVersion,scheduledActionBindingVersion,recoveryActionBindingVersion} from './peer-action-binding.mjs';
import {automationCommandPaths,automationCommandReply,automationCommandRequest,automationCommandRequestLimit,automationCommandResponseLimit,automationCommandVersion} from './peer-automation-command.mjs';
import {approvalProtectionNotice,runApprovalProtectionReply,runApprovalProtectionVersion,runApprovalProtectionObservation,
 runApprovalProtectionObservationVersion,endorsementRevocationNotice,endorsementRevocationReceipt} from './peer-run-approval-protection.mjs';
const day=86400000000000n,sha=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const runRecordReads={
 'approval-proposals':{owner:'seamer',reader:'controller',name:'run-approval-proposal',header:'x-leafseamer-proposal-digest',
  reference:proposalReference,request:(id,version,hash,challenge)=>proposalReadRequest(id,hash,challenge),decode:proposalReadReply,
  deadline:value=>proposalWindowEnd(value.proposal),timeout:'proposal_expired'},
 'run-approval-endorsements':{owner:'controller',reader:'seamer',name:'run-approval-endorsement',header:'x-leafseamer-endorsement-digest',
  reference:endorsementReference,request:(id,version,hash,challenge)=>endorsementReadRequest(id,hash,challenge),decode:endorsementReadReply,
  deadline:value=>value.eligible_before_ns,timeout:'endorsement_expired'},
 'run-approval-control-observations':{owner:'controller',reader:'seamer',name:'run-approval-control-observation',header:'x-leafseamer-endorsement-digest',
  reference:endorsementReference,request:(id,version,hash,challenge)=>endorsementReadRequest(id,hash,challenge),decode:endorsementControlReadReply,
  deadline:value=>value.endorsement_read.eligible_before_ns,timeout:'endorsement_expired'},
 'run-operations':{owner:'seamer',reader:'controller',name:'run-initiator',header:'x-leafseamer-operation-digest',
  reference:runArmOperationReference,request:(id,version,hash,challenge)=>runInitiatorReadRequest(id,hash,challenge),decode:runInitiatorReadReply,
  deadline:value=>value.eligible_before_ns,timeout:'run_initiator_expired'},
 'arm-plans':{owner:'seamer',reader:'controller',name:'run-arm-plan',header:'x-leafseamer-plan-digest',
  reference:armPlanReference,request:(id,version,hash,challenge)=>armPlanReadRequest(id,hash,challenge),decode:armPlanReadReply,prepared:true,
  deadline:value=>value.eligible_before_ns,timeout:'preparation_expired'},
 'recovery-operations':{owner:'seamer',reader:'controller',name:'run-recovery-initiator',header:'x-leafseamer-operation-digest',
  reference:runRecoveryOperationReference,request:(id,version,hash,challenge)=>runInitiatorReadRequest(id,hash,challenge),decode:runRecoveryInitiatorReadReply,
  deadline:value=>value.eligible_before_ns,timeout:'run_initiator_expired'},
 'recovery-plans':{owner:'seamer',reader:'controller',name:'run-recovery-plan',header:'x-leafseamer-plan-digest',
  reference:recoveryPlanReference,request:(id,version,hash,challenge)=>armPlanReadRequest(id,hash,challenge),decode:recoveryPlanReadReply,prepared:true,
  deadline:value=>value.eligible_before_ns,timeout:'preparation_expired'},
 'run-approvals':{owner:'seamer',reader:'controller',name:'run-approval',header:'x-leafseamer-approval-digest',
  reference:runApprovalReference,request:runApprovalReadRequest,decode:runApprovalReadReply,versioned:true,
  deadline:value=>value.eligible_before_ns,timeout:'approval_expired'}
};
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
function unicast(host){
 const version=isIP(host);
 if(version===4){const first=Number(host.split('.')[0]);return first>0&&first<224;}
 if(version!==6||host.includes('%'))return false;
 const name=new URL('https://['+host+']').hostname;
 return name!=='[::]'&&!name.startsWith('[ff')&&!name.startsWith('[::ffff:');
}

// 独立内部监听。pending只交付具名配对状态；普通核验另需显式处理器、active及用途授权。
export async function startPeerPairingTransport({pairings,clock,identity,cert,key,ca,host='127.0.0.1',port=0,serverName=host,network=false,introspection=null,sessionDenial=null,sessionDenials=null,deviceBindings=null,deviceEvents=null,subscriptions=null,automationApproval=null,runProposal=null,runEndorsement=null,runControlObservation=null,runApproval=null,runInitiator=null,runArmPlan=null,runRecoveryInitiator=null,runRecoveryPlan=null,runPreparations=null,runActionBinding=null,automationCommands=null,runApprovalProtection=null,runEndorsementRevocation=null,eventAge=null}){
 need(typeof network==='boolean'&&(['127.0.0.1','::1'].includes(host)||network&&unicast(host))&&Number.isInteger(port)&&port>=0&&port<=65535,'listen');
 need(pairings&&typeof clock?.pairingSample==='function','configuration');
 need(sessionDenials===null||(identity.service_kind==='controller'&&typeof sessionDenials.scan==='function'&&typeof sessionDenials.deliverPending==='function'),'session_denial_delivery');
 const local=certificate(cert),roots=(Array.isArray(ca)?ca:[ca]).map(pem=>certificate(pem,true)),privateKey=crypto.createPrivateKey(key);
 need(roots.length>0&&roots.length<=8&&roots.some(root=>local.checkIssued(root)&&local.verify(root.publicKey))&&local.checkPrivateKey(privateKey),'certificate_chain');name(local,serverName);
 const localRoot=roots.find(root=>local.checkIssued(root)&&local.verify(root.publicKey));
 const trustDigest=digest(roots.map(root=>sha(root.raw)).sort());let peers=null,closed=false,authority;
 const checkTarget=req=>need(!network||req.headers.host===authority&&req.headers.forwarded===undefined&&
  !Object.keys(req.headers).some(header=>header.startsWith('x-forwarded-')),'endpoint');
 const validate=(socket,peer)=>{
  need(socket instanceof TLSSocket&&socket.encrypted&&socket.authorized&&socket.getProtocol()==='TLSv1.3'&&!socket.isSessionReused(),'tls');
  const remote=socket.getPeerX509Certificate();need(remote&&same(pairingCertificate(remote.raw),pairingCertificate(peer.cert)),'certificate_binding');
  const checked=certificate(remote.raw);name(checked,peer.server_name);inTime(checked,clock);inTime(local,clock);inTime(localRoot,clock);
  const issuer=roots.find(root=>checked.checkIssued(root)&&checked.verify(root.publicKey));need(issuer,'certificate_chain');inTime(issuer,clock);
 };
 const current=(bindingId,socket,reference=null)=>{need(!closed&&peers,'configuration_missing');const record=reference?pairings.requireActivatedInTransaction(reference):pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);
  need(peer,'peer');validate(socket,peer);const party=record.transcript.parties.find(p=>p.service_id===peer.identity.service_id);
  need(same(pairingCertificate(socket.getPeerX509Certificate().raw),{certificate_der_sha256:party.certificate_der_sha256,spki_sha256:party.spki_sha256}),'certificate_binding');return record;};
 const readRunRecord={'approval-proposals':runProposal,'run-approval-endorsements':runEndorsement,'run-approval-control-observations':runControlObservation,
  'run-approvals':runApproval,'run-operations':runInitiator,'arm-plans':runArmPlan,'recovery-operations':runRecoveryInitiator,'recovery-plans':runRecoveryPlan};
 const server=https.createServer({key,cert,ca:roots.map(root=>root.toString()),requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',
  secureOptions:crypto.constants.SSL_OP_NO_TICKET,maxHeaderSize:8192,requestTimeout:5000,headersTimeout:5000,handshakeTimeout:5000,keepAliveTimeout:1000},async(req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  let sourceTimeSelection=null;
  try{
   checkTarget(req);
   const actionRead=req.url===actionBindingPath;
   const commandOperation=Object.keys(automationCommandPaths).find(operation=>req.url===automationCommandPaths[operation]);
   if(actionRead||commandOperation){
    const recoveryAction=actionRead&&req.headers['x-leafseamer-action-binding-version']===recoveryActionBindingVersion;
    const version=actionRead?(recoveryAction?recoveryActionBindingVersion:actionBindingVersion):automationCommandVersion;
    const versionHeader=actionRead?'x-leafseamer-action-binding-version':'x-leafseamer-automation-command-version';
    const handler=actionRead?runActionBinding:automationCommands?.[commandOperation];
    need(req.method==='POST'&&identity.service_kind===(actionRead?'seamer':'controller')&&typeof handler==='function'&&
     req.headers[versionHeader]===version&&req.headers.authorization===undefined&&
     req.headers.cookie===undefined&&req.headers.origin===undefined,'route');
    const bindingId=req.headers['x-leafseamer-pairing'],challenge=req.headers['x-leafseamer-challenge'];pairingUuid(challenge);
    const record=current(bindingId,req.socket),peer=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
    need(record.state==='activated'&&peer?.service_kind===(actionRead?'controller':'seamer')&&peer.permissions.includes('automation.prepare.read')&&
     (commandOperation!=='submit'||peer.permissions.includes('automation.prepare'))&&
     (commandOperation!=='reject'||peer.permissions.includes('automation.protect')),'purpose');
    const length=Number(req.headers['content-length']);
    const limit=actionRead?actionBindingRequestLimit:automationCommandRequestLimit;
    need(req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&
     /^[1-9][0-9]{0,3}$/.test(req.headers['content-length'])&&length<=limit,'body');
    const chunks=[];let size=0;
    for await(const chunk of req){size+=chunk.length;need(size<=length,'capacity');chunks.push(chunk);}
    need(size===length&&same(current(bindingId,req.socket),record),'changed');
    const encoded=Buffer.concat(chunks),parsed=decodeDeviceBindings(encoded,limit);
    const input=actionRead?actionAdmissionRequest(parsed,peerScope(peer)):automationCommandRequest(parsed,peerScope(identity));
    if(actionRead)need(recoveryAction===(input.execution_ref.revision==='2'),'action_reference');
    need(Buffer.from(canonical(input)).equals(encoded)&&same((actionRead?input:input.action).preparation.lookup.origin_scope,
     peerScope(actionRead?identity:peer)),'action_reference');
    let observation;
    try{observation=await handler(bindingId,req.socket,input);}
    catch(error){
     if(!commandOperation||error?.code!=='peer_pairing_automation_command_conflict')throw error;
     need(same(current(bindingId,req.socket),record),'changed');res.writeHead(409,{'Content-Length':0});res.end();return;
    }
    const commandRead=commandOperation==='lookup'||commandOperation==='result'||commandOperation==='resource';
    const body=actionRead?observation.body:commandRead?observation:observation.adjudication;
    const reply={version:actionRead&&body.execution?.origin_kind==='schedule'?scheduledActionBindingVersion:version,
     challenge_id:challenge,pair_attempt_id:record.transcript.pair_attempt_id,
     transcript_digest:record.transcript_digest,body};
    if(actionRead)actionBindingReply(reply,input,record,challenge);
    else automationCommandReply(reply,input,record,challenge,commandOperation);
    const response=Buffer.from(canonical(reply));
    need(response.length<=(actionRead?actionBindingResponseLimit:automationCommandResponseLimit)&&same(current(bindingId,req.socket),record),'changed');
    if(actionRead)need(same(observation.beforeSend(),body),'changed');
    else{
     const current=automationCommands[commandRead?commandOperation:'lookup'](bindingId,req.socket,input);
     need(same(commandRead?current:current.adjudication,body),'changed');
    }
    res.writeHead(commandOperation==='submit'&&observation.created?202:200,
     {'Content-Type':'application/json','Content-Length':response.length,[versionHeader]:version});
    res.end(response);return;
   }
   const eventTime=/^\/internal\/(events\/age-evidence|events\/source-times|reference-time\/bundles)\/([A-Za-z0-9._:-]{1,128})\/([1-9][0-9]{0,19})\?digest=sha256(?::|%3[Aa])([0-9a-f]{64})$/.exec(req.url);
   if(eventTime){
    const [,kind,id,revision,hash]=eventTime,age=kind==='events/age-evidence',bundle=kind==='reference-time/bundles';
    const handler=age?eventAge:bundle?subscriptions?.referenceBundle:subscriptions?.sourceTime;
    need(req.method==='GET'&&identity.service_kind===(age?'seamer':'controller')&&typeof handler?.read==='function'&&
     req.headers.authorization===undefined&&req.headers.cookie===undefined&&req.headers.origin===undefined&&
     req.headers['content-length']===undefined&&req.headers['transfer-encoding']===undefined,'route');
    const {contract_id,contract_digest}=handler.selection;
    need(req.headers['x-leafseamer-contract']===contract_id&&req.headers['x-leafseamer-contract-digest']===contract_digest,'contract');
    if(!age)sourceTimeSelection=handler.selection;
    const bindingId=req.headers['x-leafseamer-pairing'],record=current(bindingId,req.socket);
    const peer=record.transcript.parties.find(item=>item.service_id===record.peer_service_id);
    need(record.state==='activated'&&peer?.service_kind===(age?'controller':'seamer')&&peer.permissions.includes(bundle?'clock.internal.read':'events.internal.read'),'purpose');
    const reference={id,revision,digest:`sha256:${hash}`};
    const value=bundle?handler.read(reference,bindingId,req.socket):handler.read(reference,peer,bindingId,req.socket);
    need(value&&(bundle?value.bundle_id===id&&value.bundle_digest===reference.digest:value.id===id&&value.digest===reference.digest)&&value.revision===revision,'event_time_reference');
    const body=Buffer.from(canonical(bundle?{contract:'reference-time-service/0.1.0-draft.1',request_id:crypto.randomUUID(),
     service_id:identity.service_id,service_boot_id:handler.serviceBootId,data:value}:value));
    need(body.length<=(bundle?65536:16384)&&same(current(bindingId,req.socket),record),'changed');
    res.writeHead(200,{'Content-Type':'application/json','Content-Length':body.length,'X-LeafSeamer-Contract':contract_id,
     'X-LeafSeamer-Contract-Digest':contract_digest});res.end(body);return;
   }
   if(/^\/internal\/automation\/preparations(?:\/lookup|\/eligibility)?$/.test(req.url)){
    const lookup=req.url.endsWith('/lookup'),eligibility=req.url.endsWith('/eligibility');
    const version=req.headers['x-leafseamer-preparation-version'],recovery=version===recoveryPreparationProtocol;
    const handle=eligibility?runPreparations?.prepareEligibility:lookup?runPreparations?.lookup:runPreparations?.prepare;
    const bindingId=req.headers['x-leafseamer-pairing'],challenge=req.headers['x-leafseamer-challenge'];pairingUuid(challenge);
    need(req.method==='POST'&&identity.service_kind==='controller'&&typeof handle==='function'&&
     (recovery||version===preparationProtocol)&&req.headers.authorization===undefined&&
     req.headers.cookie===undefined&&req.headers.origin===undefined,'route');
    const record=current(bindingId,req.socket),peer=record.transcript.parties.find(part=>part.service_id===record.peer_service_id);
    need(record.state==='activated'&&peer?.service_kind==='seamer'&&peer.permissions.includes('automation.prepare.read'),'purpose');
    const length=req.headers['content-length'];
    need(req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&
     /^[1-9][0-9]{0,6}$/.test(length)&&Number(length)<=preparationRequestLimit,'body');
    const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;need(size<=Number(length),'capacity');chunks.push(chunk);}
    need(size===Number(length)&&same(current(bindingId,req.socket),record),'changed');
    const decode=eligibility?armPreparationEligibilityRequest:lookup?armPreparationLookup:armPreparationRequest;
    const input=decode(decodeDeviceBindings(Buffer.concat(chunks),preparationRequestLimit),peerScope(identity),{allowScheduled:eligibility&&!recovery,recovery});
    need(same((eligibility?input.lookup:input).origin_scope,peerScope(peer)),'preparation_scope');
    let outcome;
    try{outcome=await handle(bindingId,req.socket,input,{recovery});}catch(error){
     if(error?.code!=='peer_pairing_preparation_conflict')throw error;
     need(same(current(bindingId,req.socket),record),'changed');res.writeHead(409,{'Content-Length':0});res.end();return;
    }
    const reply={challenge_id:challenge,pair_attempt_id:record.transcript.pair_attempt_id,transcript_digest:record.transcript_digest,
     body:eligibility?outcome.body:lookup?outcome:outcome.record};
    if(eligibility)armPreparationEligibilityReply(reply,input,record,challenge);
    else armPreparationReply(reply,input,record,challenge,lookup,{recovery});
    const bytes=Buffer.from(canonical(reply));
    need(bytes.length<=preparationResponseLimit&&same(current(bindingId,req.socket),record),'changed');
    if(eligibility)need(same(outcome.beforeSend(),reply.body),'changed');
    res.writeHead(!lookup&&!eligibility&&outcome.created?202:200,{'Content-Type':'application/json','Content-Length':bytes.length,'X-LeafSeamer-Preparation-Version':version});
    res.end(bytes);return;
   }
   const runRead=/^\/internal\/automation\/(approval-proposals|run-approval-endorsements|run-approval-control-observations|run-approvals|run-operations|arm-plans|recovery-operations|recovery-plans)\/([0-9a-f-]{36})(?:\/revisions\/([1-9][0-9]{0,19}))?$/.exec(req.url);
   if(runRead){
    const [,collection,id,revision]=runRead,spec=runRecordReads[collection],read=readRunRecord[collection];
    need(req.method==='GET'&&identity.service_kind===spec.owner&&typeof read==='function'&&Boolean(revision)===Boolean(spec.versioned),'route');
    need(req.headers.authorization===undefined&&req.headers.cookie===undefined&&req.headers.origin===undefined&&
     req.headers['transfer-encoding']===undefined&&[undefined,'0'].includes(req.headers['content-length']),'body');
    const bindingId=req.headers['x-leafseamer-pairing'],record=current(bindingId,req.socket);
    const peer=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
    need(record.state==='activated'&&peer?.service_kind===spec.reader&&peer.permissions.includes('automation.prepare.read'),'purpose');
    const request=spec.request(id,revision,req.headers[spec.header],req.headers['x-leafseamer-challenge']);
    const prepared=spec.prepared?await read(bindingId,req.socket,request):null;
    const body=spec.prepared?prepared.body:read(bindingId,req.socket,request);
    const reply={format:'leafseamer.'+spec.name+'-response/1',challenge_id:request.challenge_id,
     pair_attempt_id:record.transcript.pair_attempt_id,transcript_digest:record.transcript_digest,body};
    spec.decode(reply,request,record,peerScope(identity),peerScope(peer));
    const bytes=Buffer.from(canonical(reply));
    need(bytes.length<=runProposalResponseLimit&&same(current(bindingId,req.socket),record),'changed');
    const verified=spec.prepared?prepared.beforeSend():read(bindingId,req.socket,request);
    need(same(verified,body),'changed');
    res.writeHead(200,{'Content-Type':'application/json','Content-Length':bytes.length});res.end(bytes);return;
   }
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
   const approval=/^\/internal\/pairings\/([0-9a-f-]{36})\/automation-service-approval$/.exec(req.url);
   if(approval){
    need(req.method==='POST'&&identity.service_kind==='controller'&&typeof automationApproval==='function','route');
    need(req.headers.authorization===undefined&&req.headers.cookie===undefined&&req.headers.origin===undefined&&
     req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&/^[1-9][0-9]{0,4}$/.test(req.headers['content-length'])&&
     Number(req.headers['content-length'])<=4096,'body');
    const bindingId=approval[1],initial=current(bindingId,req.socket);
    const authorized=()=>{
     const record=current(bindingId,req.socket),peer=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
     need(same(record,initial)&&record.state==='activated'&&peer?.service_kind==='seamer'&&peer.permissions.includes('automation.prepare.read'),'purpose');
     return record;
    };
    authorized();const chunks=[];let size=0;
    for await(const chunk of req){size+=chunk.length;need(size<=4096,'capacity');chunks.push(chunk);}
    const request=automationApprovalRequest(decodeDeviceBindings(Buffer.concat(chunks),4096));
    const record=authorized(),input={principal:request.principal,approval_ref:request.approval_ref},body=automationApproval(bindingId,req.socket,input);
    const reply={format:'leafseamer.automation-approval-response/1',challenge_id:request.challenge_id,pair_attempt_id:record.transcript.pair_attempt_id,
     transcript_digest:record.transcript_digest,body};
    automationApprovalReply(reply,request,record);const bytes=Buffer.from(canonical(reply));authorized();
    need(same(automationApproval(bindingId,req.socket,input),body),'changed');
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
   const protection=/^\/internal\/automation\/(run-approvals\/([0-9a-f-]{36})\/revoke|run-approval-endorsements\/([0-9a-f-]{36})\/revoked)$/.exec(req.url);
   if(protection){
    const reverse=protection[3]!==undefined,handler=reverse?runEndorsementRevocation:runApprovalProtection;
    const decode=reverse?endorsementRevocationNotice:approvalProtectionNotice,verify=reverse?endorsementRevocationReceipt:runApprovalProtectionReply;
    const version=req.headers['x-leafseamer-protection-version'],completion=!reverse&&version===runApprovalProtectionVersion;
    const observing=!reverse&&version===runApprovalProtectionObservationVersion;
    need(version===undefined||completion||observing,'version');
    const observation=observing?req.headers['x-leafseamer-challenge']:null;
    if(observing)pairingUuid(observation);
    need(req.method==='POST'&&identity.service_kind===(reverse?'seamer':'controller')&&typeof handler==='function'&&
     req.headers.authorization===undefined&&req.headers.cookie===undefined&&req.headers.origin===undefined,'route');
    const bindingId=req.headers['x-leafseamer-pairing'];
    const authorized=()=>{const record=current(bindingId,req.socket),peer=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
     need(record.state==='activated'&&peer?.service_kind===(reverse?'controller':'seamer')&&peer.permissions.includes('automation.protect'),'purpose');return record;};
    const record=authorized();
    need(req.headers['content-type']==='application/json'&&req.headers['transfer-encoding']===undefined&&/^[1-9][0-9]{0,4}$/.test(req.headers['content-length'])&&Number(req.headers['content-length'])<=16384,'body');
    const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;need(size<=16384,'capacity');chunks.push(chunk);}
    const notice=decode(decodeDeviceBindings(Buffer.concat(chunks),16384)),requested=reverse?notice.endorsement_ref.object_id:notice.approval_ref.object_id;
    need(requested===(protection[3]??protection[2])&&same(authorized(),record),'changed');
    const value=await handler(bindingId,req.socket,notice,observing?{observation}:{completion});
    const receipt=observing?runApprovalProtectionObservation(value,notice,observation):verify(value,notice,{completion});
    const bytes=Buffer.from(canonical(receipt));need(bytes.length<=16384&&same(authorized(),record),'changed');
    res.writeHead(observing?200:202,{'Content-Type':'application/json','Content-Length':bytes.length,
     ...(observing&&{'X-LeafSeamer-Protection-Version':version})});res.end(bytes);return;
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
  }catch{
   if(res.headersSent){res.destroy();return;}
   if(sourceTimeSelection){
    const body=Buffer.from(canonical({code:'forbidden',retry_write:false}));
    res.writeHead(403,{'Content-Type':'application/json','Content-Length':body.length,Connection:'close',
     'X-LeafSeamer-Contract':sourceTimeSelection.contract_id,'X-LeafSeamer-Contract-Digest':sourceTimeSelection.contract_digest});
    res.end(body);return;
   }
   res.writeHead(403,{'Content-Length':0,Connection:'close'});res.end();
  }
 });
 const websocketServer=subscriptions?.channel?createPeerWebsocketServer({protocol:subscriptions.channel.protocol}):null,websocketClients=new Set();
 server.on('upgrade',(req,socket,head)=>{try{
  checkTarget(req);
  need(!closed&&websocketServer&&req.method==='GET'&&req.url==='/internal/events'&&req.headers.authorization===undefined&&req.headers.cookie===undefined&&req.headers.origin===undefined&&req.headers['content-length']===undefined&&req.headers['transfer-encoding']===undefined,'route');
  const binding=req.headers['x-leafseamer-pairing'],initial=current(binding,socket),party=initial.transcript.parties.find(p=>p.service_id===initial.peer_service_id);need(initial.state==='activated'&&party.permissions.includes('event.internal.subscribe'),'purpose');
  const headers=[];for(let i=0;i<req.rawHeaders.length;i+=2)headers.push([req.rawHeaders[i],req.rawHeaders[i+1]]);subscriptions.channel.prepare(headers);
  websocketServer.accept(req,socket,head,{open:()=>subscriptions.channel.open(binding,socket),stable:()=>need(same(current(binding,socket),initial),'changed')});
 }catch{socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');}});
 server.maxConnections=16;server.maxRequestsPerSocket=32;server.on('tlsClientError',()=>{});server.on('clientError',(_error,socket)=>socket.destroy());
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});
 const address=server.address(),localUrl=new URL('https://'+(isIP(host)===6?'['+host+']':host)+':'+address.port);
 const origin=localUrl.origin,localEndpoint=endpoint(origin,serverName);authority=localUrl.host;
 const describe=(value,pem,ep,trust=trustDigest)=>({...value,...pairingCertificate(pem),trust_bundle_digest:trust,endpoint_config_digest:digest(ep)});
 const localConfiguration=describe(identity,cert,localEndpoint);
 async function remote(bindingId,operation,body=null,received=value=>value){
  const recovery=operation.startsWith('recovery-preparations');
  if(recovery)operation=operation.slice('recovery-'.length);
  const preparationVersion=recovery?recoveryPreparationProtocol:preparationProtocol;
  need(!closed&&peers,'configuration_missing');const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);need(peer,'peer');
  const target=record.transcript.parties.find(p=>p.service_id===peer.identity.service_id),bytes=body===null?null:Buffer.from(canonical(body));
  const approvalRead=operation==='automation-service-approval';
  const completion=operation==='run-approval-protection-completion',observation=operation==='run-approval-protection-observation',
   reverse=operation==='run-endorsement-revocation',protection=completion||observation||operation==='run-approval-protection'||reverse;
  const lookup=operation==='preparations/lookup',eligibility=operation==='preparations/eligibility';
  const readPreparation=lookup||eligibility,preparation=readPreparation||operation==='preparations';
  const actionRead=operation==='action-bindings';
  const commandOperation=operation.startsWith('automation-commands/')?operation.slice('automation-commands/'.length):null;
  const actionProtocol=actionRead||commandOperation;
  const actionVersion=actionRead?(body.execution_ref?.revision==='2'?recoveryActionBindingVersion:actionBindingVersion):automationCommandVersion;
  const actionVersionHeader=actionRead?'x-leafseamer-action-binding-version':'x-leafseamer-automation-command-version';
  const challenge=preparation||actionProtocol||observation?crypto.randomUUID():null;
  if(actionProtocol){
   const local=record.transcript.parties.find(p=>p.service_id===identity.service_id);
   need(record.state==='activated'&&identity.service_kind===(actionRead?'controller':'seamer')&&
    target?.service_kind===(actionRead?'seamer':'controller')&&local?.permissions.includes('automation.prepare.read')&&
    (commandOperation!=='submit'||local.permissions.includes('automation.prepare'))&&
    (commandOperation!=='reject'||local.permissions.includes('automation.protect')),'purpose');
   if(actionRead)actionAdmissionRequest(body,peerScope(identity));
   else automationCommandRequest(body,peerScope(target));
   need(bytes.length<=(actionRead?actionBindingRequestLimit:automationCommandRequestLimit)&&
    same((actionRead?body:body.action).preparation.lookup.origin_scope,peerScope(actionRead?target:identity)),'action_reference');
  }
  if(preparation){
   const local=record.transcript.parties.find(p=>p.service_id===identity.service_id);
   need(record.state==='activated'&&identity.service_kind==='seamer'&&target.service_kind==='controller'&&
    local?.permissions.includes('automation.prepare.read')&&(readPreparation||local.permissions.includes('automation.prepare')),'purpose');
   const decode=eligibility?armPreparationEligibilityRequest:lookup?armPreparationLookup:armPreparationRequest;
   decode(body,peerScope(target),{allowScheduled:eligibility&&!recovery,recovery});
   need(same((eligibility?body.lookup:body).origin_scope,peerScope(identity))&&bytes.length<=preparationRequestLimit,'preparation_scope');
  }
  if(protection){
   (reverse?endorsementRevocationNotice:approvalProtectionNotice)(body);const local=record.transcript.parties.find(p=>p.service_id===identity.service_id);
   need(record.state==='activated'&&identity.service_kind===(reverse?'controller':'seamer')&&target.service_kind===(reverse?'seamer':'controller')&&
    local.permissions.includes('automation.protect')&&same(body.origin_scope,peerScope(identity))&&same(body.target_scope,peerScope(target))&&bytes.length<=16384,'purpose');
  }
  if(approvalRead){
   automationApprovalRequest(body);const localParty=record.transcript.parties.find(p=>p.service_id===identity.service_id);
   need(record.state==='activated'&&identity.service_kind==='seamer'&&target.service_kind==='controller'&&
    localParty.permissions.includes('automation.prepare.read')&&bytes.length<=4096,'purpose');
  }
  if(operation==='session-denials'){
   sessionDenialNotice(body);const localParty=record.transcript.parties.find(p=>p.service_id===identity.service_id);
   need(record.state==='activated'&&identity.service_kind==='controller'&&target.service_kind==='seamer'&&localParty.permissions.includes('auth.revoke')&&bytes.length<=16384,'purpose');
  }
  return new Promise((resolve,reject)=>{
   let path='/internal/pairings/'+target.binding_id+'/'+operation;
   if(protection)path=reverse?'/internal/automation/run-approval-endorsements/'+body.endorsement_ref.object_id+'/revoked':
    '/internal/automation/run-approvals/'+body.approval_ref.object_id+'/revoke';
   if(preparation)path='/internal/automation/'+operation;
   if(actionRead)path=actionBindingPath;
   if(commandOperation)path=automationCommandPaths[commandOperation];
   const headers=bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{};
   if(protection)headers['X-LeafSeamer-Pairing']=target.binding_id;
   if(completion)headers['X-LeafSeamer-Protection-Version']=runApprovalProtectionVersion;
   if(observation)Object.assign(headers,{'X-LeafSeamer-Protection-Version':runApprovalProtectionObservationVersion,'X-LeafSeamer-Challenge':challenge});
   if(preparation)Object.assign(headers,{'X-LeafSeamer-Pairing':target.binding_id,'X-LeafSeamer-Challenge':challenge,
    'X-LeafSeamer-Preparation-Version':preparationVersion});
   if(actionProtocol)Object.assign(headers,{'X-LeafSeamer-Pairing':target.binding_id,'X-LeafSeamer-Challenge':challenge,
    [actionVersionHeader]:actionVersion});
   const request=https.request(peer.origin+path,{method:bytes?'POST':'GET',agent:false,key,cert,ca:roots.map(root=>root.toString()),
    headers,servername:isIP(peer.server_name)?undefined:peer.server_name,
    minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true,timeout:5000},response=>{
    try{
     validate(response.socket,peer);
     if(actionProtocol){
      need(same(current(bindingId,response.socket),record),'changed');
      if(commandOperation)need(response.statusCode!==409,'automation_command_conflict');
      need(response.headers[actionVersionHeader]===actionVersion,'response');
     }
     if(preparation){need(same(current(bindingId,response.socket),record),'changed');need(response.statusCode!==409,'preparation_conflict');}
     need((response.statusCode===(protection&&!observation?202:200)||preparation&&!readPreparation&&response.statusCode===202||
      commandOperation==='submit'&&response.statusCode===202)&&response.headers['content-type']==='application/json'&&
      (!(approvalRead||protection||preparation||actionProtocol)||response.headers['cache-control']==='no-store')&&
      (!preparation||response.headers['x-leafseamer-preparation-version']===preparationVersion)&&
      (!observation||response.headers['x-leafseamer-protection-version']===runApprovalProtectionObservationVersion),'response');
    }catch(error){response.destroy();reject(error);return;}
    const socket=response.socket,chunks=[],limit=actionRead?actionBindingResponseLimit:commandOperation?automationCommandResponseLimit:
     preparation?preparationResponseLimit:16384;let size=0;
    response.on('data',chunk=>{size+=chunk.length;if(size>limit)response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});
    response.on('error',reject);response.on('end',()=>{try{validate(socket,peer);need(pairings.currentPending(bindingId).transcript_digest===record.transcript_digest,'changed');
     const bytes=Buffer.concat(chunks),value=JSON.parse(bytes);need(Buffer.from(canonical(value)).equals(bytes),'response');
     if(actionRead){
      need(same(current(bindingId,socket),record),'changed');
      const result=actionBindingReply(value,body,record,challenge);
      need(BigInt(clock.pairingSample().upper_ns)<BigInt(result.eligible_before_ns),'action_expired');
      resolve(result);return;
     }
     if(commandOperation){
      need(same(current(bindingId,socket),record),'changed');
      resolve(automationCommandReply(value,body,record,challenge,commandOperation));return;
     }
     if(preparation){
      need(same(current(bindingId,socket),record),'changed');
      const result=eligibility?armPreparationEligibilityReply(value,body,record,challenge):armPreparationReply(value,body,record,challenge,lookup,{recovery});
      resolve(readPreparation?result:{created:response.statusCode===202,record:result});return;
     }
     if(protection){
      need(same(current(bindingId,socket),record),'changed');
      resolve(observation?runApprovalProtectionObservation(value,body,challenge):(reverse?endorsementRevocationReceipt:runApprovalProtectionReply)(value,body,{completion}));return;
     }
     if(operation==='session-denials'){need(same(pairings.currentPending(bindingId),record),'changed');sessionDenialReceipt(value,body);}
     else need(value.pair_attempt_id===record.transcript.pair_attempt_id&&value.transcript_digest===record.transcript_digest,'response_binding');
     if(operation==='status')need(value.format==='leafseamer.peer-pairing-status/1'&&value.binding_ref?.id===target.binding_id&&Array.isArray(value.proofs)&&value.proofs.length<=2,'response_binding');
     if(approvalRead){need(same(current(bindingId,socket),record),'changed');resolve(automationApprovalReply(value,body,record));return;}
     resolve(received(value,socket));
    }catch(error){reject(error);}});
   });request.on('error',reject);request.on('timeout',()=>request.destroy(new Error('peer_pairing_timeout')));
   if(operation==='session-denials'||approvalRead||protection||preparation||actionProtocol){
    const timer=setTimeout(()=>request.destroy(new Error('peer_pairing_timeout')),5000);request.on('close',()=>clearTimeout(timer));
    request.on('socket',socket=>socket.once('secureConnect',()=>{try{need(same(current(bindingId,socket),record),'changed');request.end(bytes);}catch(error){request.destroy(error);}}));
   }else request.end(bytes);
  });
 }
 async function prepareBoundObservation(bindingId,receive,project,windowNs){
  const start=clock.pairingSample(),started=BigInt(start.tick_ns),record=pairings.currentPending(bindingId),pairingRef=pairingReference(record);
  const observationDeadline=started+windowNs;
  const body=await receive();
  let active=true;
  return Object.freeze({get original(){return structuredClone(project(body));},assertCurrentInTransaction(){
   need(active&&!closed,'preparation_expired');
   try{
    need(same(pairings.requireActivatedInTransaction(pairingRef),record),'changed');
    const now=clock.pairingSample(),tick=BigInt(now.tick_ns);
    need(same(now.runtime_domain_ref,start.runtime_domain_ref)&&tick>=started&&tick<observationDeadline&&
     BigInt(now.upper_ns)<BigInt(body.eligible_before_ns),'preparation_expired');
    return true;
   }catch(error){active=false;throw error;}
  }});
 }
 function requestRunRecord(bindingId,reference,collection){
  const spec=runRecordReads[collection],fixed=spec.reference(structuredClone(reference));
  const start=clock.pairingSample(),started=BigInt(start.tick_ns);
  const approvalObservation=collection==='run-approvals';
  const observationDeadline=started+(approvalObservation?runEligibilityObservationNs:2000000000n);
  need(!closed&&peers&&identity.service_kind===spec.reader,'configuration_missing');
  const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id);
  const target=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
  const localParty=record.transcript.parties.find(p=>p.service_id===identity.service_id);
  need(peer&&record.state==='activated'&&target?.service_kind===spec.owner&&
   localParty.permissions.includes('automation.prepare.read')&&same(fixed.scope,peerScope(target)),'purpose');
  const challenge=crypto.randomUUID(),request=spec.request(fixed.object_id,fixed.revision,fixed.digest,challenge);
  const stable=socket=>{
   need(same(current(bindingId,socket),record),'changed');const now=clock.pairingSample(),tick=BigInt(now.tick_ns);
   need(same(now.runtime_domain_ref,start.runtime_domain_ref)&&tick>=started&&tick<observationDeadline,spec.timeout);
   return now;
  };
  const suffix=spec.versioned?'/revisions/'+fixed.revision:'';
  return new Promise((resolve,reject)=>{
   const outgoing=https.request(peer.origin+'/internal/automation/'+collection+'/'+fixed.object_id+suffix,{
    method:'GET',agent:false,key,cert,ca:roots.map(root=>root.toString()),servername:isIP(peer.server_name)?undefined:peer.server_name,
    minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true,headers:{'X-LeafSeamer-Pairing':target.binding_id,
     [spec.header]:fixed.digest,'X-LeafSeamer-Challenge':challenge}},response=>{
    const socket=response.socket;
    try{stable(socket);need(response.statusCode===200&&response.headers['content-type']==='application/json'&&
     response.headers['cache-control']==='no-store','response');}catch(error){response.destroy();reject(error);return;}
    const chunks=[];let size=0;
    response.on('data',chunk=>{size+=chunk.length;if(size>runProposalResponseLimit)response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});
    response.on('error',reject);response.on('end',()=>{try{
     const value=spec.decode(decodeDeviceBindings(Buffer.concat(chunks),runProposalResponseLimit),request,record,peerScope(target),peerScope(identity));
     const now=stable(socket),deadline=spec.deadline(value);
     if(deadline!==null)need(BigInt(now.upper_ns)<BigInt(deadline),spec.timeout);
     resolve(value);
    }catch(error){reject(error);}});
   });
   const timer=setTimeout(()=>outgoing.destroy(new Error('peer_pairing_timeout')),approvalObservation?runEligibilityObservationMs:2000);
   outgoing.on('close',()=>clearTimeout(timer));outgoing.on('error',reject);
   outgoing.on('socket',socket=>socket.once('secureConnect',()=>{try{stable(socket);outgoing.end();}catch(error){outgoing.destroy(error);}}));
  });
 }
 let delivery=null,stopping=null;
 const subscriptionMonitor=subscriptions?setInterval(()=>{try{subscriptions.sweep();websocketServer?.sweep();}catch{websocketServer?.sweep();}},250):null;subscriptionMonitor?.unref();
 const api=Object.freeze({origin,configuration:structuredClone(localConfiguration),
  bindPeers(values){need(!peers&&Array.isArray(values)&&values.length<=64,'configuration');const next=values.map(p=>{
   const x=certificate(p.cert),ep=endpoint(p.origin,p.server_name);name(x,ep.server_name);need(roots.some(root=>x.checkIssued(root)&&x.verify(root.publicKey))&&/^sha256:[0-9a-f]{64}$/.test(p.trust_bundle_digest),'certificate_chain');
   return {...structuredClone(p),...ep};});
   need(new Set([localConfiguration.spki_sha256,...next.map(p=>pairingCertificate(p.cert).spki_sha256)]).size===next.length+1,'certificate_service_alias');
   const signer=identity.service_kind==='controller'?Object.freeze({certificate:local,check(serviceId){
    need(!closed,'closed');const peer=next.find(item=>item.identity.service_id===serviceId);need(peer,'peer');
    const remote=certificate(peer.cert),root=roots.find(item=>remote.checkIssued(item)&&remote.verify(item.publicKey));need(root,'certificate_chain');
    const chain=[local,localRoot,remote,root];for(const item of new Set(chain))inTime(item,clock);
    return BigInt(Math.min(...chain.map(item=>item.validToDate.getTime())))*1000000n;
   },sign(body){return signFirstPairingAuthorization(body,local,privateKey);}}):null;
   need(!closed,'closed');pairings.bindConfiguration({local:localConfiguration,peers:next.map(p=>describe(p.identity,p.cert,endpoint(p.origin,p.server_name),p.trust_bundle_digest))},signer);peers=next;
   if(sessionDenials)delivery=startSessionDenialDelivery({store:sessionDenials,transport:api});
  },
  sessionDenialStatus:()=>delivery?.status()??null,
  status:bindingId=>remote(bindingId,'status'),
  deliverSessionDenial:(bindingId,notice)=>remote(bindingId,'session-denials',notice),
  deliverRunApprovalProtection:(bindingId,notice,{completion=false}={})=>
   remote(bindingId,completion?'run-approval-protection-completion':'run-approval-protection',structuredClone(notice)),
  observeRunApprovalProtection:(bindingId,notice)=>remote(bindingId,'run-approval-protection-observation',structuredClone(notice)),
  deliverRunEndorsementRevocation:(bindingId,notice)=>remote(bindingId,'run-endorsement-revocation',structuredClone(notice)),
  submitRunPreparation:(bindingId,request)=>remote(bindingId,'preparations',structuredClone(request)),
  lookupRunPreparation:(bindingId,request)=>remote(bindingId,'preparations/lookup',structuredClone(request)),
  submitRecoveryPreparation:(bindingId,request)=>remote(bindingId,'recovery-preparations',structuredClone(request)),
  lookupRecoveryPreparation:(bindingId,request)=>remote(bindingId,'recovery-preparations/lookup',structuredClone(request)),
  readAutomationServiceApproval:(bindingId,{principal,approval_ref})=>remote(bindingId,'automation-service-approval',
   {format:'leafseamer.automation-approval-request/1',challenge_id:crypto.randomUUID(),principal:structuredClone(principal),approval_ref:structuredClone(approval_ref)}),
  readRunApprovalProposal:(bindingId,reference)=>requestRunRecord(bindingId,reference,'approval-proposals'),
  readRunApprovalEndorsement:(bindingId,reference)=>requestRunRecord(bindingId,reference,'run-approval-endorsements'),
  readRunApprovalControls:(bindingId,reference)=>requestRunRecord(bindingId,reference,'run-approval-control-observations'),
  readRunApproval:(bindingId,reference)=>requestRunRecord(bindingId,reference,'run-approvals'),
  readRunInitiator:(bindingId,reference)=>requestRunRecord(bindingId,reference,'run-operations'),
  readRunRecoveryInitiator:(bindingId,reference)=>requestRunRecord(bindingId,reference,'recovery-operations'),
  prepareRunArmPlan:(bindingId,reference)=>prepareBoundObservation(bindingId,()=>requestRunRecord(bindingId,reference,'arm-plans'),body=>body.original,2000000000n),
  prepareRunRecoveryPlan:(bindingId,reference)=>prepareBoundObservation(bindingId,()=>requestRunRecord(bindingId,reference,'recovery-plans'),body=>body.original,2000000000n),
  prepareRunPreparationEligibility:(bindingId,request)=>prepareBoundObservation(bindingId,
   ()=>remote(bindingId,'preparations/eligibility',structuredClone(request)),body=>body,runEligibilityObservationNs),
  prepareRecoveryPreparationEligibility:(bindingId,request)=>prepareBoundObservation(bindingId,
   ()=>remote(bindingId,'recovery-preparations/eligibility',structuredClone(request)),body=>body,runEligibilityObservationNs),
  prepareRunActionBinding:(bindingId,request)=>prepareBoundObservation(bindingId,
   ()=>remote(bindingId,'action-bindings',structuredClone(request)),body=>body,runEligibilityObservationNs),
  submitAutomationCommand:(bindingId,request)=>remote(bindingId,'automation-commands/submit',structuredClone(request)),
  lookupAutomationCommand:(bindingId,request)=>remote(bindingId,'automation-commands/lookup',structuredClone(request)),
  readAutomationCommandResult:(bindingId,request)=>remote(bindingId,'automation-commands/result',structuredClone(request)),
  readAutomationCommandResource:(bindingId,request)=>remote(bindingId,'automation-commands/resource',structuredClone(request)),
  rejectAutomationCommand:(bindingId,request)=>remote(bindingId,'automation-commands/reject',structuredClone(request)),
  async openSubscriptionChannel(bindingId,{protocol,onFrame,onClose}){
   need(!closed&&peers&&identity.service_kind==='seamer'&&websocketClients.size<8,'subscription_request');const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id),local=record.transcript.parties.find(p=>p.service_id===identity.service_id),target=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
   need(peer&&record.state==='activated'&&local.permissions.includes('event.internal.subscribe'),'purpose');const stable=(socket,inside=false)=>{need(!closed,'closed');validate(socket,peer);need(same(current(bindingId,socket,inside?{id:record.binding_id,revision:record.revision,digest:record.digest}:null),record),'changed');};
   const abort=new AbortController(),pending={close:()=>abort.abort()};websocketClients.add(pending);let channel;
   const opening=openPeerWebsocket(peer.origin.replace('https:','wss:')+'/internal/events',protocol,{agent:false,signal:abort.signal,key,cert,ca:roots.map(root=>root.toString()),headers:{'X-LeafSeamer-Pairing':target.binding_id},servername:isIP(peer.server_name)?undefined:peer.server_name,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true},{stable,onFrame,onClose:error=>{websocketClients.delete(channel);onClose?.(error);}});
   pending.finished=opening.catch(()=>{});try{channel=await opening;}finally{websocketClients.delete(pending);}
   if(closed){channel.close();throw Error('peer_pairing_closed');}websocketClients.add(channel);return channel;
  },
  requestSubscription(bindingId,{method,path,headers,body}){
   const sourceTime=method==='GET'&&/^\/internal\/events\/source-times\/[A-Za-z0-9._:-]{1,128}\/[1-9][0-9]{0,19}\?digest=sha256%3A[0-9a-f]{64}$/.test(path);
   const referenceBundle=method==='GET'&&/^\/internal\/reference-time\/bundles\/[A-Za-z0-9._:-]{1,128}\/[1-9][0-9]{0,19}\?digest=sha256%3A[0-9a-f]{64}$/.test(path);
   const subscription=['POST','GET','DELETE'].includes(method)&&/^\/internal\/subscriptions(?:\/[A-Za-z0-9_-]{1,128}(?:(?:\/snapshot|\/snapshots\/[A-Za-z0-9_-]{1,128}\/pages\/[0-9]{1,3})\?expected_connection_generation=[0-9]{1,20}|\/snapshot-context|\/connections\/[A-Za-z0-9_-]{1,128}|\?expected_revision=[0-9]{1,20})?)?$/.test(path);
   const evidence=sourceTime||referenceBundle;
   need(!closed&&peers&&identity.service_kind==='seamer'&&(evidence||subscription)&&Buffer.isBuffer(body)&&body.length<=(evidence?0:16384),'subscription_request');
   const record=pairings.currentPending(bindingId),peer=peers.find(p=>p.identity.service_id===record.peer_service_id),local=record.transcript.parties.find(p=>p.service_id===identity.service_id),target=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
   need(peer&&record.state==='activated'&&local.permissions.includes(referenceBundle?'clock.internal.read':sourceTime?'events.internal.read':'event.internal.subscribe'),'purpose');
   const limit=referenceBundle?65536:sourceTime?16384:path.includes('/snapshot?')?8388608:262144;
   const stable=socket=>{validate(socket,peer);need(same(current(bindingId,socket),record),'changed');};
   return new Promise((resolve,reject)=>{let timer;const done=(error,value)=>{clearTimeout(timer);error?reject(error):resolve(value);};
    const outgoing=https.request(peer.origin+path,{method,agent:false,key,cert,ca:roots.map(root=>root.toString()),headers:{...Object.fromEntries(headers),'X-LeafSeamer-Pairing':target.binding_id},servername:isIP(peer.server_name)?undefined:peer.server_name,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true},response=>{
     const socket=response.socket;try{stable(socket);need(response.headers['cache-control']==='no-store','response');}catch(error){response.destroy();done(error);return;}
     const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>limit)response.destroy(new Error('peer_pairing_response_capacity'));else chunks.push(chunk);});response.on('error',done);
     response.on('end',()=>{try{stable(socket);const headers=[];for(let i=0;i<response.rawHeaders.length;i+=2)headers.push([response.rawHeaders[i],response.rawHeaders[i+1]]);done(null,{status:response.statusCode,headers,body:Buffer.concat(chunks)});}catch(error){done(error);}});
    });timer=setTimeout(()=>outgoing.destroy(new Error('peer_pairing_timeout')),evidence?1000:5000);outgoing.on('error',done);outgoing.on('socket',socket=>socket.once('secureConnect',()=>{try{stable(socket);outgoing.end(body);}catch(error){outgoing.destroy(error);}}));
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
