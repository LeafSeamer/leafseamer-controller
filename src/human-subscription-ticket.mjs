import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {createOpaqueSecret,opaqueVerifier} from './opaque-secret.mjs';
import {IdentityError} from './identity-error.mjs';
import {contractSelection as selection} from './sdk/selection.mjs';

const need=(ok,why)=>{if(!ok)throw new IdentityError('subscription_'+why);};
const deliver=value=>{if(value.denied)throw new IdentityError(value.denied);return value;};
const activeStates=['building','snapshot_ready','catching_up','live'];
const timeBudget=30000000000n;
const pad=value=>String(value).padStart(20,'0');

export function humanSubscriptionTickets({db,service,bootId,writer,read,time,domain,authority,checkCurrent}){
 const select=`SELECT t.*, EXISTS(SELECT 1 FROM human_event_ticket_consumption c WHERE c.ticket_id=t.ticket_id) AS consumed
   FROM human_event_ticket t`;
 function bound(row){
  const original=JSON.parse(row.binding_jcs);
  need(canonical(original)===row.binding_jcs&&digest(original)===row.binding_digest,'integrity');
  return original;
 }
 function ticketView(row,original){return {...original.binding,consumed:row.consumed===1};}
 function requireOwner(actor,saved){
  const owner=saved.view.owner;
  need(owner.kind==='human'&&same(authority.owner(actor,owner.client_instance_id),owner),'not_found');
 }
 function current(original,saved,tokenId){
  const {binding,domain_ref}=original,channel=binding.channel,view=saved.view,clock=domain?.();
  need(view.owner.kind==='human'&&activeStates.includes(view.state)&&channel.service_boot_id===bootId&&
   same(channel.selection,selection)&&channel.publisher_service_id===service.service_id&&channel.publisher_database_instance_id===service.database_instance_id&&
   channel.subscription_id===view.binding.subscription_id&&same(channel.owner,view.owner)&&
   binding.scope_digest===view.binding.scope_digest&&binding.authorization_revision===view.binding.authorization_revision&&
   clock&&same(clock.ref,domain_ref)&&BigInt(clock.tick)>=BigInt(original.issued_tick),'binding');
  checkCurrent(saved);authority.tokenCurrent(tokenId,channel.owner);
  return clock;
 }
 function checkDeadline(original,row,clock){
  need(!row.consumed&&time().upper<BigInt(row.expires_ns)&&BigInt(clock.tick)<BigInt(original.deadline_tick),'ticket_expired');
 }
 return Object.freeze({
  issue(token,csrf,request,origin){
   need(request&&request.origin===origin&&same(request.selection,selection),'binding');
   return deliver(writer(()=>{
    const actor=authority.authenticate(token,csrf,true);if(actor.denied)return actor;
    const saved=read(request.subscription_id);requireOwner(actor,saved);
    const view=saved.view;
    need(activeStates.includes(view.state),'gone');
    need(request.client_instance_id===view.owner.client_instance_id&&request.scope_digest===view.binding.scope_digest&&
     request.expected_authorization_revision===view.binding.authorization_revision,'binding');
    const proof=checkCurrent(saved),requestDigest=digest(request);
    const prior=db.prepare(select+' WHERE t.context_id=? AND t.idempotency_key=?').get(request.context_id,request.idempotency_key);
    if(prior){
     const original=bound(prior);
     need(prior.request_digest===requestDigest&&same(original.binding.channel.owner,view.owner),'conflict');
     return {status:200,view:ticketView(prior,original)};
    }
    const count=db.prepare('SELECT count(*) FROM human_event_ticket').pluck().get();
    const pending=db.prepare(select+" WHERE t.subscription_id=? AND t.expires_ns>? AND NOT EXISTS(SELECT 1 FROM human_event_ticket_consumption c WHERE c.ticket_id=t.ticket_id) LIMIT 8").all(request.subscription_id,pad(time().upper));
    need(count<16384&&pending.length<8,'capacity');
    const context=authority.consumeContext(token,request.context_id,'issueWsTicket');if(context.denied)return context;
    const deadline=db.prepare('SELECT expires_ns FROM request_context WHERE context_id=?').pluck().get(request.context_id);
    const clock=domain?.(),now=time();
    need(clock&&clock.ref&&typeof clock.tick==='string','unavailable');
    const expires=[now.lower+timeBudget,deadline,actor.expires_ns,proof.expires_ns,saved.creation.expires_ns].map(BigInt).reduce((a,b)=>a<b?a:b);
    need(expires>now.upper,'expired');
    const channel={binding_id:crypto.randomUUID(),selection,publisher_service_id:service.service_id,publisher_database_instance_id:service.database_instance_id,
     service_boot_id:bootId,owner:view.owner,subscription_id:request.subscription_id,transport:'human_ticket'};
    const binding={channel,authorization_revision:view.binding.authorization_revision,scope_digest:view.binding.scope_digest,origin,
     expires_at:new Date(Number(expires/1000000n)).toISOString(),consumed:false};
    const original={binding,domain_ref:clock.ref,issued_tick:clock.tick,deadline_tick:String(BigInt(clock.tick)+expires-now.upper)};
    const {secret,verifier}=createOpaqueSecret('ws_ticket');
    const inserted=db.prepare('INSERT INTO human_event_ticket VALUES(?,?,?,?,?,?,?,?,?,?)').run(channel.binding_id,request.subscription_id,
     request.context_id,token.token_id,request.idempotency_key,requestDigest,verifier,pad(expires),canonical(original),digest(original));
    need(inserted.changes===1,'storage');
    checkDeadline(original,{expires_ns:pad(expires)},current(original,saved,token.token_id));
    return {status:201,view:{binding,ticket:secret}};
   }));
  },
  confirm(token,expected,issued){
   return deliver(writer(()=>{
    const actor=authority.authenticate(token);if(actor.denied)return actor;
    const row=db.prepare(select+' WHERE t.ticket_id=?').get(expected.channel.binding_id);
    need(row,'not_found');const original=bound(row),saved=read(row.subscription_id);requireOwner(actor,saved);
    checkCurrent(saved);need(same(ticketView(row,original),expected),'changed');
    if(issued)checkDeadline(original,row,current(original,saved,row.token_id));
    return {};
   }));
  },
  consume(secret,origin){
   const verifier=opaqueVerifier('ws_ticket',secret);
   return writer(()=>{
    const row=db.prepare(select+' WHERE t.verifier=?').get(verifier);
    need(row,'ticket_invalid');const original=bound(row);
    need(original.binding.origin===origin,'binding');
    const clock=current(original,read(row.subscription_id),row.token_id);
    checkDeadline(original,row,clock);
    const inserted=db.prepare('INSERT INTO human_event_ticket_consumption VALUES(?,?)').run(row.ticket_id,bootId);
    need(inserted.changes===1,'storage');
    return {original,tokenId:row.token_id};
   });
  },
  checkAlive(grant){return writer(()=>current(grant.original,read(grant.original.binding.channel.subscription_id),grant.tokenId));},
  check(grant,saved){current(grant.original,saved??read(grant.original.binding.channel.subscription_id),grant.tokenId);}
 });
}
