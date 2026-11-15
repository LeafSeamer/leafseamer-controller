import {canonical,digest,same} from './auth-clock-value.mjs';
const need=(value,code)=>{if(!value)throw new Error('session_denial_'+code);};
const fields=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.split(',').sort().join(','),'fields');
const id=v=>need(typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(v),'id');
const revision=v=>need(typeof v==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(v)&&BigInt(v)<=(1n<<64n)-1n,'revision');
const hash=v=>need(typeof v==='string'&&/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(v),'digest');
const scope=v=>{fields(v,'authority_service_id,database_instance_id');Object.values(v).forEach(id);};
export function sessionDenialNotice(v){
 fields(v,'format,issuer_scope,issuer_id,issuer_epoch,operation_ref,session_id,revision_floor,target_scope');
 need(v.format==='leafseamer.session-denial/1','format');scope(v.issuer_scope);scope(v.target_scope);id(v.issuer_id);id(v.issuer_epoch);id(v.session_id);
 fields(v.operation_ref,'id,revision,digest');id(v.operation_ref.id);revision(v.operation_ref.revision);hash(v.operation_ref.digest);revision(v.revision_floor);
 need(v.issuer_scope.authority_service_id!==v.target_scope.authority_service_id,'scope');return v;
}
export function sessionDenialReceipt(v,notice){
 sessionDenialNotice(notice);fields(v,'format,receipt_id,notice_digest,target_scope,service_boot_id,identity_state,protection_state');
 need(v.format==='leafseamer.session-denial-receipt/1'&&v.identity_state==='denied'&&v.protection_state==='pending','receipt');
 id(v.receipt_id);id(v.service_boot_id);hash(v.notice_digest);scope(v.target_scope);
 need(v.notice_digest===digest(notice)&&same(v.target_scope,notice.target_scope),'receipt_binding');return v;
}
export function decodeSessionDenial(bytes){
 need(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=16384,'capacity');const value=JSON.parse(bytes);
 need(Buffer.from(canonical(value)).equals(bytes),'canonical');return sessionDenialNotice(value);
}
