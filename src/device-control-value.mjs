import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
export const controlNeed=(ok,code)=>{if(!ok)throw new IdentityError('control_'+code);};
export const controlHash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
export const controlSame=(a,b)=>canonicalize(a)===canonicalize(b);
export const controlActor=proof=>({issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch,principal_id:proof.principal_id});
export const controlVersion=record=>({epoch:record.control_epoch,version:record.effective_version});
export const controlRef=(value,id,digest)=>({id:value[id],revision:value.revision,digest:value[digest]});
export const controlNext=value=>{const next=BigInt(value)+1n;controlNeed(next<=99999999999999999999n,'capacity');return String(next);};
export const controlSeal=(value,key)=>{const body={...value};delete body[key];return {...body,[key]:controlHash(body)};};
export function controlRead(text,digest){const value=JSON.parse(text);controlNeed(canonicalize(value)===text&&controlHash(value)===digest,'integrity');return value;}
export const controlFrozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(controlFrozen);Object.freeze(value);}return value;};
