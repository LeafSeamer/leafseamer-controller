import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {controlNeed as need,controlHash as hash,controlRead as read,controlSeal as seal,controlNext as next} from './device-control-value.mjs';

// 只在业务writer事务内使用；原登记记录保留不动，追加修订成为唯一当前投影。
export function deviceControlRepository(db,devices){
 const writer=()=>need(db.inTransaction,'writer');
 const tables={record:['control_record_revision','control_record_head','device_id'],operation:['control_operation_revision','control_operation_head','operation_id'],offer:['control_offer_revision','control_offer_head','transfer_id']};
 function current(kind,id){writer();const [table,head,key]=tables[kind];const row=db.prepare(`SELECT r.body_jcs,r.body_digest,r.revision,r.target_device_id FROM ${table} r JOIN ${head} h USING(${key},revision) WHERE r.${key}=?`).raw().get(id);
  if(!row){if(kind==='record')return devices.control(id);need(false,'not_found');}const value=read(row[0],row[1]);
  need(value[key]===id&&value.revision===String(row[2])&&value.device_id===row[3],'integrity');return value;}
 function append(kind,value,commit){
  writer();const [table,head,key]=tables[kind],row=db.prepare(`SELECT revision FROM ${head} WHERE ${key}=?`).pluck().get(value[key]);
  const revision=Number(value.revision);need(Number.isSafeInteger(revision)&&revision===(row??(kind==='record'?1:0))+1,'revision');
  need(db.prepare(`INSERT INTO ${table} VALUES(?,?,?,?,?,?)`).run(value[key],revision,value.device_id,canonicalize(value),hash(value),commit).changes===1,'storage');
  if(row===undefined)need(db.prepare(`INSERT INTO ${head} VALUES(?,?)`).run(value[key],revision).changes===1,'storage');
  else need(db.prepare(`UPDATE ${head} SET revision=? WHERE ${key}=? AND revision=?`).run(revision,value[key],row).changes===1,'storage');
 }
 return Object.freeze({current,append,
  touch(kind,value,commit){const field={record:'record_digest',operation:'operation_digest',offer:'offer_digest'}[kind];const updated=seal({...value,revision:next(value.revision)},field);append(kind,updated,commit);return updated;},
  prior(identity){writer();const row=db.prepare('SELECT request_digest,receipt_jcs,receipt_digest,key_jcs FROM control_request WHERE key_digest=?').raw().get(hash(identity.key));if(!row)return null;
   need(row[0]===identity.request_digest,'conflict');const receipt=read(row[1],row[2]);need(canonicalize(receipt.identity)===canonicalize(identity)&&row[3]===canonicalize(identity.key),'integrity');return receipt;},
  request(identity,context,device,receipt,commit){writer();need(db.prepare('INSERT INTO control_request VALUES(?,?,?,?,?,?,?,?)').run(hash(identity.key),canonicalize(identity.key),identity.request_digest,device,context,canonicalize(receipt),hash(receipt),commit).changes===1,'storage');},
  commit(id,kind,actor,members,acquisition){writer();need(db.prepare('INSERT INTO control_change_commit VALUES(?,?,?,?,?,?)').run(id,kind,members,
   canonicalize({kind,actor,acquisition_ref:acquisition}),crypto.randomUUID(),canonicalize({kind,commit_id:id})).changes===1,'storage');},
  capacity(){writer();need(db.prepare('SELECT count(*) FROM control_request').pluck().get()<4096&&db.prepare('SELECT count(*) FROM control_change_commit').pluck().get()<16384,'capacity');}
 });
}
