import {canonical,digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';

const need=(ok,reason)=>{if(!ok)throw new IdentityError('obs_scene_confirmation_'+reason);};
const available=db=>Number(db.pragma('user_version',{simple:true}))>=100;
const ready=catalog=>({...catalog,binding_revision:'2',status:'ready'});
const read=(body,expected)=>{
 const value=JSON.parse(body);
 need(canonical(value)===body&&digest(value)===expected,'integrity');
 return value;
};

export function readConfirmedObsSceneCatalog(db,catalog){
 if(!available(db))return catalog;
 const row=db.prepare('SELECT body_jcs,body_digest FROM obs_scene_confirmation WHERE approval_id=?').raw().get(catalog.collection_ref);
 if(!row)return catalog;
 const record=read(...row);
 need(record.format==='leafseamer-obs-scene-confirmation/1'&&record.catalog_digest===digest(catalog)&&
  canonical(record.catalog)===canonical(catalog),'integrity');
 return ready(catalog);
}

export function confirmObsSceneCatalog(db,catalog,request,proof){
 need(db.inTransaction&&available(db),'unavailable');
 const requestId=request?.request_id,expected=request?.expected_catalog_digest;
 need(request&&Object.keys(request).sort().join(',')==='expected_catalog_digest,request_id'&&
  typeof requestId==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(requestId)&&
  typeof expected==='string'&&/^sha256:[0-9a-f]{64}(?![\s\S])/.test(expected),'input');
 need(catalog.status==='unconfirmed'&&catalog.binding_revision==='1'&&expected===digest(catalog),'stale');
 const {issuer_id,issuer_epoch,principal_id,session_id,authorization_revision,acquisition_ref}=proof;
 const prior=db.prepare('SELECT approval_id,body_jcs,body_digest FROM obs_scene_confirmation WHERE session_id=? AND request_id=?')
  .raw().get(session_id,requestId);
 if(prior){
  need(prior[0]===catalog.collection_ref,'conflict');
  return readConfirmedObsSceneCatalog(db,catalog);
 }
 need(!db.prepare('SELECT 1 FROM obs_scene_confirmation WHERE approval_id=?').pluck().get(catalog.collection_ref),'conflict');
 const record={format:'leafseamer-obs-scene-confirmation/1',request_id:requestId,catalog_digest:expected,catalog,
  actor:{issuer_id,issuer_epoch,principal_id,session_id,authorization_revision,acquisition_ref}};
 need(db.prepare('INSERT INTO obs_scene_confirmation VALUES(?,?,?,?,?)')
  .run(catalog.collection_ref,session_id,requestId,canonical(record),digest(record)).changes===1,'storage');
 return readConfirmedObsSceneCatalog(db,catalog);
}
