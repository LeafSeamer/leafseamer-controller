import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../../dist/storage.mjs';
export const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
export const inspect=(dir,fn)=>{const db=new Database(path.join(dir,'controller.sqlite'));try{return fn(db);}finally{db.close();}};
export async function setup(t,revision=13){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-installation-authority-'));initializeStorage(dir);await migrateStorage(dir,revision);let store=openStorage(dir);
  t.after(()=>{store?.close();assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
  return {dir,get store(){return store;},close(){store.close();},reopen(){store=openStorage(dir);return store;}};
}
export function fixture(service){
  const identity={host_installation_id:'host.synthetic',authority_service_id:'installer.synthetic',database_instance_id:'installation.synthetic'};
  const ref=kind=>({kind,authority_service_id:identity.authority_service_id,database_instance_id:identity.database_instance_id,object_id:kind,revision:'1',digest:hash(kind)});
  const inventory={inventory_version:'extension-files/1',files:['config','license','lock','policy','worker'].map(file_id=>({file_id,path:file_id+'.txt',size_bytes:'1',digest:hash(file_id),
    role:{config:'schema',license:'license',lock:'dependency_lock',policy:'policy',worker:'module'}[file_id],executable:false}))};
  const manifest={manifest_version:'extension-artifact/0.1.0-draft.1',extension_id:'extension.synthetic',extension_version:'1',kind:'device_module',publisher_id:'publisher.synthetic',source_revision:'source.synthetic',
    inventory_digest:hash(inventory),dependency_lock_file_id:'lock',license_file_ids:['license'],capability_template_file_ids:[],configuration_schema_file_id:'config',platforms:['windows-x64'],
    api_versions:['api.synthetic'],ipc_versions:['ipc.synthetic'],required_features:[],entrypoints:[{entry_id:'worker',kind:'worker',file_id:'worker',loader:'node_module',io_policy_file_id:'policy'}],roles:[],permission_templates:[]};
  const receipt={host_installation_id:identity.host_installation_id,host_trust_epoch:'1',import_operation_id:'import.synthetic',intake_id:'intake.synthetic',target_authority_service_id:service.service_id,
    manifest_digest:hash(manifest),artifact_set_digest:hash(inventory),package_bytes:'1',file_inventory_digest:hash(inventory),dependency_lock_digest:hash('lock'),
    platform_profile_ref:ref('platform_profile'),validation_policy_ref:ref('validation_policy'),release_authorization_ref:ref('release_authorization'),verification_record_ref:ref('verification')};
  const content={format:'leafseamer-intake-content/1',intake_ref:{...ref('intake'),object_id:receipt.intake_id,digest:hash(receipt)},receipt,manifest,inventory};
  return {identity,content,describeIntake:async()=>({status:'available',content})};
}
export function configure(f){const api=f.store.extensionInstallations,host=fixture(f.store.identity);api.bindSource(host);
  const slot=api.createSlot({request_id:'slot.request',extension_id:host.content.manifest.extension_id});
  return {api,host,slot,request:{request_id:'stage.request',slot_id:slot.record.slot_id,expected_slot_revision:'1',intake_ref:host.content.intake_ref}};}
