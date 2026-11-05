import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {pinLaunchContent} from './launch-content.mjs';
import {IdentityError} from './identity-crypto.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('extension_launch_'+code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
// 核心内部启动准备的固定来源；不接受调用者传入审批、角色或安装提供者。
export function extensionLaunchBinding({db,service,available,source,currentApproval,currentResolution,reference}){
 function select(approvalRef){
  need(db.inTransaction,'writer_required');const approved=currentApproval(approvalRef);
  need(approved.status==='approved','revoked');const record=approved.record;
  const row=db.prepare('SELECT content_jcs,content_digest FROM extension_candidate WHERE installation_id=?').raw().get(record.installation_ref.object_id);
  need(row,'installation');const content=JSON.parse(row[0]);need(canonicalize(content)===row[0]&&hash(content)===row[1]&&
   same(record.installation_ref,reference('installation',content.installation_id,1,content)),'installation');
  const receipt=content.receipt;
  need(same(record.platform_profile_ref,receipt.platform_profile_ref)&&
   record.manifest_digest===receipt.manifest_digest&&record.artifact_set_digest===receipt.artifact_set_digest,'content_binding');
  need(content.manifest.kind==='device_module','entry');
  const resolution=currentResolution(record.installation_ref);need(same(resolution.resolution_ref,record.role_resolution_ref),'resolution');
  // 先覆盖全部实际设备角色，不能仅从批准权限数组缩小worker登记范围。
  // 其他对象与隐式物理足迹须由完整资源图接通后进入运行授权，准备本身不签发授权。
  need(resolution.record.bindings.every(binding=>binding.kind==='device'),'object_provider_unavailable');
  return {content,approval:record,permissions:approved.permissions,resolution:resolution.record};
 }
 function current(intent){
  const chosen=select(intent.extension_binding.approval_ref),{content,approval:record,resolution}=chosen,binding=intent.extension_binding;
  for(const name of ['installation_ref','approval_ref','review_ref','role_resolution_ref','configuration_ref','permissions_digest'])need(same(binding[name],record[name]),'approval_binding');
  for(const name of ['platform_profile_ref','host_installation_id','host_trust_epoch','manifest_digest','artifact_set_digest'])need(same(binding[name],content.receipt[name]),'content_binding');
  need(same(binding.intake_ref,content.intake_ref),'content_binding');
  const entry=content.manifest.entrypoints.find(value=>value.entry_id===binding.entry_id);
  need(entry?.kind==='worker'&&entry.loader==='node_module','entry');
  need(content.inventory.files.some(file=>file.file_id===entry.file_id&&file.role==='module')&&content.inventory.files.some(file=>file.file_id===entry.io_policy_file_id&&file.role==='policy'),'entry');
  const devices=[...new Set(resolution.bindings.flatMap(value=>value.values.map(ref=>ref.object_id)))].sort();
  need(same(intent.object_scope,{kind:'devices',device_ids:devices}),'devices');return {...chosen,entry};
 }
 async function observeSelected(read){
  available();const selected=db.transaction(read).immediate(),host=source(),content=selected.content;
  need(host&&host.identity.authority_service_id===content.intake_ref.authority_service_id&&host.identity.database_instance_id===content.intake_ref.database_instance_id&&
   host.identity.host_installation_id===content.receipt.host_installation_id,'source');
  const result=await host.describe({intake_id:content.intake_ref.object_id,target_authority_service_id:service.service_id});available();
  need(result?.status==='available'&&result.content?.format==='leafseamer-intake-content/1'&&same(result.content.intake_ref,content.intake_ref)&&
   same(result.content.receipt,content.receipt)&&same(result.content.manifest,content.manifest)&&same(result.content.inventory,content.inventory),'source_unavailable');
  return selected;
 }
 const observe=intent=>observeSelected(()=>current(intent));
 return Object.freeze({current,observe,select,observeSelection:ref=>observeSelected(()=>select(ref)),async acquire(intent){
  available();const selected=db.transaction(()=>current(intent)).immediate(),host=source(),content=selected.content;
  need(host?.loader,'loader_source');
  need(host.identity.authority_service_id===content.intake_ref.authority_service_id&&host.identity.database_instance_id===content.intake_ref.database_instance_id&&
   host.identity.host_installation_id===content.receipt.host_installation_id,'source');let lease,pin;
  try{
   lease=await host.loader({intake_id:content.intake_ref.object_id,target_authority_service_id:service.service_id});available();
   const value=lease?.content;
   need(lease?.status==='available'&&typeof lease.assertCurrent==='function'&&typeof lease.close==='function'&&
    value?.format==='leafseamer-loader-materialization/1'&&same(value.intake_ref,content.intake_ref)&&same(value.receipt,content.receipt)&&
    same(value.manifest,content.manifest)&&same(value.inventory,content.inventory),'loader_binding');
   lease.assertCurrent();pin=await pinLaunchContent(value.root.path,content.inventory,value.root.root_identity);available();
   lease.assertCurrent();pin.assertHeld();need(same(db.transaction(()=>current(intent)).immediate(),selected),'approval_stale');
   const released=await lease.close();lease=null;need(released?.status==='released','loader_expired');available();pin.assertHeld();
   const protection=Object.freeze({root_path:value.root.path,root_identity:pin.rootIdentity,entry_file_id:selected.entry.file_id,
    entry_path:content.inventory.files.find(file=>file.file_id===selected.entry.file_id).path,
    io_policy_file_id:selected.entry.io_policy_file_id,manifest_digest:content.receipt.manifest_digest,artifact_set_digest:content.receipt.artifact_set_digest});
   const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
   const materials=freeze({format:'leafseamer-worker-load/1',root_path:protection.root_path,root_identity:protection.root_identity,
    manifest:structuredClone(content.manifest),inventory:structuredClone(content.inventory)});
   const held=pin;pin=null;
   return Object.freeze({protection,materials,closed:held.closed,close:held.close,async verify(){
    try{held.assertHeld();await observe(intent);await held.verify();available();db.transaction(()=>current(intent)).immediate();held.assertHeld();}
    catch(error){await held.close();throw error;}
   }});
  }catch(error){if(pin)await pin.close();throw error;}
  finally{if(lease?.close)await lease.close();}
 }});
}
