import crypto from 'node:crypto';
import {setup,fixture,hash} from './extension-installation.mjs';
export async function prepared(t,{revision=15,recheck=()=>{},prepareHost=()=>{}}={}){
 const f=await setup(t,revision),host=fixture(f.store.identity),raw=Buffer.from('{}'),file=host.content.inventory.files.find(f=>f.file_id==='config');
 Object.assign(file,{size_bytes:String(raw.length),digest:'sha256:'+crypto.createHash('sha256').update(raw).digest('hex')});
 host.content.manifest.roles=[{role_id:'device',kind:'device',minimum:1,maximum:1,purpose:'设备绑定'}];
 host.content.manifest.permission_templates=[{request_id:'device.request',kind:'device_scope',purpose:'请求设备动作',scope:{device_role:'device',action_ids:['get','set'],trigger_ids:[]}}];
 prepareHost(host);
 host.content.manifest.inventory_digest=hash(host.content.inventory);host.content.receipt.artifact_set_digest=hash(host.content.inventory);
 host.content.receipt.file_inventory_digest=hash(host.content.inventory);host.content.receipt.manifest_digest=hash(host.content.manifest);host.content.intake_ref.digest=hash(host.content.receipt);
 host.describeConfigurationSchema=async()=>({status:'available',content:{format:'leafseamer-configuration-schema/1',intake_ref:host.content.intake_ref,
  manifest_digest:host.content.receipt.manifest_digest,artifact_set_digest:host.content.receipt.artifact_set_digest,file,bytes:raw}});
 const describe=host.describeIntake;host.describeIntake=async query=>{if(host.checkRoles)await recheck(f,host);return host.revoked?{status:'unavailable',content:null}:describe(query);};
 const api=f.store.extensionInstallations;api.bindSource(host);const slot=api.createSlot({request_id:'slot',extension_id:host.content.manifest.extension_id});
 const installed=await api.stage({request_id:'stage',slot_id:slot.record.slot_id,expected_slot_revision:'1',intake_ref:host.content.intake_ref});
 const config=await api.configurations.configure({request_id:'configuration',installation_ref:installed.installation_ref,expected_revision:'0',bytes:raw});
 const capability=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:capability.token_id,secret:capability.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const registered=f.store.registerDevice({request_id:'device',device_kind:'simulator',display_name:'测试设备'});
 host.checkRoles=true;
 return {f,api,host,installed,config,registered,request:api.roles?{request_id:'resolve',installation_ref:installed.installation_ref,configuration_ref:config.configuration_ref,expected_revision:'0',
  bindings:[{role_id:'device',kind:'device',values:[api.roles.deviceReference(registered.device_id)],configuration_ref:config.configuration_ref}]}:null};
}
