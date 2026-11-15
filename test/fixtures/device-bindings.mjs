import assert from 'node:assert/strict';
import fs from 'node:fs';
import Database from 'better-sqlite3';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../../',import.meta.url));assert.ok(path.isAbsolute(root));
const asset=name=>path.join(root,'dist',name),load=name=>import(pathToFileURL(asset(name)));
const {canonical,digest}=await load('auth-clock-value.mjs');
const {readDeviceCapabilities}=await load('device-capability-view.mjs');
const {qualifyDeviceFootprint}=await load('device-footprint-qualification.mjs');
const {registerDeviceAutomation,readDeviceAutomationBindings}=await load('device-automation-binding.mjs');

export function fixture(t,change=()=>{},options={}){
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec(`CREATE TABLE device_record(device_id TEXT,descriptor_body TEXT,descriptor_digest TEXT);
 CREATE TABLE device_module_frame(channel_id TEXT,direction TEXT,sequence TEXT,message_type TEXT,frame_jcs TEXT,frame_digest TEXT);
 CREATE TABLE device_catalog_approval(channel_id TEXT,device_id TEXT,device_session_id TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE extension_approval_capabilities(approval_id TEXT,body_jcs TEXT,body_digest TEXT);`);
 const template=JSON.parse(fs.readFileSync(asset('simulator-control-capability.json'),'utf8'));change(template);
 const service=options.service??{service_id:'service',database_instance_id:'database'},device=options.device??'device',channel='channel';
 const extension_binding={installation_ref:{object_id:'installation'},approval_ref:{object_id:'approval'},platform_profile_ref:{object_id:'platform'}};
 const runtime={ref:{object_id:'runtime'},binding:{...service,launch_intent:{member_id:'worker',extension_binding},admission_receipt:{member_boot_id:'boot'}}};
 const content={receipt:{manifest_digest:digest('manifest'),artifact_set_digest:digest('artifacts')},intake_ref:{object_id:'intake'},manifest:{extension_id:'simulator',extension_version:'1.0.0'}};
 const link={device_ref:{object_id:device},resource_ref:{object_id:'resource'},template_digest:digest(template)};
 const evidence={...content.receipt,intake_ref:content.intake_ref,documents:[{template}]};
 const qualification={...content.receipt,...extension_binding,...link};
 const approved={device_id:device,channel_id:channel,connected_message_id:'connected',runtime_binding_ref:runtime.ref,qualification,
 catalog:{catalog_revision:'1',state_schema:template.state_schema,action_ids:template.actions.map(x=>x.action_id),trigger_ids:template.triggers.map(x=>x.trigger_id)}};
 const connected={request_id:'connected',binding:{runtime_binding_ref:runtime.ref},body:{device_id:device,device_session_id:'session'}};
 const descriptor={device_id:device,device_kind:'simulator',display_name:'模拟器',connection_state:'offline'};
 db.prepare('INSERT INTO device_record VALUES(?,?,?)').run(device,canonical(descriptor),digest(descriptor));
 db.prepare('INSERT INTO device_module_frame VALUES(?,?,?,?,?,?)').run(channel,'w2c','9','CONNECTED',canonical(connected),digest(connected));
 db.prepare('INSERT INTO device_catalog_approval VALUES(?,?,?,?,?)').run(channel,device,'session',canonical(approved),digest(approved));
 db.prepare('INSERT INTO extension_approval_capabilities VALUES(?,?,?)').run('approval',canonical(evidence),digest(evidence));
 const input={service,device,channel,runtime,selected:{content},dependencies:{links:[link],capability_evidence_digest:digest(evidence)}};
 return {db,input,template,connected,approved,read:()=>db.transaction(()=>readDeviceCapabilities(db,input)).immediate()};
}
export function registered(t,options={}){
 const f=fixture(t,()=>{},options),review=JSON.parse(fs.readFileSync(asset('simulator-control-footprint.json')));
 Object.assign(f.approved.qualification,{qualification:'fixed_memory_control_catalog/1',module_digest:review.module_digest,protocol_io_policy_digest:review.protocol_io_policy_digest});
 f.approved.qualification.installation_ref.revision='1';f.approved.format='leafseamer-catalog-approval/3';f.approved.approval_id='catalog';f.approved.device_session_id='session';
 f.approved.footprint_qualification=qualifyDeviceFootprint({...f.approved,runtime:f.input.runtime});
 f.approved.automation_registration=registerDeviceAutomation(f.approved,f.input.runtime);
 f.input.selected.entry={file_id:'module',io_policy_file_id:'policy'};
 f.input.selected.content.inventory={files:[{file_id:'module',digest:review.module_digest},{file_id:'policy',digest:review.protocol_io_policy_digest}]};
 const save=()=>f.db.prepare('UPDATE device_catalog_approval SET body_jcs=?,body_digest=?').run(canonical(f.approved),digest(f.approved));save();
 return {...f,save,bindings:expected=>f.db.transaction(()=>readDeviceAutomationBindings(f.db,f.input,expected)).immediate()};
}
