import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {seal,ref,digest,same,checked} from './auth-clock-value.mjs';
import {readControlSource} from './device-control-source.mjs';
import {readInitialFence} from './device-execution-control.mjs';
import {readCommandClosure} from './command-settlement.mjs';
import {memoExecutionRead,withExecutionReadView} from './execution-read-view.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('initial_open_'+code);};
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const signed=(value,key)=>({...value,[key]:digest(value)});
const reference=(value,id,key)=>({id:value[id],revision:value.revision,digest:value[key]});
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(v);
function decode(text,hash){const v=checked(JSON.parse(text));need(canonicalize(v)===text&&v.digest===hash,'integrity');return v;}

// 首次手动开放的持久前态与计划；没有出站seq、写尝试、ACK或Ready，不授予发送权。
// 两安全状态从真实初始资源与FENCE确认初始化，不用任意revision=0或占位Ref代表风险已清除。
export function deviceInitialOpen({db,writer,resourceCurrent,resourceRead,domain,attach}){
 function derive(id,source,selected){
  need(db.inTransaction,'writer');const s=source.value,i=s.inventory,b=s.binding;
  const successor=s.format==='leafseamer-device-resource-successor/1';
  need((successor||s.format==='leafseamer-initial-resource-source/2')&&s.deny_snapshots&&
   BigInt(s.selected_tick_ns)<=BigInt(selected)&&BigInt(selected)<BigInt(s.expires_tick_ns),'source');
  const revision=db.prepare('SELECT revision FROM control_state_source WHERE source_id=? AND device_id=?').pluck().get(i.control_state_ref.id,b.device_id);
  need(revision!==undefined,'control');const control=readControlSource(db,b.device_id,String(revision));
  need(same(control.ref,i.control_state_ref)&&control.value.mode==='manual'&&control.value.holder&&
   control.value.pending_operation_id===null&&control.value.gate_state==='protected','control');
  const fence=successor?readCommandClosure(db,i.closing_ref.id.replace(/\.fence_request$/,'')):readInitialFence(db,i.initial_fence_ref.id);
  const confirmation=successor?fence.ack?.ref:fence?.confirmation_ref;
  need(confirmation&&same(confirmation,successor?i.closing_ack_ref:i.initial_confirmation_ref)&&same(fence.ref,successor?i.closing_ref:i.initial_fence_ref),'fence');
  const common={revision:'1',binding:b,control_authority_ref:i.control_authority_ref,initial_resource_ref:source.ref,selected_tick_ns:selected};
  const resourceSafety=signed({format_version:'initial-resource-safety/1',state_id:id+'_resource_safety',...common,state:'clear'},'state_digest');
  const gateSafety=signed({format_version:'initial-gate-safety/1',state_id:id+'_gate_safety',...common,state:'fenced',
   control_state_ref:i.control_state_ref,fence_ref:fence.ref,confirmation_ref:confirmation},'state_digest');
  const resourceSafetyRef=reference(resourceSafety,'state_id','state_digest'),gateSafetyRef=reference(gateSafety,'state_id','state_digest');
  const gate=signed({format_version:'initial-gate-storage/1',gate_id:id+'_gate',revision:'1',binding:b,gate_revision:successor?fence.ack.reply.frame.body.gate_revision:'1',gate_token:id+'_token',
   barrier_id:fence.request.frame.body.barrier_id,phase:'fenced',activation_id:null,lease_until_tick_ns:s.expires_tick_ns,
   gate_safety_ref:gateSafetyRef,confirmation_ref:confirmation},'record_digest');
  const resource=signed({format_version:'initial-resource-state/1',state_id:id+'_resource',revision:'1',binding:b,control_state_ref:i.control_state_ref,
   control_authority_ref:i.control_authority_ref,resource_safety_ref:resourceSafetyRef,provider_source_ref:source.ref,
   sampled_tick_ns:s.selected_tick_ns,expires_tick_ns:s.expires_tick_ns,holds:[],
   run_deny_snapshot:s.deny_snapshots.run_deny_snapshot,command_deny_snapshot:s.deny_snapshots.command_deny_snapshot,reference_time_snapshot:null},'state_digest');
  const access=signed({format_version:'gate-access/0.1.0-draft.1',access_id:id+'_access',revision:'1',purpose:'ordinary',binding:b,
   control_authority_ref:i.control_authority_ref,control_epoch:control.value.control_epoch,effective_version:control.value.effective_version,
   authorization_ref:i.authorization_state_ref,resource_safety_ref:resourceSafetyRef,gate_safety_ref:gateSafetyRef,
   protection:null,initial_assessment_ref:null,selected_tick_ns:selected,expires_tick_ns:s.expires_tick_ns},'access_digest');
  const body={barrier_id:gate.barrier_id,gate_token:gate.gate_token,device_session_id:b.device_session_id,control_epoch:access.control_epoch,
   control_version:access.effective_version,gate_revision:gate.gate_revision,authorization_revision:i.authorization_state_ref.revision,
   clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest,lease_until_tick_ns:gate.lease_until_tick_ns,
   run_deny_snapshot:resource.run_deny_snapshot,command_deny_snapshot:resource.command_deny_snapshot,reference_time_snapshot:null,
   gate_access:access,protection_assessment:null};
  const plan=signed({format_version:'gate-open-plan/0.4.0-product.1',plan_id:id+'_plan',revision:'1',binding:b,
   state_refs:{control:i.control_state_ref,gate:reference(gate,'gate_id','record_digest'),authorization:i.authorization_state_ref,
    resource:reference(resource,'state_id','state_digest')},basis:{kind:'activation',record_ref:i.control_authority_ref},body,
   selected_tick_ns:selected,expires_tick_ns:s.expires_tick_ns},'plan_digest');
  return seal({format:'leafseamer-initial-open/1',id,revision:'1',resource_source_ref:source.ref,authorization_evidence_ref:i.authorization_evidence_ref,
   resource_safety:resourceSafety,gate_safety:gateSafety,gate,resource,access,plan});
 }
 function read(reference){return withExecutionReadView(db,()=>memoExecutionRead(db,'initial-open',reference,()=>readOriginal(reference)));}
 function readOriginal(reference){
  need(db.inTransaction,'writer');const row=db.prepare(`SELECT o.body_jcs,o.body_digest,o.request_id,o.request_digest,o.request_jcs,
   o.binding_id,o.resource_source_id,o.evidence_id,o.fence_id,o.gate_token,o.commit_id,c.body_jcs,c.body_digest,c.audit_jcs
   FROM device_initial_open o JOIN device_initial_open_commit c USING(opening_id,commit_id) WHERE o.opening_id=?`).raw().get(reference?.id);
  need(row,'missing');const value=decode(row[0],row[1]),commit=decode(row[11],row[12]),request=JSON.parse(row[4]);
  need(same(ref(value),reference)&&request.request_id===row[2]&&canonicalize(request)===row[4]&&digest(request)===row[3]&&
   same(request.expected_resource_ref,value.resource_source_ref)&&same(commit.request,request)&&same(commit.opening_ref,reference)&&
   commit.id===row[10]&&commit.format==='initial-device-open-commit/1'&&
   row[13]===canonicalize({kind:'initial_device_open_prepared',opening_ref:reference,commit_ref:ref(commit)}),'integrity');
  const source=resourceRead(value.resource_source_ref),i=source.value.inventory;
  need(request.device_id===source.value.binding.device_id&&row[5]===i.binding_ref.id&&row[6]===source.ref.id&&row[7]===i.authorization_evidence_ref.id&&
   row[8]===i.initial_fence_ref.id&&row[9]===value.gate.gate_token&&same(value,derive(value.id,source,value.plan.selected_tick_ns)),'source_binding');
  return {ref:reference,value,commit};
 }
 function current(reference,dispatchRef=null,readyRef=null,preparedRef=null){
  return withExecutionReadView(db,()=>{
  const saved=read(reference),source=resourceCurrent(saved.value.resource_source_ref,dispatchRef,readyRef,preparedRef),now=domain();
  need(same(saved.value.plan.binding,source.value.binding)&&now.ref.clock_domain_id===source.value.binding.clock_domain_id&&
   now.ref.descriptor_digest===source.value.binding.descriptor_digest&&BigInt(saved.value.plan.selected_tick_ns)<=BigInt(now.tick)&&
   BigInt(now.tick)<BigInt(saved.value.plan.expires_tick_ns),'expired');return {...saved,...(source.prepared_resource?{prepared_resource:source.prepared_resource}:{})};
  });
 }
 attach?.(Object.freeze({current,read,currentReady(reference,dispatchRef,readyRef,preparedRef=null){need(readyRef,'ready');return current(reference,dispatchRef,readyRef,preparedRef);}}));
 return Object.freeze({
  select(request){need(request&&Object.keys(request).sort().join(',')==='device_id,expected_resource_ref,request_id'&&uuid(request.request_id),'input');
   const fixed=structuredClone(request);return freeze(writer(()=>{
    const old=db.prepare('SELECT opening_id,body_digest,request_digest FROM device_initial_open WHERE request_id=?').raw().get(fixed.request_id);
    if(old){need(old[2]===digest(fixed),'conflict');return read({id:old[0],revision:'1',digest:old[1]});}
    // 同一不可变来源已经有计划时，无论资格是否过期，都不能用新请求重新选token。
    // 此分支只拒绝；复核原件后无需再次遍历当前短授权链。
    const selected=db.prepare('SELECT opening_id,body_digest FROM device_initial_open WHERE resource_source_id=?').raw().get(fixed.expected_resource_ref?.id??null);
    if(selected){const prior=read({id:selected[0],revision:'1',digest:selected[1]});
     need(same(prior.value.resource_source_ref,fixed.expected_resource_ref)&&prior.value.plan.binding.device_id===fixed.device_id,'source_binding');
     need(false,'already_selected');}
    const source=withExecutionReadView(db,()=>resourceCurrent(fixed.expected_resource_ref)),i=source.value.inventory;
    need(source.value.binding.device_id===fixed.device_id,'device');
    if(source.value.format!=='leafseamer-device-resource-successor/1')need(!db.prepare('SELECT 1 FROM device_initial_open WHERE binding_id=?').pluck().get(i.binding_ref.id),'already_selected');
    need(db.prepare('SELECT count(*) FROM device_initial_open').pluck().get()<16384,'capacity');
    const now=domain();need(now.ref.clock_domain_id===source.value.binding.clock_domain_id&&now.ref.descriptor_digest===source.value.binding.descriptor_digest,'clock');
    const value=derive(crypto.randomUUID(),source,now.tick),commit=seal({format:'initial-device-open-commit/1',id:crypto.randomUUID(),revision:'1',opening_ref:ref(value),request:fixed});
    const audit=canonicalize({kind:'initial_device_open_prepared',opening_ref:ref(value),commit_ref:ref(commit)}),written=v=>need(v.changes===1,'storage');
    written(db.prepare('INSERT INTO device_initial_open VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(value.id,fixed.request_id,digest(fixed),canonicalize(fixed),
     i.binding_ref.id,source.ref.id,i.authorization_evidence_ref.id,i.initial_fence_ref.id,value.gate.gate_token,canonicalize(value),value.digest,commit.id));
    written(db.prepare('INSERT INTO device_initial_open_commit VALUES(?,?,?,?,?,?)').run(commit.id,value.id,canonicalize(commit),commit.digest,audit,audit));
    const saved=read(ref(value));need(same(saved.value,value)&&same(saved.commit,commit),'readback');
    need(BigInt(domain().tick)<BigInt(value.plan.expires_tick_ns),'expired');return saved;
   }));
  },
  current(reference){return freeze(writer(()=>current(reference)));},lookup(reference){return freeze(writer(()=>read(reference)));}
 });
}
