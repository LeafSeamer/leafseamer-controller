import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
const need=(ok,reason)=>{if(!ok)throw new IdentityError('snapshot_'+reason);};
const hash=value=>digest(value).slice(7),format_version='snapshot-projection/0.2.0-draft.1';
export const snapshotBudget=Object.freeze({page:245760,response:262144,total:8388608,pages:128,build:5000000000n,apply:30000000000n});
// 输入只能来自批准scope的一致读切点；本函数不查询设备或产生采样证据。
export function sealSourceSnapshot({view,cut,snapshotId,domainRef,createdAt,expiresAt}){
 const {scope,binding:subscriptionBinding}=view,registration=cut.registration;
 const profileRef=scope.projection_profile_ref;
 need((view.purpose==='canonical_trigger'&&view.owner.kind==='service'||view.purpose==='status_projection'&&view.owner.kind==='human')&&
  view.purpose===registration.purpose&&same(scope,registration.scope)&&same(profileRef,registration.selector.profile_ref)&&
  subscriptionBinding.scope_digest===hash(scope)&&subscriptionBinding.publisher_service_id===profileRef.authority_service_id&&
  subscriptionBinding.publisher_database_instance_id===profileRef.database_instance_id,'scope');
 need(registration.profile.owner_kinds.includes(view.owner.kind)&&registration.profile.purposes.includes(view.purpose),'profile');
 need(registration.profile.collections.length===1&&registration.profile.collections[0].entity_kind==='sources'&&scope.collections.length===1&&scope.collections[0].entity_kind==='sources','profile');
 const selected=registration.selector.entity_ids;
 need(Array.isArray(selected)&&selected.length>=1&&selected.length<=32&&new Set(selected).size===selected.length,'scope');
 need(cut.records.length===selected.length&&cut.source_watermarks.length===selected.length,'coverage');
 const records=structuredClone(cut.records).sort((a,b)=>a.entity_id<b.entity_id?-1:a.entity_id>b.entity_id?1:0),watermarks=[];
 need(new Set(records.map(r=>r.entity_id)).size===selected.length,'duplicate');
 for(const record of records){
  need(record.entity_kind==='sources'&&selected.includes(record.entity_id)&&record.entity_id===record.view.source_key.registration_id&&record.entity_epoch===record.view.source_key.source_epoch,'record');
  const marks=cut.source_watermarks.filter(w=>same(w.source_key,record.view.source_key));need(marks.length===1,'watermark');
  const expected={source_key:record.view.source_key,binding_ref:record.view.binding_ref,baseline_sequence:record.view.contiguous_sequence,source_state_revision:record.entity_revision,baseline_ref:record.view.baseline_ref,gap_summary:record.view.gaps};
  need(same(marks[0],expected),'watermark');watermarks.push(expected);
 }
 const {connection_generation,...delivery}=subscriptionBinding,binding={snapshot_id:snapshotId,...delivery,projection_profile_ref:profileRef,publisher_domain_ref:domainRef};
 const content=(index,items,next)=>({format_version,binding,page_index:index,next_page_index:next,records:items});
 const groups=[];let group=[];
 for(const record of records){const candidate=[...group,record];if(Buffer.byteLength(canonical(content(groups.length,candidate,127)))>snapshotBudget.page){need(group.length>0,'record_capacity');groups.push(group);group=[];}
  group.push(record);need(Buffer.byteLength(canonical(content(groups.length,group,127)))<=snapshotBudget.page,'record_capacity');}
 groups.push(group);need(groups.length<=snapshotBudget.pages,'capacity');
 const pages=groups.map((items,index)=>{const value=content(index,items,index+1<groups.length?index+1:null),body=canonical(value);return {page_index:index,body,content_digest:hash(value),content_bytes:Buffer.byteLength(body)};});
 const unsigned={format_version,binding,snapshot_cursor:'0',collections:[{entity_kind:'sources',count:String(records.length),view_schema_ref:registration.profile.collections[0].view_schema_ref}],
  source_watermarks:watermarks,pages:pages.map(({page_index,content_digest,content_bytes})=>({page_index,content_digest,content_bytes})),page_count:pages.length,total_content_bytes:pages.reduce((sum,p)=>sum+p.content_bytes,0),created_at:createdAt,expires_at:expiresAt};
 need(Number.isFinite(Date.parse(createdAt))&&Date.parse(expiresAt)>Date.parse(createdAt),'dates');
 const manifest={...unsigned,manifest_digest:hash(unsigned)},manifestBody=canonical(manifest);
 // 下载时换上实际连接代际；按U20最大长度预留信封空间。
 const deliveryBinding={...view.binding,connection_generation:'18446744073709551615'};
 let storedBytes=Buffer.byteLength(manifestBody);
 for(const page of pages){const bytes=Buffer.byteLength(canonical({manifest_digest:manifest.manifest_digest,content_digest:page.content_digest,content:JSON.parse(page.body),delivery_binding:deliveryBinding}));need(bytes<=snapshotBudget.response,'page_capacity');storedBytes+=bytes;}
 need(storedBytes<=snapshotBudget.total,'capacity');
 const snapshotRef={snapshot_id:snapshotId,manifest_digest:manifest.manifest_digest,snapshot_cursor:'0'},marker={entry_kind:'snapshot.baseline',payload:snapshotRef};
 return {manifest,manifestBody,pages,storedBytes,snapshotRef,markerBody:canonical(marker),markerDigest:hash(marker)};
}
