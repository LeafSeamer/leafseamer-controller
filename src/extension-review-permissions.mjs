import canonicalize from 'canonicalize';
export class PermissionReviewError extends Error {constructor(code){super(code);this.name='PermissionReviewError';this.code=code;}}
export const reviewNeed=(ok,code)=>{if(!ok)throw new PermissionReviewError('extension_review_'+code);};
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const keys=value=>Object.keys(value).sort().join(',');
const sorted=values=>values.every((v,i)=>i===0||Buffer.compare(Buffer.from(canonicalize(values[i-1])),Buffer.from(canonicalize(v)))<0);
// 输入先经过产品Permission Schema；这里只执行不可扩权的关联与集合规则。
export function narrowPermissions(requested,proposed){
 const need=reviewNeed;need(Array.isArray(requested)&&Array.isArray(proposed)&&requested.length<=128&&proposed.length<=128,'permissions');
 const source=new Map(requested.map(p=>[p.request_id,p]));need(source.size===requested.length,'identity');let previous='';
 for(const permission of proposed){
  need(permission.request_id>previous,'order');previous=permission.request_id;const original=source.get(permission.request_id);
  need(original&&keys(permission)===keys(original)&&permission.kind===original.kind&&permission.purpose===original.purpose,'binding');
  need(keys(permission.scope)===keys(original.scope),'scope');
  for(const [key,value] of Object.entries(permission.scope)){
   const old=original.scope[key];
   if(Array.isArray(value)){need(Array.isArray(old)&&sorted(value)&&value.every(item=>old.some(prior=>same(prior,item))),'expansion');}
   else if(key==='quota_bytes'){need(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})(?![\s\S])/.test(value)&&BigInt(value)<=BigInt(old),'expansion');}
   else need(same(value,old),'expansion');
  }
  if(permission.kind==='device_scope')need(permission.scope.action_ids.length+permission.scope.trigger_ids.length>0,'empty_device');
  if(permission.kind==='secret_role')need(permission.scope.devices.length+permission.scope.sources.length>0,'empty_secret');
 }
 const byId=new Map(proposed.map(p=>[p.request_id,p]));
 for(const permission of proposed)if(permission.kind==='protocol_io'){
  const endpoint=byId.get(permission.scope.endpoint_request_id);need(endpoint?.kind==='network_endpoint'&&same(endpoint.scope.profile_ref,permission.scope.profile_ref),'endpoint');
 }
 return structuredClone(proposed);
}
