import canonicalize from 'canonicalize';
import {isIP} from 'node:net';
export class RoleResolutionError extends Error {constructor(code){super(code);this.name='RoleResolutionError';this.code=code;}}
export const roleNeed=(ok,code)=>{if(!ok)throw new RoleResolutionError('extension_role_'+code);};
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
const sorted=values=>Array.isArray(values)&&values.every((v,i)=>typeof v==='string'&&(i===0||v>values[i-1]));
const id=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(v);
function reference(v,kind,scope){return exact(v,'kind,authority_service_id,database_instance_id,object_id,revision,digest')&&v.kind===kind&&
 v.authority_service_id===scope.authority_service_id&&v.database_instance_id===scope.database_instance_id&&id(v.object_id)&&
 typeof v.revision==='string'&&/^(0|[1-9][0-9]{0,19})(?![\s\S])/.test(v.revision)&&typeof v.digest==='string'&&/^sha256:[0-9a-f]{64}(?![\s\S])/.test(v.digest);}
function hostValid(host){
 if(typeof host!=='string'||host.length>253||!host.length)return false;
 if(isIP(host)===4)return host.split('.').every(n=>String(Number(n))===n);
 if(isIP(host)===6){try{return new URL('http://['+host+']/').hostname==='['+host+']';}catch{return false;}}
 if(/^[0-9.]+$/.test(host))return false;
 return host.split('.').every(part=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part));
}
// 由安装存储在同一writer快照内调用；current只读实际本地对象，不接收客户端提供者。
export function resolveRolePermissions({manifest,inventory,configuration_ref,bindings,scope,current}){
 const need=roleNeed;need(Array.isArray(bindings)&&bindings.length<=128,'bindings');
 const declarations=new Map(manifest.roles.map(role=>[role.role_id,role])),selected=new Map(),used=new Set(),objects=new Map();
 need(declarations.size===manifest.roles.length&&bindings.length===declarations.size,'set');let previous='';
 for(const binding of bindings){
  need(exact(binding,'role_id,kind,values,configuration_ref')&&id(binding.role_id)&&binding.role_id>previous,'order');previous=binding.role_id;
  const declaration=declarations.get(binding.role_id);
  need(declaration&&declaration.kind===binding.kind&&Array.isArray(binding.values)&&1<=declaration.minimum&&declaration.minimum<=binding.values.length&&
   binding.values.length<=declaration.maximum&&declaration.maximum<=64,'kind_count');
  need(same(binding.configuration_ref,configuration_ref),'configuration');let prior=null;const identities=new Set();
  for(const value of binding.values){
   const encoded=Buffer.from(canonicalize(value));need(prior===null||Buffer.compare(prior,encoded)<0,'value_order');prior=encoded;
   if(binding.kind==='endpoint'){need(exact(value,'host,port')&&hostValid(value.host)&&Number.isInteger(value.port)&&value.port>=1&&value.port<=65535,'endpoint');continue;}
   need(reference(value,binding.kind,scope),'authority');need(!identities.has(value.object_id),'duplicate_object');identities.add(value.object_id);
   const key=canonicalize(value);if(!objects.has(key)){const object=current(value);need(object&&typeof object==='object','object_unavailable');objects.set(key,object);}
  }
  selected.set(binding.role_id,binding);
 }
 const take=(name,kind,single=false)=>{const binding=selected.get(name);need(binding&&binding.kind===kind,'reference');used.add(name);
  need(!single||binding.values.length===1,'single');return single?binding.values[0]:binding.values;};
 const permissions=[];previous='';
 for(const template of manifest.permission_templates){
  const {request_id,kind,purpose,scope:s}=template;need(request_id>previous,'template_order');previous=request_id;
  for(const key of ['action_ids','trigger_ids','method_ids','object_roles','frame_classes'])if(Object.hasOwn(s,key))need(sorted(s[key]),'template_order');
  let out;
  switch(kind){
   case 'device_scope':need(s.action_ids.length+s.trigger_ids.length>0,'empty_device');out={devices:take(s.device_role,'device'),action_ids:s.action_ids,trigger_ids:s.trigger_ids};break;
   case 'data_scope':out={objects:take(s.data_role,'data_object'),access:s.access};break;
   case 'network_endpoint':{const endpoint=take(s.endpoint_role,'endpoint',true);need(s.min_port<=endpoint.port&&endpoint.port<=s.max_port,'endpoint');
    out={transport:s.transport,...endpoint,profile_ref:take(s.protocol_profile_role,'protocol_profile',true)};break;}
   case 'secret_role':out={role_ref:take(s.secret_role,'secret_role',true),devices:s.device_role===null?[]:take(s.device_role,'device'),sources:s.source_role===null?[]:take(s.source_role,'source')};
    need(out.devices.length+out.sources.length>0,'secret_scope');break;
   case 'filesystem_root_role':out={role_ref:take(s.filesystem_role,'filesystem_role',true),access:s.access,quota_bytes:s.quota_bytes};break;
   case 'helper_artifact':{const artifact=take(s.helper_role,'helper_artifact',true),file=inventory.files.find(file=>file.file_id===s.helper_file_id&&file.role==='native_helper');
    const object=objects.get(canonicalize(artifact));need(file&&object&&object.file_id===file.file_id&&object.file_digest===file.digest&&object.artifact_set_digest===manifest.inventory_digest,'helper_binding');
    out={artifact_ref:artifact,launch_profile_ref:take(s.launch_policy_role,'validation_policy',true)};break;}
   case 'panel_method':{need(s.authority===scope.authority,'service_kind');const refs=new Map();
    for(const name of s.object_roles){const type=selected.get(name)?.kind;need(['device','data_object','run'].includes(type),'panel_role');for(const ref of take(name,type))refs.set(canonicalize(ref),ref);}
    out={authority:s.authority,method_ids:s.method_ids,object_refs:[...refs.entries()].sort((a,b)=>Buffer.compare(Buffer.from(a[0]),Buffer.from(b[0]))).map(([,ref])=>ref)};break;}
   case 'protocol_io':out={profile_ref:take(s.protocol_profile_role,'protocol_profile',true),endpoint_request_id:s.endpoint_request_id,frame_classes:s.frame_classes};break;
   default:need(false,'kind');
  }
  permissions.push({request_id,kind,purpose,scope:out});
 }
 need(used.size===declarations.size,'unused');const byId=new Map(permissions.map(p=>[p.request_id,p]));
 for(const permission of permissions)if(permission.kind==='protocol_io'){const endpoint=byId.get(permission.scope.endpoint_request_id);
  need(endpoint?.kind==='network_endpoint'&&same(endpoint.scope.profile_ref,permission.scope.profile_ref),'protocol_binding');}
 return structuredClone(permissions);
}
