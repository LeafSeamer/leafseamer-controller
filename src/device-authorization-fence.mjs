import {DeviceExecutionError} from './device-execution-channel.mjs';

// 输入来自严格解码并核对摘要的Selector及ExecutionGuard；修订达到下界不等于获得授权。
export function authorizationRevoked(binding,selector){
 if(!['session','principal','credential','grant','extension','trust'].includes(selector.kind))throw new DeviceExecutionError('authorization_selector_unsupported');
 if(binding.issuer_id!==selector.issuer_id||binding.issuer_epoch!==selector.issuer_epoch)return false;
 if(selector.kind==='trust')return true;
 if(selector.kind==='credential')return binding.credential_id===selector.target_id;
 const fields={session:['session_id','session_revision'],principal:['principal_id','subject_revision'],grant:['grant_id','grant_revision'],extension:['extension_instance_id','extension_approval_revision']};
 const [id,revision]=fields[selector.kind];return binding[id]!==null&&binding[id]===selector.target_id&&BigInt(binding[revision])<BigInt(selector.revision_floor);
}
