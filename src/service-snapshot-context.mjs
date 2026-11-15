import {same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
const need=(ok,why)=>{if(!ok)throw new IdentityError('snapshot_context_'+why);};
const N=1000000000n,MAX=(1n<<64n)-1n;
const integer=value=>{need(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(value),'integer');const n=BigInt(value);need(n<=MAX,'integer');return n;};
// 调用者须在同一writer下核当前配对、授权、连接、scope和已发布原件。
export function snapshotContext({saved,input,bootId,registration,snapshot,clock}){
 need(same(input.snapshot_ref,saved.view.snapshot_ref)&&same(registration.scope,saved.view.scope),'binding');
 need(same(clock.runtime_domain_ref,snapshot.domain),'domain');
 const now=integer(clock.tick_ns),bounds=clock.duration_bounds,q=integer(bounds.monotonic_quantization_ns),d=BigInt(bounds.drift_ppb);
 need(q>0n&&Number.isSafeInteger(bounds.drift_ppb)&&d>=0n&&d<=1000000n,'clock');
 const remaining=integer(saved.creation.expires_ns)-integer(clock.upper_ns);need(remaining>0n,'expired');
 // 原授权墙钟上界转换为保守的本域未来耗时，量化余量另扣除。
 const duration=remaining*N/(N+d)-2n*q;need(duration>0n,'expired');
 const deadline=[integer(snapshot.deadline),integer(clock.valid_before_tick_ns),now+duration].reduce((a,b)=>a<b?a:b);
 need(now<deadline&&deadline<=MAX,'expired');
 return {format_version:'snapshot-context/1',challenge_id:input.challenge_id,delivery_binding:structuredClone(saved.view.binding),owner:structuredClone(saved.view.owner),publisher_service_boot_id:bootId,
  snapshot_ref:structuredClone(saved.view.snapshot_ref),projection_profile:structuredClone(registration.profile),selector:structuredClone(registration.selector),
  lease:{publisher_domain_ref:structuredClone(snapshot.domain),observed_tick_ns:String(now),valid_before_tick_ns:String(deadline),clock_policy_ref:structuredClone(bounds.policy_ref),clock_acquisition_ref:structuredClone(clock.acquisition_ref),drift_ppb:bounds.drift_ppb,monotonic_quantization_ns:bounds.monotonic_quantization_ns}};
}
export function checkSnapshotContext(original,current){
 const {lease:a,...left}=original,{lease:b,...right}=current;
 need(same(left,right)&&same(a.publisher_domain_ref,b.publisher_domain_ref)&&same(a.clock_policy_ref,b.clock_policy_ref)&&a.drift_ppb===b.drift_ppb&&a.monotonic_quantization_ns===b.monotonic_quantization_ns,'changed');
 need(integer(b.observed_tick_ns)>=integer(a.observed_tick_ns)&&integer(b.observed_tick_ns)<integer(a.valid_before_tick_ns)&&integer(b.valid_before_tick_ns)>=integer(a.valid_before_tick_ns),'expired');
 return original;
}
