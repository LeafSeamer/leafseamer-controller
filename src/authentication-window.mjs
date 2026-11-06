import {checked,seal,ref,same,extrapolate} from './auth-clock-value.mjs';
import {clockInteger} from './native-clock.mjs';
import {IdentityError} from './identity-crypto.mjs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
const need=(v,c)=>{if(!v)throw new IdentityError('authentication_window_'+c);};
const N=1000000000n;
const minimum=(...values)=>values.reduce((a,b)=>a<b?a:b);
function original(db,reference){
 const row=db.prepare('SELECT body,digest,service_boot_id,clock_domain_id FROM authentication_clock_acquisition WHERE id=? AND revision=?').raw().get(reference?.id,reference?.revision);
 need(row,'missing');const text=row[0].toString(),v=checked(JSON.parse(text));
 need(canonicalize(v)===text&&same(ref(v),reference)&&v.digest===row[1]&&v.service_boot_id===row[2]&&v.clock_domain_id===row[3],'integrity');return v;
}
function evidence(db,reference,kind){const row=db.prepare('SELECT body,kind,digest FROM authentication_clock_evidence WHERE id=? AND revision=?').raw().get(reference.id,reference.revision);
 need(row&&row[1]===kind,'evidence');const text=row[0].toString(),v=checked(JSON.parse(text));need(canonicalize(v)===text&&same(ref(v),reference)&&row[2]===v.digest,'integrity');return v;}
function resolve({db,service,coreRuntime,acquisitionRef,domain},selecting){
 need(db.inTransaction,'writer');const a=original(db,acquisitionRef),boot=coreRuntime.value.service_boot_id;
 need(a.service_id===service.service_id&&a.service_boot_id===boot&&same(coreRuntime.value.domain_ref,domain)&&
  domain.clock_domain_id==='clock_'+domain.descriptor_digest?.slice(7)&&a.clock_domain_id===domain.clock_domain_id&&a.descriptor_digest===domain.descriptor_digest,'domain');
 need(!db.prepare('SELECT 1 FROM authentication_clock_fault WHERE service_boot_id=? AND clock_domain_id=?').pluck().get(boot,a.clock_domain_id),'fault');
 const head=db.prepare('SELECT a.id,a.revision,a.digest FROM authentication_clock_head h JOIN authentication_clock_acquisition a ON a.id=h.acquisition_id WHERE h.service_boot_id=? AND h.clock_domain_id=?').raw().get(boot,a.clock_domain_id);
 need(head,'head');const current=original(db,{id:head[0],revision:head[1],digest:head[2]});
 need((!selecting||same(ref(current),acquisitionRef))&&same(current.runtime_ref,a.runtime_ref)&&same(current.policy_ref,a.policy_ref),'changed');
 const p=evidence(db,a.policy_ref,'policy'),r=evidence(db,a.runtime_ref,'runtime'),h=evidence(db,a.health_evidence_ref,'health');
 need(r.service_id===service.service_id&&r.service_boot_id===boot&&r.clock_domain_id===domain.clock_domain_id&&r.descriptor_digest===domain.descriptor_digest&&
  h.service_boot_id===boot&&h.clock_domain_id===domain.clock_domain_id&&same(r.policy_ref,ref(p))&&same(h.runtime_ref,ref(r))&&same(h.policy_ref,ref(p))&&
  a.drift_ppb===p.drift_ppb&&Number.isSafeInteger(a.drift_ppb)&&a.drift_ppb>=0&&a.drift_ppb<=1000000,'binding');
 return {a,r,h};
}
function project(input,resolved,id){
 const {a,r,h}=resolved,selected=clockInteger(input.selectedTick),start=clockInteger(input.validFrom),end=clockInteger(input.validBefore),cap=clockInteger(input.capTick);
 const bounds=extrapolate(a,selected);need(clockInteger(bounds.lower_ns)>=start&&clockInteger(bounds.upper_ns)<end,'validity');
 const upper=clockInteger(a.effective_upper_ns),b=clockInteger(a.b);need(end>upper,'validity');
 // ceil(dt*(N+d)/N) <= end-U-1；最后一个可用整数tick之后即为半开截止。
 const utcDeadline=b+(end-upper-1n)*N/(N+BigInt(a.drift_ppb))+1n;
 const before=minimum(utcDeadline,clockInteger(a.valid_before_tick_ns),clockInteger(r.valid_before_tick_ns),clockInteger(h.valid_before_tick_ns),cap);
 need(selected<before,'expired');
 return seal({format:'authentication-monotonic-window/1',id,revision:'1',service_id:input.service.service_id,service_boot_id:a.service_boot_id,
  domain_ref:input.domain,acquisition_ref:input.acquisitionRef,policy_ref:a.policy_ref,runtime_ref:a.runtime_ref,health_ref:a.health_evidence_ref,
  selected_tick_ns:String(selected),before_tick_ns:String(before),cap_tick_ns:String(cap),valid_from_ns:String(start),valid_before_ns:String(end),
  selected_lower_ns:bounds.lower_ns,selected_upper_ns:bounds.upper_ns});
}
export function selectAuthenticationWindow(input){return project(input,resolve(input,true),crypto.randomUUID());}
export function currentAuthenticationWindow(input,window,nowTick){
 checked(window);need(window.format==='authentication-monotonic-window/1','format');
 const expected=project(input,resolve(input,false),window.id);need(same(expected,window),'changed');
 const now=clockInteger(nowTick);need(now>=clockInteger(window.selected_tick_ns)&&now<clockInteger(window.before_tick_ns),'expired');return window;
}
