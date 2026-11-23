import {createHash, randomUUID} from 'node:crypto';
import canonicalize from 'canonicalize';
import {clockInteger} from './native-clock.mjs';
import {decodeReferenceBundle,encodeReferenceBundle,referencePacketSummary,validateReferenceBundle} from './reference-time-bundle.mjs';

const fraction = 1n << 32n;
const billion = 1000000000n;
const million = 1000000n;
const ntpEpoch = 2208988800n;
// Fixed-point UTC numerators use 2^32 units per nanosecond.
const eraSpan = fraction * billion * fraction;
const signed = /^(0|-?[1-9][0-9]{0,29})$/;
const hash = /^sha256:[0-9a-f]{64}$/;
const id = /^[A-Za-z0-9_.:-]{1,128}$/;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',')===keys;
const matches = (pattern, value) => typeof value==='string' && value.trim()===value && pattern.test(value);
const digest = value => 'sha256:' + createHash('sha256').update(value).digest('hex');
const same = (left,right) => canonicalize(left)===canonicalize(right);
const floor = (n,d) => n<0n ? (n-d+1n)/d : n/d;
const ceil = (n,d) => -floor(-n,d);
const pad = tick => String(tick).padStart(20,'0');

class Unqualified extends Error {}
const requireQualified = ok => { if(!ok) throw new Unqualified('reference_time_unqualified'); };

function utc(value) {
  requireQualified(matches(signed,value));
  return BigInt(value);
}

function reference(value) {
  requireQualified(exact(value,'digest,id,revision') && matches(id,value.id) && matches(hash,value.digest) && clockInteger(value.revision)>0n);
}

function normalize(value) {
  const encoded = canonicalize(value);
  requireQualified(typeof encoded==='string' && Buffer.byteLength(encoded)<=8192);
  return JSON.parse(encoded);
}

function approval(value, context) {
  const p = normalize(value);
  requireQualified(exact(p,'approval_ref,authentication,configuration_ref,elapsed_error_ppm,format,leap_mode,max_anchor_age_ns,max_exchange_age_ns,max_half_width_ns,max_span_ns,max_upstream_age_ns,policy_ref,profile_ref,smear,source_digest,span_quantization_ns,time_scale,valid_before_tick_ns') &&
    p.format==='leafseamer-reference-approval/1' && ['nts','trusted_network'].includes(p.authentication) && p.time_scale==='UTC' &&
    p.leap_mode==='normal_only' && p.smear===false && Number.isSafeInteger(p.elapsed_error_ppm) && p.elapsed_error_ppm>=0 &&
    p.elapsed_error_ppm<million && p.source_digest===context.facts.source_digest &&
    same(p.configuration_ref,context.facts.configuration_ref) && same(p.approval_ref,context.facts.approval_ref) &&
    context.tick < clockInteger(p.valid_before_tick_ns));
  for (const key of ['approval_ref','configuration_ref','policy_ref','profile_ref']) reference(p[key]);
  for (const key of ['max_anchor_age_ns','max_exchange_age_ns','max_half_width_ns','max_span_ns','max_upstream_age_ns','span_quantization_ns']) {
    requireQualified(clockInteger(p[key])>0n);
  }
  return p;
}

function evidence(value, expected, p, context) {
  const e = normalize(value);
  requireQualified(exact(e,'authentication_ref,era_ref,error_ref,exchange_digest,format,independent_utc_lower_ns,independent_utc_upper_ns,t2_error_ns,t3_error_ns,upstream_age_at_m1_ns,valid_before_tick_ns') &&
    e.format==='leafseamer-reference-evidence/1' && e.exchange_digest===expected && context.tick<clockInteger(e.valid_before_tick_ns));
  for (const key of ['authentication_ref','error_ref','era_ref']) reference(e[key]);
  requireQualified(utc(e.independent_utc_lower_ns)<=utc(e.independent_utc_upper_ns));
  requireQualified(clockInteger(e.upstream_age_at_m1_ns)<clockInteger(p.max_upstream_age_ns));
  return e;
}

function elapsed(delta, p) {
  const error = BigInt(p.elapsed_error_ppm), quantization = clockInteger(p.span_quantization_ns)*million;
  const lower = delta*(million-error)-quantization;
  return {lower:lower<0n?0n:lower,upper:delta*(million+error)+quantization};
}

function timestamp(bytes, offset, lower, upper, error) {
  const seconds = BigInt(bytes.readUInt32BE(offset)), fractional = BigInt(bytes.readUInt32BE(offset+4));
  const base = ((seconds-ntpEpoch)*fraction+fractional)*billion;
  const earliest = ceil((lower-error)*fraction-base,eraSpan);
  const latest = floor((upper+error)*fraction-base,eraSpan);
  requireQualified(earliest===latest && earliest>=-2147483648n && earliest<=2147483647n && (seconds!==0n || fractional!==0n));
  return {value:base+earliest*eraSpan,era:String(earliest),seconds:String(seconds),fraction:String(fractional)};
}

function derive(candidate, p, e) {
  const m1=clockInteger(candidate.m1_tick_ns), m4=clockInteger(candidate.m4_tick_ns);
  requireQualified(m4>=m1 && m4-m1<=clockInteger(p.max_span_ns));
  const lower=utc(e.independent_utc_lower_ns), upper=utc(e.independent_utc_upper_ns);
  const e2=clockInteger(e.t2_error_ns), e3=clockInteger(e.t3_error_ns);
  const bytes = Buffer.from(candidate.response,'base64url');
  try {
    const t2=timestamp(bytes,32,lower,upper,e2), t3=timestamp(bytes,40,lower,upper,e3);
    requireQualified(t2.value<=t3.value);
    const L=floor(t3.value-e3*fraction,fraction);
    const U=ceil((t2.value+e2*fraction)*million+elapsed(m4-m1,p).upper*fraction,fraction*million);
    requireQualified(L<=U);
    const word = ({era,seconds,fraction})=>({era,seconds,fraction});
    return {lower_utc_ns:String(L),upper_utc_ns:String(U),t2:word(t2),t3:word(t3)};
  } finally { bytes.fill(0); }
}

function assess(anchor, context) {
  const {tick} = context, p=anchor.approval, e=anchor.evidence;
  const m1=clockInteger(anchor.m1_tick_ns), m4=clockInteger(anchor.m4_tick_ns);
  requireQualified(tick>=m4 && tick<clockInteger(p.valid_before_tick_ns) && tick<clockInteger(e.valid_before_tick_ns));
  const sinceAnchor=elapsed(tick-m4,p), sinceExchange=elapsed(tick-m1,p);
  const a=ceil(sinceAnchor.upper,million), x=ceil(sinceExchange.upper,million), u=clockInteger(e.upstream_age_at_m1_ns)+x;
  const lower=utc(anchor.lower_utc_ns)+floor(sinceAnchor.lower,million), upper=utc(anchor.upper_utc_ns)+a;
  requireQualified(a<clockInteger(p.max_anchor_age_ns) && x<clockInteger(p.max_exchange_age_ns) &&
    u<clockInteger(p.max_upstream_age_ns) && upper-lower<=2n*clockInteger(p.max_half_width_ns));
  return {status:'conditional',tick_ns:String(tick),lower_utc_ns:String(lower),upper_utc_ns:String(upper),
    anchor_age_ns:String(a),exchange_age_ns:String(x),upstream_age_ns:String(u)};
}

function anchorRecord(row) {
  if(!row) return null;
  const body=JSON.parse(row[0]);
  if(canonicalize(body)!==row[0] || digest(row[0])!==row[1]) throw new Error('reference_time_anchor_integrity');
  return {body,digest:row[1]};
}

function acceptedProjection(record, accepted) {
  const tick=clockInteger(accepted.tick_ns), {body}=record;
  requireQualified(tick>=clockInteger(body.published_tick_ns));
  const assessment=assess(body,{tick});
  const midpointMs=floor(BigInt(assessment.lower_utc_ns)+BigInt(assessment.upper_utc_ns),2000000n);
  requireQualified(midpointMs>=-62167219200000n && midpointMs<=253402300799999n);
  return {format:'leafseamer-command-reference-acceptance/1',anchor_ref:{id:body.anchor_id,revision:'1',digest:record.digest},
    domain_ref:accepted.domain,...assessment,accepted_at:new Date(Number(midpointMs)).toISOString()};
}

export function verifyCommandReferenceAcceptance(db, observed, accepted, ipcSessionId) {
  if(!observed || !observed.anchor_ref) return false;
  const row=db.prepare(`SELECT a.body_jcs,a.body_digest,r.body_jcs,r.body_digest FROM time_provider_reference_anchor a
    JOIN time_provider_runtime_binding r USING(service_boot_id) JOIN execution_session s USING(service_boot_id)
    WHERE a.anchor_id=? AND a.body_digest=? AND s.ipc_session_id=?`).raw().get(observed.anchor_ref.id,observed.anchor_ref.digest,ipcSessionId);
  if(!row) return false;
  const record=anchorRecord(row), runtime=anchorRecord(row.slice(2));
  const {clock_domain_id,descriptor_digest}=runtime.body.clock_domain_descriptor;
  if(record.body.runtime_digest!==runtime.digest || !same(accepted.domain,{clock_domain_id,descriptor_digest})) return false;
  try { return same(observed,acceptedProjection(record,accepted)); }
  catch { return false; }
}

export function referenceTimeAnchorStore(db, bootId, binding, {sourceSlot, readApproval, readEvidence, readContext, readBundleOriginals}, invalidation = null) {
  if (!matches(id,sourceSlot) || typeof readApproval!=='function' || typeof readEvidence!=='function' || typeof readContext!=='function' ||
      (readBundleOriginals!==undefined&&typeof readBundleOriginals!=='function')) {
    throw new Error('reference_time_authority');
  }
  const latest = db.prepare('SELECT body_jcs,body_digest FROM time_provider_reference_anchor WHERE service_boot_id=? ORDER BY rowid DESC LIMIT 1').raw();
  let withdrawn=false;

  function head() {
    return anchorRecord(latest.get(bootId));
  }

  function sealBundle(anchor){
    if(!readBundleOriginals)return null;
    try{
      const runtime=JSON.parse(binding.text),packet={...anchor.packet_summary,t2:anchor.t2,t3:anchor.t3};
      const context={anchor,runtime,packet,assessment:assess(anchor,{tick:clockInteger(anchor.m4_tick_ns)})};
      return encodeReferenceBundle(validateReferenceBundle(readBundleOriginals(structuredClone(context)),context));
    }catch{return null;}
  }

  function withdraw(prior,cause) {
    withdrawn=true;
    invalidation?.deny(prior,cause);
  }

  function context() {
    const before=readContext(sourceSlot);
    const p=approval(readApproval(Object.freeze({source_slot:sourceSlot,runtime_digest:binding.digest,
      authorization:JSON.parse(canonicalize(before.facts))})),before);
    const now=readContext(sourceSlot);
    requireQualified(now.tick>=before.tick && same(now.facts,before.facts) && now.tick<clockInteger(p.valid_before_tick_ns));
    return {now,p};
  }

  function authority(prior) {
    try {
      const current=context();
      requireQualified(!prior || (same(prior.body.approval,current.p) && same(prior.body.authorization,current.now.facts)));
      return current;
    } catch (error) {
      if(prior) withdraw(prior,'authority_changed');
      throw error;
    }
  }

  function acquireEvidence({poll_ref,attempt_id,plaintext_digest,m1_tick_ns,m4_tick_ns,packet_summary}, {p,now}) {
    const bindingFields={poll_ref,attempt_id,runtime_digest:binding.digest,approval_ref:p.approval_ref,
      profile_ref:p.profile_ref,policy_ref:p.policy_ref,plaintext_digest};
    const exchangeDigest=digest(canonicalize(bindingFields));
    const verified=evidence(readEvidence({...structuredClone(bindingFields),exchange_digest:exchangeDigest,
      source_digest:p.source_digest,authentication:p.authentication,m1_tick_ns,m4_tick_ns,
      ...(packet_summary&&{packet:structuredClone(packet_summary),runtime:JSON.parse(binding.text),endpoint_ref:structuredClone(now.facts.endpoint_ref)})}),exchangeDigest,p,now);
    requireQualified(verified.era_ref.digest!==plaintext_digest && verified.era_ref.digest!==exchangeDigest);
    return verified;
  }

  function qualification() {
    if(withdrawn) { invalidation?.flush(); return null; }
    const record=head();
    if(!record) return null;
    let current;
    try { current=authority(record); assess(record.body,current.now); }
    catch { return null; }
    try { requireQualified(same(record.body.evidence,acquireEvidence(record.body,current))); }
    catch { withdraw(record,'evidence_withdrawn'); return null; }
    try {
      current=authority(record);
      return {record,now:current.now,assessment:assess(record.body,current.now)};
    } catch { return null; }
  }

  function storedBundle(record,runtime) {
    const saved=record.body.reference_bundle;
    requireQualified(saved && runtime.digest===record.body.runtime_digest);
    return validateReferenceBundle(decodeReferenceBundle(saved),{anchor:record.body,runtime:runtime.body,
      packet:{...record.body.packet_summary,t2:record.body.t2,t3:record.body.t3},
      assessment:assess(record.body,{tick:clockInteger(record.body.m4_tick_ns)})});
  }

  function bundleRecord(anchorId) {
    const row=db.prepare(`SELECT a.body_jcs,a.body_digest,r.body_jcs,r.body_digest FROM time_provider_reference_anchor a
      JOIN time_provider_runtime_binding r USING(service_boot_id) WHERE a.anchor_id=?`).raw().get(anchorId);
    return row ? {record:anchorRecord(row),runtime:anchorRecord(row.slice(2))} : null;
  }

  function receiverDeadline(record,now) {
    const {approval,evidence}=record.body;
    const authority=clockInteger(approval.valid_before_tick_ns),proof=clockInteger(evidence.valid_before_tick_ns);
    const expires=authority<proof?authority:proof;
    return now.deadline<expires?now.deadline:expires;
  }

  // 读取接收方自己已经提交的原件。历史包的 m4 或评估时刻不能替代发布时刻。
  const receiverReference=Object.freeze({
    readFirst({tick_ns,runtime_domain_ref}) {
      try {
        const tick=clockInteger(tick_ns),live=qualification();
        if(!live || !same(runtime_domain_ref,live.now.sample.runtime_domain_ref)) return null;
        const {record,now}=live;
        requireQualified(tick<=now.tick && tick>=clockInteger(record.body.published_tick_ns));
        assess(record.body,{tick});
        const original=storedBundle(record,anchorRecord([binding.text,binding.digest]));
        return {service_boot_id:bootId,valid_before_tick_ns:String(receiverDeadline(record,now)),...original};
      } catch { return null; }
    },
    isCurrent({first_tick_ns,tick_ns,reference}) {
      try {
        const first=clockInteger(first_tick_ns),tick=clockInteger(tick_ns),deadline=clockInteger(reference.valid_before_tick_ns);
        if(reference.service_boot_id!==bootId || first>tick || tick>=deadline || !matches(id,reference.bundle?.bundle_id))return false;
        const live=qualification(),stored=bundleRecord(reference.bundle.bundle_id);
        if(!live||!stored||stored.record.body.service_boot_id!==bootId||stored.runtime.digest!==binding.digest)return false;
        const {record,runtime}=stored,{now}=live,{body}=record;
        requireQualified(tick<=now.tick && now.tick<deadline && deadline<=receiverDeadline(record,now) &&
          first>=clockInteger(body.published_tick_ns) && same(body.authorization,live.record.body.authorization) &&
          same(body.approval,live.record.body.approval));
        assess(body,{tick:first});
        assess(body,now);
        const original=storedBundle(record,runtime);
        return same(reference.bundle,original.bundle)&&same(reference.state,original.state)&&
          (record.digest===live.record.digest || same(body.evidence,acquireEvidence(body,{now,p:live.record.body.approval})));
      } catch { return false; }
    }
  });

  return Object.freeze({
    receiverReference,
    ...(invalidation && {protectionStatus:invalidation.status,reconcileProtection:invalidation.reconcile,
      invalidate(cause) { withdraw(head(),cause); }}),
    prepare({reservation,candidate,receipt,network,attempt}) {
      if(withdrawn || reservation.source_slot!==sourceSlot) return null;
      const prior=head();
      try {
        const current=authority(prior), {now,p}=current;
        requireQualified(same(now.facts,reservation.authorization) && network.authentication===p.authentication);
        const packet_summary=readBundleOriginals?referencePacketSummary(candidate,attempt.valid_before_tick_ns):null;
        const e=acquireEvidence({...receipt,packet_summary},current);
        const result=derive(candidate,p,e);
        const body={format:'leafseamer-reference-anchor/1',model:'reference-bound/1',anchor_id:randomUUID(),service_boot_id:bootId,
          runtime_digest:binding.digest,source_slot:sourceSlot,authorization:now.facts,approval:p,evidence:e,...receipt,...result,
          ...(packet_summary&&{packet_summary})};
        assess(body,now);
        const bundle=sealBundle(body);
        if(bundle)body.reference_bundle=bundle;
        return body;
      } catch { return null; }
    },
    commit(proposed, remainingBytes) {
      if (!proposed || withdrawn) return;
      if (!db.inTransaction) throw new Error('reference_time_anchor_writer');
      const prior=head();
      let current;
      try {
        current=authority(prior);
        requireQualified(same(proposed.approval,current.p) && same(proposed.authorization,current.now.facts) && (!prior ||
          clockInteger(proposed.m4_tick_ns)>clockInteger(prior.body.m4_tick_ns)));
        requireQualified(same(proposed.evidence,acquireEvidence(proposed,current)));
        current=authority(prior);
        requireQualified(same(proposed.approval,current.p) && same(proposed.authorization,current.now.facts));
        assess(proposed,current.now);
      } catch { return; }
      const body={...proposed,previous_anchor_digest:prior?.digest??null,published_tick_ns:String(current.now.tick)};
      const limit=Math.min(remainingBytes,16384);
      let text=canonicalize(body);
      if(Buffer.byteLength(text)>limit&&body.reference_bundle){delete body.reference_bundle;text=canonicalize(body);}
      if(Buffer.byteLength(text)>limit) return;
      if (db.prepare('INSERT INTO time_provider_reference_anchor VALUES (?,?,?,?,?,?,?,?,?)').run(body.anchor_id,bootId,body.poll_ref.id,
        body.capture_ref.id,body.capture_ref.digest,pad(clockInteger(body.m4_tick_ns)),body.previous_anchor_digest,text,digest(text)).changes!==1) {
        throw new Error('reference_time_anchor_storage');
      }
    },
    current() {
      const live=qualification();
      if(!live) return null;
      return {...live.assessment,anchor_ref:{id:live.record.body.anchor_id,revision:'1',digest:live.record.digest},
        ...(live.record.body.reference_bundle&&{bundle_ref:{id:live.record.body.anchor_id,revision:'1',digest:live.record.body.reference_bundle.digest}}),
        runtime_domain_ref:live.now.sample.runtime_domain_ref};
    },
    readBundle(reference){
      if(!reference||reference.revision!=='1'||!matches(id,reference.id)||!matches(hash,reference.digest))return null;
      const stored=bundleRecord(reference.id);
      if(stored?.record.body.reference_bundle?.digest!==reference.digest)return null;
      return storedBundle(stored.record,stored.runtime).bundle;
    },
    projectCapture(capture) {
      if (!exact(capture,'after_tick_ns,before_tick_ns,domain') ||
          !exact(capture.domain,'clock_domain_id,descriptor_digest')) return null;
      let before, after;
      try {
        before=clockInteger(capture.before_tick_ns);
        after=clockInteger(capture.after_tick_ns);
      } catch { return null; }
      if (after<before) return null;

      const live=qualification();
      if (!live || after>live.now.tick || !same(capture.domain,live.now.sample.runtime_domain_ref)) return null;
      const {body,digest}=live.record;
      try {
        requireQualified(before>=clockInteger(body.published_tick_ns));
        const start=assess(body,{tick:before}), end=assess(body,{tick:after});
        return {anchor_ref:{id:body.anchor_id,revision:'1',digest},
          runtime_domain_ref:{...live.now.sample.runtime_domain_ref},
          elapsed_profile_ref:{...body.approval.profile_ref},
          ...(body.reference_bundle&&{reference_context_ref:{id:body.anchor_id,revision:'1',digest:body.reference_bundle.digest}}),
          before_tick_ns:start.tick_ns,after_tick_ns:end.tick_ns,
          lower_utc_ns:start.lower_utc_ns,upper_utc_ns:end.upper_utc_ns};
      } catch { return null; }
    },
    acceptAt(accepted) {
      if(!db.inTransaction) throw new Error('reference_time_acceptance_writer');
      const live=qualification();
      if(!live || !same(accepted.domain,live.now.sample.runtime_domain_ref) || clockInteger(accepted.tick_ns)>live.now.tick) return null;
      try { return acceptedProjection(live.record,accepted); }
      catch { return null; }
    }
  });
}
