import {createHash} from 'node:crypto';
import canonicalize from './runtime/canonicalize.mjs';
import {referenceTimeScheduler} from './reference-time-scheduler.mjs';

export function openReferenceCaptureRuntime({storage, authorization, authentication, link, assertCurrent,
  allowSourceReplacement=false, observeRetirement, assertRetirement}){
  const polls = storage.openTimeProviderPolls({
    limits: authorization.limits,
    allowSourceReplacement,
    readSource: slot=>authorization.readSource(slot,authentication),
    readAuthentication: () => authentication.referenceTimeSample(),
    assertCurrent,
    observeRetirement, assertRetirement
  });
  const {readEndpoint, captureProtection, referenceAuthority, schedule} = authorization;
  if (readEndpoint !== undefined && typeof readEndpoint !== 'function') throw new Error('time_provider_poll_endpoint_authority');
  if (referenceAuthority !== undefined && !readEndpoint) throw new Error('reference_time_authority');
  const publication = referenceAuthority===undefined ? null : storage.openReferenceTimeAnchor({...referenceAuthority,readContext:polls.referenceContext});
  const archive = readEndpoint ? storage.openTimeProviderCapture(captureProtection,publication) : null;
  function collect(pollRef, scheduled = null) {
    return link.collect(() => {
      let stored;
      if (!scheduled) {
        stored = polls.lookup(pollRef?.id);
        if (!stored || stored.digest !== pollRef.digest || stored.reservation.service_boot_id !== storage.serviceBootId) {
          throw new Error('time_provider_poll_identity_conflict');
        }
        if (stored.attempt) throw new Error('time_provider_poll_already_attempted');
      }
      const endpoint = (scheduled?.authorization??stored.reservation.authorization).endpoint_ref;
      const encoded = canonicalize(readEndpoint(Object.freeze({...endpoint})));
      if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > 12000 ||
          'sha256:' + createHash('sha256').update(encoded).digest('hex') !== endpoint.digest) {
        throw new Error('time_provider_poll_endpoint_binding');
      }
      archive.assertWritable();
      if (scheduled) {
        stored=polls.reserve(scheduled.slot,scheduled.id,scheduled.authorization);
        pollRef={id:scheduled.id,digest:stored.digest};
      }
      const attempt = polls.markAttempt(pollRef);
      const reservation = stored.reservation, network=JSON.parse(encoded), authorize = () => polls.authorizeAttempt(attempt);
      return {reservation, attempt, network, authorize,
        ...(polls.storeControl && {storeControl:control=>polls.storeControl(attempt,control),releaseControl:polls.releaseControl}),
        archive: (candidate,ntsBootstrap) => archive.store({reservation,attempt,candidate,authorize,network,ntsBootstrap}),
        release: (receipt,acknowledgement) => archive.release({receipt,acknowledgement,reservation,assertCurrent})};
    });
  }
  let scheduler=null;
  if(schedule!==undefined) {
    if(!schedule || Object.keys(schedule).join(',')!=='sourceSlots' || !archive || !polls.schedulePlan) {
      throw new Error('reference_time_schedule_authority');
    }
    scheduler=referenceTimeScheduler(schedule,{plan:polls.schedulePlan,recover:polls.recover,
      collect:(slot,id,authorization)=>collect(null,{slot,id,authorization})});
  }
  const api = Object.freeze({lookup: polls.lookup, reserve:(slot,id)=>polls.reserve(slot,id), markAttempt: polls.markAttempt,
    ...(polls.recover && {recover: polls.recover}),
    ...(publication && {currentReference:publication.current,projectReferenceCapture:publication.projectCapture,readReferenceBundle:publication.readBundle,
      receiverReference:publication.receiverReference}),
    ...(publication?.protectionStatus && {referenceProtectionStatus:publication.protectionStatus}),
    ...(publication?.protectionFenceSource && {referenceProtectionFenceSource:publication.protectionFenceSource}),
    ...(scheduler && {scheduleStatus:scheduler.status}),
    ...(archive && {lookupCapture: archive.lookup, readCapture: archive.read, async collect(pollRef){return collect(pollRef);}})
  });
  return {api,publication,scheduler};
}
