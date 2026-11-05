import {hash} from './extension-installation.mjs';
export function bind(storage,platform={profile_id:'synthetic-profile',revision:'1'}){
  const identity=storage.identity, suffix=storage.serviceBootId;
  const policy={format:'leafseamer-core-bootstrap-policy/1',service_id:identity.service_id,database_instance_id:identity.database_instance_id,
    artifact_manifest_ref:{manifest_id:'synthetic-bundle',revision:'1',digest:hash('bundle')},
    platform_profile_ref:platform,policy_revision:'1',bootstrap_timeout_ms:5000,clock_backend_revision:'1'};
  const body={descriptor_version:'clock-domain/1',domain_kind:'supervised_runtime',authority_service_id:identity.service_id,
    runtime_generation:'generation.'+suffix,supervisor_instance_id:'supervisor.'+suffix,clock_backend_id:'windows_interrupt_precise',
    clock_backend_revision:'1',tick_unit:'ns',suspend_accounting:'included',namespace_identity:'windows-global',
    os_boot_identity:{status:'unavailable'},platform_profile_id:platform.profile_id,platform_profile_revision:platform.revision};
  const descriptor={...body,descriptor_digest:hash(body),clock_domain_id:'clock_'+hash(body).slice(7)};
  const intent={launch_id:'core.'+suffix,service_id:identity.service_id,supervisor_instance_id:descriptor.supervisor_instance_id,
    runtime_generation:descriptor.runtime_generation,member_id:'core-member.'+suffix,role:'core',artifact_manifest_ref:policy.artifact_manifest_ref,
    containment_ref:{group_id:'core-group.'+suffix,generation:'1',backend:'windows_job'},device_ids:[],policy_revision:'1'};
  const receipt={bootstrap_id:'bootstrap.'+suffix,launch_id:intent.launch_id,launch_intent_digest:hash(intent),member_id:intent.member_id,
    member_boot_id:'member-boot.'+suffix,role:'core',artifact_manifest_ref:intent.artifact_manifest_ref,channel_binding_id:'channel.'+suffix,
    receipt_id:'receipt.'+suffix,os_observation_ref:'observation.'+suffix,containment_ref:intent.containment_ref,gate_state:'closed',
    domain_ref:{clock_domain_id:descriptor.clock_domain_id,descriptor_digest:descriptor.descriptor_digest},admitted_tick_ns:'1'};
  storage.bindCoreRuntime({intent,descriptor,receipt},policy);return {intent,descriptor,receipt,policy};
}

export function workerIntent(storage,core,content,approved,devices){
 const record=approved.record,receipt=content.receipt;
 return {launch_id:'worker',service_id:storage.identity.service_id,supervisor_instance_id:core.descriptor.supervisor_instance_id,
  runtime_generation:core.descriptor.runtime_generation,member_id:'worker.member',role:'worker',artifact_manifest_ref:core.intent.artifact_manifest_ref,
  containment_ref:{group_id:'worker.group',generation:'1',backend:'windows_job'},object_scope:{kind:'devices',device_ids:devices},policy_revision:'1',
  extension_binding:{installation_ref:record.installation_ref,approval_ref:approved.approval_ref,review_ref:record.review_ref,role_resolution_ref:record.role_resolution_ref,
   configuration_ref:record.configuration_ref,intake_ref:content.intake_ref,platform_profile_ref:receipt.platform_profile_ref,host_installation_id:receipt.host_installation_id,
   host_trust_epoch:receipt.host_trust_epoch,manifest_digest:receipt.manifest_digest,artifact_set_digest:receipt.artifact_set_digest,entry_id:'worker',permissions_digest:record.permissions_digest}};
}
