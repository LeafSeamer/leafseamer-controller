DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER extension_owner_binding;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v106 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '106'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v106 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '106', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v106 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v106 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 106),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v106 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v106 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

CREATE TRIGGER request_context_parent BEFORE INSERT ON request_context
WHEN NOT EXISTS (
  SELECT 1 FROM service_state a JOIN service_boot b ON b.service_id = a.service_id
  JOIN auth_session s ON s.session_id = NEW.session_id
  JOIN session_refresh_credential c ON c.credential_id = NEW.credential_id AND c.session_id = s.session_id
  JOIN access_token t ON t.token_id = NEW.token_id AND t.session_id = s.session_id AND t.credential_id = c.credential_id
  WHERE a.service_id = NEW.service_id AND a.database_instance_id = NEW.database_instance_id
    AND a.request_epoch = NEW.context_epoch AND b.service_boot_id = NEW.service_boot_id AND b.state = 'started'
    AND s.issuer_id = NEW.issuer_id AND s.issuer_epoch = NEW.issuer_epoch AND s.principal_id = NEW.principal_id
    AND s.state = 'active' AND c.state != 'revoked' AND t.state = 'active' AND t.audience = NEW.service_id
    AND NEW.not_before_ns >= t.not_before_ns AND NEW.expires_ns <= t.expires_ns)
BEGIN SELECT RAISE(ABORT, 'request_context_parent'); END;

CREATE TRIGGER device_authorization_state_parent BEFORE INSERT ON device_authorization_state
WHEN NOT EXISTS (SELECT 1 FROM control_state_source s JOIN control_record_head h ON h.device_id=s.device_id AND (h.revision=s.revision OR (
 s.revision=(SELECT max(a.revision) FROM control_state_source a WHERE a.device_id=s.device_id AND a.change_kind NOT IN('ready','gate_protect'))
 AND EXISTS(SELECT 1 FROM control_state_source g WHERE g.device_id=h.device_id AND g.revision=h.revision AND g.change_kind IN('ready','gate_protect'))))
 JOIN service_state v ON v.singleton=1 WHERE s.source_id=NEW.control_source_id AND s.device_id=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.format_version')='device-authorization-state/0.1.0-draft.1'
 AND json_extract(NEW.body_jcs,'$.state_id')=NEW.state_id
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.revision'),-20)=NEW.revision
 AND json_extract(NEW.body_jcs,'$.state_digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.parent_ref.id') IS NEW.parent_id
 AND ((json_extract(NEW.body_jcs,'$.status')='protected' AND json_extract(NEW.body_jcs,'$.recovery_ref') IS NULL) OR
 (json_extract(NEW.body_jcs,'$.status')='policy_selected' AND EXISTS(SELECT 1 FROM device_recovery_consumption r
 JOIN device_recovery_authorization a USING(authorization_id) WHERE r.state_id=NEW.state_id AND r.commit_id=NEW.commit_id
 AND a.authorization_id=json_extract(NEW.body_jcs,'$.recovery_ref.id') AND a.protected_state_id=NEW.parent_id
 AND a.device_id=NEW.device_id)))
 AND json_extract(NEW.body_jcs,'$.context.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.context.scope.authority_service_id')=v.service_id
 AND json_extract(NEW.body_jcs,'$.context.scope.database_instance_id')=v.database_instance_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.id')=s.source_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.revision')=CAST(s.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'device_authorization_state_parent'); END;

CREATE TRIGGER ca_namespace_parent BEFORE INSERT ON ca_namespace
WHEN NEW.owner_evidence_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM request_context c JOIN service_state s ON c.service_id=s.service_id
 WHERE c.context_id=NEW.owner_evidence_id AND c.database_instance_id=s.database_instance_id
 AND c.issuer_id=NEW.issuer_id AND c.issuer_epoch=NEW.issuer_epoch AND c.principal_id=NEW.principal_id
 AND c.context_epoch=NEW.request_epoch AND c.body=NEW.owner_evidence_body)
BEGIN SELECT RAISE(ABORT,'namespace_context_binding'); END;


CREATE TRIGGER obs_local_resource_parent BEFORE INSERT ON obs_local_resource
WHEN NOT EXISTS (
  SELECT 1 FROM device_record d JOIN service_state s ON s.singleton = 1
  WHERE d.device_id = NEW.device_id AND json_extract(CAST(d.descriptor_body AS TEXT), '$.device_kind') = 'obs'
    AND json_extract(NEW.body_jcs, '$.format') = 'leafseamer-obs-local-resource/1'
    AND json_extract(NEW.body_jcs, '$.resource_id') = NEW.resource_id
    AND json_extract(NEW.body_jcs, '$.device_ref.object_id') = NEW.device_id
    AND json_extract(NEW.body_jcs, '$.device_ref.digest') = d.descriptor_digest
    AND json_extract(NEW.body_jcs, '$.device_ref.authority_service_id') = s.service_id
    AND json_extract(NEW.body_jcs, '$.device_ref.database_instance_id') = s.database_instance_id
    AND json_extract(NEW.body_jcs, '$.endpoint.address') = '127.0.0.1'
    AND json_extract(NEW.body_jcs, '$.endpoint.port') = NEW.endpoint_port
    AND json_extract(NEW.body_jcs, '$.profile') = 'obs_isolated_empty_cut/1')
BEGIN SELECT RAISE(ABORT, 'obs_local_resource_parent'); END;

CREATE TRIGGER extension_owner_binding BEFORE INSERT ON extension_resource_owner
WHEN NOT EXISTS (
  SELECT 1 FROM device_resource_identity r JOIN service_state s ON s.singleton = 1
  WHERE r.resource_id = NEW.resource_id AND r.device_id = NEW.device_id
    AND json_extract(NEW.resource_ref_jcs, '$.kind') = 'resource'
    AND json_extract(NEW.resource_ref_jcs, '$.revision') = '1'
    AND json_extract(NEW.resource_ref_jcs, '$.digest') = r.body_digest
    AND json_extract(NEW.resource_ref_jcs, '$.authority_service_id') = s.service_id
    AND json_extract(NEW.resource_ref_jcs, '$.database_instance_id') = s.database_instance_id)
BEGIN SELECT RAISE(ABORT, 'extension_owner_binding'); END;

-- 一次人员接管只登记一个新的封闭启动，原启动及拒绝记录均保留。
CREATE TABLE obs_worker_launch_replacement (
 launch_id TEXT PRIMARY KEY NOT NULL REFERENCES worker_launch_preparation(launch_id) DEFERRABLE INITIALLY DEFERRED,
 activation_operation_id TEXT NOT NULL REFERENCES extension_activation(operation_id),
 previous_launch_id TEXT NOT NULL UNIQUE REFERENCES worker_launch_preparation(launch_id),
 control_operation_id TEXT NOT NULL UNIQUE REFERENCES control_barrier_evidence(operation_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 CHECK(launch_id<>previous_launch_id)
) STRICT;
CREATE TRIGGER obs_worker_launch_replacement_parent BEFORE INSERT ON obs_worker_launch_replacement WHEN NOT EXISTS(
 SELECT 1 FROM worker_launch_preparation p JOIN worker_runtime_binding w USING(launch_id)
 JOIN execution_session s ON s.runtime_id=w.runtime_id JOIN execution_session_end d USING(ipc_session_id)
 JOIN device_execution_binding b USING(ipc_session_id)
 JOIN control_barrier_evidence e ON e.operation_id=NEW.control_operation_id
 JOIN control_barrier_target t ON t.operation_id=e.operation_id AND t.launch_id=p.launch_id
 JOIN control_operation_revision o ON o.operation_id=e.operation_id AND o.commit_id=e.commit_id
 JOIN control_record_revision r ON r.device_id=b.device_id AND r.commit_id=o.commit_id
 JOIN control_record_head h ON h.device_id=r.device_id AND h.revision=r.revision
 WHERE p.launch_id=NEW.previous_launch_id AND p.activation_operation_id=NEW.activation_operation_id
 AND t.launch_intent_digest=p.intent_digest AND t.service_boot_id=p.service_boot_id
 AND json_extract(b.body_jcs,'$.transport_profile.format')='leafseamer-obs-cut-transport/1'
 AND json_extract(o.body_jcs,'$.kind')='acquire' AND json_extract(o.body_jcs,'$.state')='effective'
 AND json_extract(o.body_jcs,'$.device_id')=b.device_id
 AND json_extract(r.body_jcs,'$.mode')='manual' AND json_extract(r.body_jcs,'$.gate_state')='protected'
 AND json_extract(NEW.body_jcs,'$.format')='leafseamer-obs-worker-launch-replacement/1'
 AND json_extract(NEW.body_jcs,'$.launch_id')=NEW.launch_id
 AND json_extract(NEW.body_jcs,'$.activation_operation_id')=NEW.activation_operation_id
 AND json_extract(NEW.body_jcs,'$.previous_launch_id')=p.launch_id
 AND json_extract(NEW.body_jcs,'$.previous_session_id')=s.ipc_session_id
 AND json_extract(NEW.body_jcs,'$.previous_end_transaction_id')=d.transaction_id
 AND json_extract(NEW.body_jcs,'$.control_operation_id')=e.operation_id
 AND json_extract(NEW.body_jcs,'$.control_ref.id')=o.commit_id
 AND json_extract(NEW.body_jcs,'$.retirement.state')='retired'
 AND json_extract(NEW.body_jcs,'$.retirement.barrier_ref.digest')=e.body_digest
 AND EXISTS(SELECT 1 FROM worker_launch_denial y WHERE y.launch_id=p.launch_id)
) BEGIN SELECT RAISE(ABORT,'obs_worker_launch_replacement_parent'); END;
CREATE TRIGGER obs_worker_launch_replacement_no_update BEFORE UPDATE ON obs_worker_launch_replacement
BEGIN SELECT RAISE(ABORT,'immutable_obs_worker_launch_replacement'); END;
CREATE TRIGGER obs_worker_launch_replacement_no_delete BEFORE DELETE ON obs_worker_launch_replacement
BEGIN SELECT RAISE(ABORT,'immutable_obs_worker_launch_replacement'); END;
DROP INDEX worker_launch_activation_once;
CREATE INDEX worker_launch_activation_history ON worker_launch_preparation(activation_operation_id);
CREATE TRIGGER worker_launch_activation_replacement BEFORE INSERT ON worker_launch_preparation
WHEN EXISTS(SELECT 1 FROM worker_launch_preparation p WHERE p.activation_operation_id=NEW.activation_operation_id)
AND NOT EXISTS(SELECT 1 FROM obs_worker_launch_replacement x WHERE x.launch_id=NEW.launch_id
 AND x.activation_operation_id=NEW.activation_operation_id
 AND json_extract(x.body_jcs,'$.launch_intent_digest')=NEW.intent_digest)
BEGIN SELECT RAISE(ABORT,'worker_launch_activation_replacement'); END;

-- 新会话的资源前态引用已终止会话及命令核销记录。
DROP TRIGGER device_initial_resource_parent;
CREATE TRIGGER device_initial_resource_parent BEFORE INSERT ON device_initial_resource
WHEN NOT EXISTS (SELECT 1 FROM device_execution_binding b JOIN execution_initial_fence f ON f.binding_id=b.binding_id
 JOIN execution_initial_fence_ack a USING(fence_id) JOIN device_baseline_sample s ON s.sample_id=NEW.sample_id
 JOIN device_authorization_evidence e ON e.evidence_id=NEW.evidence_id
 JOIN device_authorization_evidence_head h ON h.evidence_id=e.evidence_id
 JOIN device_authorization_head d ON d.state_id=h.state_id AND d.device_id=NEW.device_id
 WHERE b.binding_id=NEW.binding_id AND b.device_id=NEW.device_id AND f.fence_id=NEW.fence_id
 AND s.approval_id=b.catalog_approval_id
 AND json_extract(NEW.body_jcs,'$.inventory.prior_execution') IS json_extract(f.body_jcs,'$.prior_execution')
 AND (json_type(NEW.body_jcs,'$.inventory.prior_execution') IS NULL OR (
  json_extract(b.body_jcs,'$.transport_profile.format')='leafseamer-obs-cut-transport/1'
  AND json_extract(NEW.body_jcs,'$.deny_snapshots.format')='initial-manual-deny-snapshots/4'
  AND json_type(NEW.body_jcs,'$.inventory.prior_execution')='array'
  AND json_array_length(NEW.body_jcs,'$.inventory.prior_execution') BETWEEN 1 AND 256
  AND json_array_length(NEW.body_jcs,'$.inventory.prior_execution')=(SELECT count(*) FROM device_execution_binding old
   WHERE old.device_id=b.device_id AND old.ipc_session_id<>b.ipc_session_id)
  AND NOT EXISTS(SELECT 1 FROM device_execution_binding old WHERE old.device_id=b.device_id AND old.ipc_session_id<>b.ipc_session_id
   AND NOT EXISTS(SELECT 1 FROM execution_session_end ee,json_each(NEW.body_jcs,'$.inventory.prior_execution') pr
    WHERE ee.ipc_session_id=old.ipc_session_id AND json_extract(pr.value,'$.ipc_session_id')=ee.ipc_session_id
    AND json_extract(pr.value,'$.binding_ref.id')=old.binding_id AND json_extract(pr.value,'$.binding_ref.digest')=old.body_digest
    AND json_extract(pr.value,'$.session_end.transaction_id')=ee.transaction_id AND json_extract(pr.value,'$.session_end.reason')=ee.reason))
 )) AND (
 (json_extract(s.body_jcs,'$.value.write_sequence')='0' AND NOT EXISTS(SELECT 1 FROM ca_command_initial c JOIN ca_request_key k USING(key_id) WHERE k.device_id=NEW.device_id)) OR
 (json_extract(NEW.body_jcs,'$.format')='leafseamer-obs-cut-initial-resource-source/1'
 AND json_extract(NEW.body_jcs,'$.provider')='fixed_obs_cut_initial/1'
 AND json_extract(b.body_jcs,'$.transport_profile.format')='leafseamer-obs-cut-transport/1'
 AND json_extract(NEW.body_jcs,'$.inventory.external_resources[0]')=json_extract(b.body_jcs,'$.transport_profile.resource_ref')
 AND json_array_length(NEW.body_jcs,'$.inventory.external_resources')=1
 AND json_extract(NEW.body_jcs,'$.inventory.obs_cut_observation.program_scene_uuid')=json_extract(s.body_jcs,'$.value.program_scene_uuid')
 AND EXISTS(SELECT 1 FROM obs_scene_confirmation x WHERE x.approval_id=b.catalog_approval_id)
 AND NOT EXISTS(SELECT 1 FROM ca_command_initial c JOIN ca_request_key k USING(key_id) WHERE k.device_id=NEW.device_id
  AND NOT (EXISTS(SELECT 1 FROM command_admission_source src,json_each(NEW.body_jcs,'$.inventory.prior_execution') prior,json_each(prior.value,'$.commands') old
  JOIN command_lifecycle_head oh ON oh.command_id=src.command_id
  JOIN command_lifecycle_revision ov ON ov.command_id=oh.command_id AND ov.revision=oh.revision AND ov.commit_id=oh.commit_id
  WHERE src.command_id=c.command_id AND src.binding_id=json_extract(prior.value,'$.binding_ref.id')
  AND json_extract(old.value,'$.command_id')=c.command_id
  AND json_extract(old.value,'$.state_ref.digest')=ov.state_digest
  AND json_extract(ov.state_jcs,'$.phase')='finished' AND json_extract(ov.state_jcs,'$.resource_status')='clear'
  AND (EXISTS(SELECT 1 FROM command_hold_clearance r WHERE r.command_id=c.command_id)
   OR json_extract(ov.state_jcs,'$.effect_status')='not_sent' AND NOT EXISTS(SELECT 1 FROM command_final_admission fa WHERE fa.command_id=c.command_id)))))) OR
 (json_extract(NEW.body_jcs,'$.format')='leafseamer-device-resource-successor/1'
 AND EXISTS(SELECT 1 FROM command_closure_request c JOIN command_closure_ack k USING(permit_id)
  JOIN command_final_admission t USING(permit_id) JOIN command_hold_release r ON r.hold_id=t.hold_id
  JOIN command_preparation_cleanup p ON p.permit_id=t.permit_id AND p.phase='release_ack'
  WHERE t.binding_id=b.binding_id AND json_extract(NEW.body_jcs,'$.inventory.closing_ref.id')=t.permit_id||'.fence_request'
  AND json_extract(NEW.body_jcs,'$.inventory.closing_ref.digest')=c.body_digest
  AND json_extract(NEW.body_jcs,'$.inventory.closing_ack_ref.digest')=k.body_digest)
 AND NOT EXISTS(SELECT 1 FROM command_device_hold x WHERE x.device_id=NEW.device_id AND NOT EXISTS(
  SELECT 1 FROM command_hold_release r JOIN command_final_admission t ON t.hold_id=r.hold_id
  JOIN command_preparation_cleanup p ON p.permit_id=t.permit_id AND p.phase='release_ack' WHERE r.hold_id=x.hold_id)
  AND NOT EXISTS(SELECT 1 FROM command_unsent_closure u,json_each(NEW.body_jcs,'$.inventory.prior_execution') pr,json_each(pr.value,'$.commands') p
   WHERE u.hold_id=x.hold_id AND json_extract(p.value,'$.command_id')=u.command_id
   AND json_extract(pr.value,'$.ipc_session_id')=u.ipc_session_id))
 AND NOT EXISTS(SELECT 1 FROM ca_command_initial c JOIN ca_request_key k USING(key_id) WHERE k.device_id=NEW.device_id AND NOT EXISTS(
  SELECT 1 FROM command_settlement t JOIN command_hold_release r USING(command_id) WHERE t.command_id=c.command_id)
  AND NOT (EXISTS(SELECT 1 FROM command_admission_source src,json_each(NEW.body_jcs,'$.inventory.prior_execution') prior,json_each(prior.value,'$.commands') old
  JOIN command_lifecycle_head oh ON oh.command_id=src.command_id
  JOIN command_lifecycle_revision ov ON ov.command_id=oh.command_id AND ov.revision=oh.revision AND ov.commit_id=oh.commit_id
  WHERE src.command_id=c.command_id AND src.binding_id=json_extract(prior.value,'$.binding_ref.id')
  AND json_extract(old.value,'$.command_id')=c.command_id
  AND json_extract(old.value,'$.state_ref.digest')=ov.state_digest
  AND json_extract(ov.state_jcs,'$.phase')='finished' AND json_extract(ov.state_jcs,'$.resource_status')='clear'
  AND (EXISTS(SELECT 1 FROM command_hold_clearance r WHERE r.command_id=c.command_id)
   OR json_extract(ov.state_jcs,'$.effect_status')='not_sent' AND NOT EXISTS(SELECT 1 FROM command_final_admission fa WHERE fa.command_id=c.command_id))))))))
BEGIN SELECT RAISE(ABORT,'initial_resource_parent'); END;

DROP TRIGGER execution_initial_fence_parent;
CREATE TRIGGER execution_initial_fence_parent BEFORE INSERT ON execution_initial_fence BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM device_execution_binding b
 JOIN control_record_revision c ON c.device_id=NEW.control_device_id AND c.revision=NEW.control_revision
 JOIN control_record_head h ON h.device_id=c.device_id AND h.revision=c.revision
 JOIN execution_frame_record f ON f.record_id=NEW.request_record_id AND f.transaction_id=NEW.request_transaction_id
 JOIN execution_handshake n ON n.ipc_session_id=b.ipc_session_id
 WHERE b.binding_id=NEW.binding_id AND b.device_id=c.device_id AND f.ipc_session_id=b.ipc_session_id AND f.device_id=b.device_id
 AND f.direction='c2w' AND f.message_type='FENCE' AND f.domain_kind='initial_control'
 AND (json_extract(c.body_jcs,'$.mode')='manual' OR
  (json_extract(c.body_jcs,'$.mode')='automatic' AND json_type(c.body_jcs,'$.holder')='null'
  AND (SELECT count(DISTINCT value) FROM json_each(n.body_jcs,'$.selected_features')
   WHERE value IN ('automation_origin_binding','run_generation_fence','run_deny_snapshot'))=3))
 AND json_extract(c.body_jcs,'$.gate_state')='protected'
 AND json_type(c.body_jcs,'$.pending_change')='null'
 AND json_array_length(c.body_jcs,'$.in_flight_command_ids')=0 AND json_array_length(c.body_jcs,'$.unresolved_command_ids')=0
 AND json_extract(NEW.body_jcs,'$.fence_id')=NEW.fence_id
 AND json_extract(NEW.body_jcs,'$.gate_state')='closed'
 AND json_extract(NEW.body_jcs,'$.binding_ref.id')=b.binding_id AND json_extract(NEW.body_jcs,'$.binding_ref.digest')=b.body_digest
 AND json_extract(NEW.body_jcs,'$.control_record')=c.body_jcs
 AND json_extract(NEW.body_jcs,'$.request_record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.request_record_ref.digest')=f.record_digest
 AND json_extract(f.frame_jcs,'$.body.barrier_id')=NEW.fence_id
 AND json_extract(f.frame_jcs,'$.body.control_epoch')=json_extract(c.body_jcs,'$.control_epoch')
 AND json_extract(f.frame_jcs,'$.body.target_version')=json_extract(c.body_jcs,'$.effective_version')
 AND json_extract(f.frame_jcs,'$.body.target_gate_revision')='1' AND json_extract(f.frame_jcs,'$.body.issued_cut_revision')='0'
 AND json_array_length(f.frame_jcs,'$.body.open_intents')=0 AND json_array_length(f.frame_jcs,'$.body.open_transmission_intents')=0
 AND json_array_length(f.frame_jcs,'$.body.cancel_transmissions')=0
 AND json_extract(f.frame_jcs,'$.body.attempt_binding.target_exit_id')=b.writer_exit_id
 AND json_extract(f.frame_jcs,'$.body.attempt_binding.attempt_ordinal')='1' AND json_type(f.frame_jcs,'$.body.attempt_binding.previous_barrier_id')='null'
 AND EXISTS(SELECT 1 FROM json_each(n.body_jcs,'$.selected_features') WHERE value='initial_control_fence')
 AND NOT EXISTS(SELECT 1 FROM ca_adjudication a JOIN ca_request_key k USING(key_id) WHERE k.device_id=b.device_id AND a.decision!='rejected'
 AND NOT EXISTS(SELECT 1 FROM command_admission_source src
  JOIN device_execution_binding old ON old.binding_id=src.binding_id JOIN execution_session_end ee ON ee.ipc_session_id=old.ipc_session_id
  JOIN command_lifecycle_head nh ON nh.command_id=src.command_id
  JOIN command_lifecycle_revision v ON v.command_id=nh.command_id AND v.revision=nh.revision AND v.commit_id=nh.commit_id,
  json_each(NEW.body_jcs,'$.prior_execution') prior,json_each(prior.value,'$.commands') item
  WHERE src.command_id=a.command_id AND old.device_id=b.device_id AND old.ipc_session_id<>b.ipc_session_id
  AND json_extract(b.body_jcs,'$.transport_profile.format')='leafseamer-obs-cut-transport/1'
  AND json_extract(prior.value,'$.binding_ref.id')=old.binding_id AND json_extract(prior.value,'$.binding_ref.digest')=old.body_digest
  AND json_extract(prior.value,'$.ipc_session_id')=ee.ipc_session_id AND json_extract(prior.value,'$.session_end.transaction_id')=ee.transaction_id
  AND json_extract(item.value,'$.command_id')=src.command_id AND json_extract(item.value,'$.state_ref.digest')=v.state_digest
  AND json_extract(v.state_jcs,'$.phase')='finished' AND json_extract(v.state_jcs,'$.resource_status')='clear'
  AND (EXISTS(SELECT 1 FROM command_hold_clearance h WHERE h.command_id=src.command_id)
   OR json_extract(v.state_jcs,'$.effect_status')='not_sent' AND NOT EXISTS(SELECT 1 FROM command_final_admission t WHERE t.command_id=src.command_id)))))
 THEN RAISE(ABORT,'execution_initial_fence_binding') END;
END;
