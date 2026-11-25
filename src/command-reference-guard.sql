DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER extension_owner_binding;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v113 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '113'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v113 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '113', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v113 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v113 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 113),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v113 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v113 RENAME TO schema_migration;
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

-- 保留原运行绑定及其依赖，同时为 Linux 增加精确的绑定格式。

-- 定时守卫必须绑定已提交的最终准入和同一执行会话的授时原件。
DROP TRIGGER command_guard_request_parent;
DROP TRIGGER command_guard_ack_parent;
CREATE TRIGGER command_guard_request_parent BEFORE INSERT ON command_guard_request WHEN NOT EXISTS(
 SELECT 1 FROM command_final_admission a JOIN command_final_observation o ON o.transaction_id=a.transaction_id
 JOIN execution_frame_record f ON f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id
 JOIN command_lifecycle_head h ON h.command_id=a.command_id AND h.commit_id=a.commit_id AND h.revision=2
 WHERE a.transaction_id=NEW.final_transaction_id AND NEW.guard_id=json_extract(a.body_jcs,'$.guard.guard_id')
 AND f.domain_kind='command_guard' AND f.direction='c2w' AND f.message_type='GUARD_INSTALL'
 AND f.ipc_session_id=json_extract(a.body_jcs,'$.seal.binding.ipc_session_id') AND f.device_id=json_extract(a.body_jcs,'$.seal.binding.device_id')
 AND json_extract(f.frame_jcs,'$.body.guard')=json_extract(a.body_jcs,'$.guard')
 AND json_extract(f.frame_jcs,'$.body.content_digest')=json_extract(a.body_jcs,'$.permit.content_digest')
 AND (
  (json_type(a.body_jcs,'$.guard.time_required')='false'
   AND json_type(f.frame_jcs,'$.body.schedule_guard')='null' AND json_type(f.frame_jcs,'$.body.reference_context')='null')
  OR
  (json_type(a.body_jcs,'$.guard.time_required')='true'
   AND json_type(f.frame_jcs,'$.body.schedule_guard')='object'
   AND json_extract(f.frame_jcs,'$.body.schedule_guard')=json_extract(a.body_jcs,'$.schedule_guard')
   AND json_type(f.frame_jcs,'$.body.reference_context')='object'
   AND json_extract(f.frame_jcs,'$.body.reference_context.bundle_id')=json_extract(a.body_jcs,'$.guard.reference_time.context_ref.id')
   AND json_extract(f.frame_jcs,'$.body.reference_context.bundle_digest')=json_extract(a.body_jcs,'$.guard.reference_time.context_ref.digest')
   AND EXISTS(SELECT 1 FROM time_provider_reference_anchor t JOIN execution_session s
    ON s.ipc_session_id=f.ipc_session_id AND s.service_boot_id=t.service_boot_id
    WHERE t.anchor_id=json_extract(a.body_jcs,'$.guard.reference_time.context_ref.id')
    AND json_extract(t.body_jcs,'$.reference_bundle.digest')=json_extract(a.body_jcs,'$.guard.reference_time.context_ref.digest')))
 )
 AND json_extract(NEW.body_jcs,'$.final_admission_ref.id')=a.transaction_id AND json_extract(NEW.body_jcs,'$.final_admission_ref.digest')=a.body_digest
 AND json_extract(NEW.body_jcs,'$.guard_id')=NEW.guard_id AND json_extract(NEW.body_jcs,'$.request_record_ref.id')=f.record_id
 AND json_extract(NEW.body_jcs,'$.request_record_ref.digest')=f.record_digest
 AND json_extract(o.body_jcs,'$.outcome')='committed'
) BEGIN SELECT RAISE(ABORT,'command_guard_request_binding'); END;
CREATE TRIGGER command_guard_ack_parent BEFORE INSERT ON command_guard_ack WHEN NOT EXISTS(
 SELECT 1 FROM command_guard_request p JOIN execution_frame_record q ON q.record_id=p.record_id
 JOIN execution_write_attempt w ON w.attempt_id=NEW.write_attempt_id AND w.record_id=q.record_id
 JOIN execution_frame_record f ON f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id
 WHERE p.guard_id=NEW.guard_id AND f.domain_kind='command_guard' AND f.direction='w2c' AND f.message_type='GUARD_ACK'
 AND f.reply_record_id=q.record_id AND f.ipc_session_id=q.ipc_session_id AND f.device_id=q.device_id AND w.started_tick<=f.observed_tick
 AND json_extract(f.frame_jcs,'$.body.guard_id')=p.guard_id
 AND json_extract(f.frame_jcs,'$.body.guard_digest')=json_extract(q.frame_jcs,'$.body.guard.guard_digest')
 AND json_type(f.frame_jcs,'$.body.schedule_guard_digest') IN('text','null')
 AND json_extract(f.frame_jcs,'$.body.schedule_guard_digest') IS json_extract(q.frame_jcs,'$.body.schedule_guard.guard_digest')
 AND json_extract(NEW.body_jcs,'$.guard_id')=p.guard_id AND json_extract(NEW.body_jcs,'$.request_ref.digest')=p.body_digest
 AND json_extract(NEW.body_jcs,'$.record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(NEW.body_jcs,'$.disposition')=NEW.disposition
) BEGIN SELECT RAISE(ABORT,'command_guard_ack_binding'); END;
