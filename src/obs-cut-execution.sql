DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER extension_owner_binding;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v101 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '101'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v101 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '101', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v101 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v101 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 101),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v101 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v101 RENAME TO schema_migration;
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

DROP TRIGGER obs_scene_confirmation_parent;
CREATE TRIGGER obs_scene_confirmation_parent BEFORE INSERT ON obs_scene_confirmation
WHEN NOT EXISTS (
  SELECT 1 FROM device_catalog_approval a JOIN auth_session s ON s.session_id = NEW.session_id
  WHERE a.approval_id = NEW.approval_id AND s.state = 'active'
    AND json_extract(a.body_jcs, '$.qualification.qualification') IN ('fixed_obs_read_only/1','fixed_obs_cut_catalog/1')
    AND json_extract(NEW.body_jcs, '$.catalog.collection_ref') = a.approval_id
    AND json_extract(NEW.body_jcs, '$.catalog.device_id') = a.device_id
    AND json_extract(NEW.body_jcs, '$.catalog.device_session_id') = a.device_session_id
    AND json_extract(NEW.body_jcs, '$.catalog.status') = 'unconfirmed'
    AND json_extract(NEW.body_jcs, '$.request_id') = NEW.request_id
    AND json_extract(NEW.body_jcs, '$.actor.session_id') = s.session_id
    AND json_extract(NEW.body_jcs, '$.actor.issuer_id') = s.issuer_id
    AND json_extract(NEW.body_jcs, '$.actor.issuer_epoch') = s.issuer_epoch
    AND json_extract(NEW.body_jcs, '$.actor.principal_id') = s.principal_id
    AND EXISTS (SELECT 1 FROM device_baseline_sample b WHERE b.approval_id = a.approval_id))
BEGIN SELECT RAISE(ABORT, 'obs_scene_confirmation_parent'); END;

DROP TRIGGER device_execution_binding_parent;
CREATE TRIGGER device_execution_binding_parent BEFORE INSERT ON device_execution_binding WHEN NOT EXISTS(
 SELECT 1 FROM execution_session s JOIN device_catalog_approval a ON a.approval_id=NEW.catalog_approval_id
 JOIN device_module_channel c ON c.channel_id=a.channel_id AND c.runtime_id=s.runtime_id
 JOIN device_baseline_sample b ON b.sample_id=NEW.baseline_sample_id AND b.approval_id=a.approval_id
 JOIN service_boot boot ON boot.service_boot_id=s.service_boot_id
 WHERE s.ipc_session_id=NEW.ipc_session_id AND boot.state='started'
 AND NOT EXISTS(SELECT 1 FROM execution_session_end e WHERE e.ipc_session_id=s.ipc_session_id)
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=s.runtime_id)
 AND NOT EXISTS(SELECT 1 FROM device_module_frame f WHERE f.channel_id=a.channel_id AND f.message_type='DISCONNECTED'
 AND json_extract(f.frame_jcs,'$.body.device_session_id')=a.device_session_id)
 AND a.device_id=NEW.device_id AND a.device_session_id=NEW.device_session_id
 AND (json_extract(a.body_jcs,'$.qualification.qualification')='fixed_memory_control_catalog/1'
  OR (json_extract(a.body_jcs,'$.qualification.qualification')='fixed_obs_cut_catalog/1'
   AND EXISTS (SELECT 1 FROM obs_scene_confirmation x WHERE x.approval_id=a.approval_id
     AND json_extract(NEW.body_jcs,'$.primitive_plan.scene_catalog')=
       json_set(json_extract(x.body_jcs,'$.catalog'),'$.status','ready','$.binding_revision','2')
     AND json_extract(NEW.body_jcs,'$.transport_profile.resource_ref')=json_extract(a.body_jcs,'$.qualification.obs_binding.resource_ref'))))
 AND json_extract(NEW.body_jcs,'$.format')='leafseamer-device-execution-binding/1'
 AND json_extract(NEW.body_jcs,'$.binding_id')=NEW.binding_id
 AND json_extract(NEW.body_jcs,'$.state')='bound_closed'
 AND json_extract(NEW.body_jcs,'$.write_eligible')=0
 AND json_extract(NEW.body_jcs,'$.catalog_approval_ref.id')=a.approval_id
 AND json_extract(NEW.body_jcs,'$.catalog_approval_ref.digest')=a.body_digest
 AND json_extract(NEW.body_jcs,'$.initial_sample_ref.id')=b.sample_id
 AND json_extract(NEW.body_jcs,'$.initial_sample_ref.digest')=b.body_digest
 AND json_extract(NEW.body_jcs,'$.session_ref.id')=s.ipc_session_id
 AND json_extract(NEW.body_jcs,'$.session_ref.digest')=s.binding_digest
 AND json_extract(NEW.body_jcs,'$.binding.writer_exit_id')=NEW.writer_exit_id
 AND json_extract(NEW.body_jcs,'$.binding.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.binding.device_session_id')=NEW.device_session_id
 AND json_extract(NEW.body_jcs,'$.binding.ipc_session_id')=s.ipc_session_id
 AND json_extract(NEW.body_jcs,'$.binding.controller_boot_id')=s.controller_boot_id
 AND json_extract(NEW.body_jcs,'$.binding.worker_boot_id')=s.worker_boot_id
 AND json_extract(NEW.body_jcs,'$.binding.clock_domain_id')=s.clock_domain_id
 AND json_extract(NEW.body_jcs,'$.binding.descriptor_digest')=s.descriptor_digest
 AND json_extract(NEW.body_jcs,'$.binding.scope.authority_service_id')=boot.service_id
 AND json_extract(NEW.body_jcs,'$.binding.scope.database_instance_id')=boot.database_instance_id
 AND json_extract(NEW.body_jcs,'$.runtime_binding_ref')=json_extract(a.body_jcs,'$.runtime_binding_ref')
) BEGIN SELECT RAISE(ABORT,'device_execution_binding_parent'); END;
