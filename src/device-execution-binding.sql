DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v29 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '29'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v29 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '29', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v29 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v29 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29')),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK((from_revision = '0' AND to_revision = '1' AND backup_ref IS NULL)
    OR (from_revision = '1' AND to_revision = '2' AND backup_ref IS NOT NULL)
    OR (from_revision = '2' AND to_revision = '3' AND backup_ref IS NOT NULL)
    OR (from_revision = '3' AND to_revision = '4' AND backup_ref IS NOT NULL)
    OR (from_revision = '4' AND to_revision = '5' AND backup_ref IS NOT NULL)
    OR (from_revision = '5' AND to_revision = '6' AND backup_ref IS NOT NULL)
    OR (from_revision = '6' AND to_revision = '7' AND backup_ref IS NOT NULL)
    OR (from_revision = '7' AND to_revision = '8' AND backup_ref IS NOT NULL)
    OR (from_revision = '8' AND to_revision = '9' AND backup_ref IS NOT NULL)
    OR (from_revision = '9' AND to_revision = '10' AND backup_ref IS NOT NULL)
    OR (from_revision = '10' AND to_revision = '11' AND backup_ref IS NOT NULL)
    OR (from_revision = '11' AND to_revision = '12' AND backup_ref IS NOT NULL)
    OR (from_revision = '12' AND to_revision = '13' AND backup_ref IS NOT NULL)
    OR (from_revision = '13' AND to_revision = '14' AND backup_ref IS NOT NULL)
    OR (from_revision = '14' AND to_revision = '15' AND backup_ref IS NOT NULL)
    OR (from_revision = '15' AND to_revision = '16' AND backup_ref IS NOT NULL)
    OR (from_revision = '16' AND to_revision = '17' AND backup_ref IS NOT NULL)
    OR (from_revision = '17' AND to_revision = '18' AND backup_ref IS NOT NULL)
    OR (from_revision = '18' AND to_revision = '19' AND backup_ref IS NOT NULL)
    OR (from_revision = '19' AND to_revision = '20' AND backup_ref IS NOT NULL)
    OR (from_revision = '20' AND to_revision = '21' AND backup_ref IS NOT NULL)
    OR (from_revision = '21' AND to_revision = '22' AND backup_ref IS NOT NULL)
    OR (from_revision = '22' AND to_revision = '23' AND backup_ref IS NOT NULL)
    OR (from_revision = '23' AND to_revision = '24' AND backup_ref IS NOT NULL)
    OR (from_revision = '24' AND to_revision = '25' AND backup_ref IS NOT NULL)
    OR (from_revision = '25' AND to_revision = '26' AND backup_ref IS NOT NULL)
    OR (from_revision = '26' AND to_revision = '27' AND backup_ref IS NOT NULL)
    OR (from_revision = '27' AND to_revision = '28' AND backup_ref IS NOT NULL)
    OR (from_revision = '28' AND to_revision = '29' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v29 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v29 RENAME TO schema_migration;
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

CREATE TRIGGER ca_namespace_parent BEFORE INSERT ON ca_namespace
WHEN NOT EXISTS (SELECT 1 FROM request_context c JOIN service_state s ON c.service_id=s.service_id
 WHERE c.context_id=NEW.owner_evidence_id AND c.database_instance_id=s.database_instance_id
 AND c.issuer_id=NEW.issuer_id AND c.issuer_epoch=NEW.issuer_epoch AND c.principal_id=NEW.principal_id
 AND c.context_epoch=NEW.request_epoch AND c.body=NEW.owner_evidence_body)
BEGIN SELECT RAISE(ABORT,'namespace_context_binding'); END;

CREATE TABLE device_execution_binding (
 binding_id TEXT PRIMARY KEY NOT NULL,
 ipc_session_id TEXT NOT NULL REFERENCES execution_session(ipc_session_id),
 catalog_approval_id TEXT NOT NULL UNIQUE REFERENCES device_catalog_approval(approval_id),
 baseline_sample_id TEXT NOT NULL REFERENCES device_baseline_sample(sample_id),
 writer_exit_id TEXT NOT NULL UNIQUE,
 device_id TEXT NOT NULL REFERENCES device_record(device_id),
 device_session_id TEXT NOT NULL UNIQUE,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=65536),
 body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 transaction_id TEXT NOT NULL UNIQUE,
 UNIQUE(binding_id,transaction_id),
 FOREIGN KEY(binding_id,transaction_id) REFERENCES device_execution_binding_commit(binding_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE device_execution_binding_commit (
 binding_id TEXT PRIMARY KEY NOT NULL,
 transaction_id TEXT NOT NULL UNIQUE,
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs) AND length(CAST(audit_jcs AS BLOB))<=8192),
 UNIQUE(binding_id,transaction_id),
 FOREIGN KEY(binding_id,transaction_id) REFERENCES device_execution_binding(binding_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
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
 AND json_extract(a.body_jcs,'$.qualification.qualification')='fixed_memory_control_catalog/1'
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
CREATE TRIGGER device_execution_binding_capacity BEFORE INSERT ON device_execution_binding
WHEN (SELECT count(*) FROM device_execution_binding)>=4096
 OR (SELECT coalesce(sum(length(CAST(body_jcs AS BLOB))+8192),0) FROM device_execution_binding)+length(CAST(NEW.body_jcs AS BLOB))+8192>67108864
BEGIN SELECT RAISE(ABORT,'device_execution_binding_capacity'); END;
CREATE TRIGGER device_execution_binding_commit_parent BEFORE INSERT ON device_execution_binding_commit WHEN NOT EXISTS(
 SELECT 1 FROM device_execution_binding b WHERE b.binding_id=NEW.binding_id AND b.transaction_id=NEW.transaction_id
 AND json_extract(NEW.audit_jcs,'$.kind')='device_execution_bound_closed'
 AND json_extract(NEW.audit_jcs,'$.binding_id')=b.binding_id AND json_extract(NEW.audit_jcs,'$.binding_digest')=b.body_digest)
BEGIN SELECT RAISE(ABORT,'device_execution_binding_commit'); END;
CREATE TRIGGER device_execution_binding_no_update BEFORE UPDATE ON device_execution_binding BEGIN SELECT RAISE(ABORT,'immutable_execution_binding'); END;
CREATE TRIGGER device_execution_binding_no_delete BEFORE DELETE ON device_execution_binding BEGIN SELECT RAISE(ABORT,'immutable_execution_binding'); END;
CREATE TRIGGER device_execution_binding_commit_no_update BEFORE UPDATE ON device_execution_binding_commit BEGIN SELECT RAISE(ABORT,'immutable_execution_binding'); END;
CREATE TRIGGER device_execution_binding_commit_no_delete BEFORE DELETE ON device_execution_binding_commit BEGIN SELECT RAISE(ABORT,'immutable_execution_binding'); END;

