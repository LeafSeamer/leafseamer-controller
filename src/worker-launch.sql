DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v12 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '12'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v12 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '12', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v12 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v12 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12')),
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
    OR (from_revision = '11' AND to_revision = '12' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v12 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v12 RENAME TO schema_migration;
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

CREATE TABLE worker_launch_preparation (
  launch_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  preparation_id TEXT NOT NULL UNIQUE,
  transaction_id TEXT NOT NULL UNIQUE,
  service_boot_id TEXT NOT NULL REFERENCES core_runtime_binding(service_boot_id),
  supervisor_instance_id TEXT NOT NULL,
  runtime_generation TEXT NOT NULL,
  member_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  group_generation TEXT NOT NULL,
  intent_digest TEXT NOT NULL CHECK(length(intent_digest)=71),
  intent_jcs TEXT NOT NULL CHECK(length(CAST(intent_jcs AS BLOB)) BETWEEN 1 AND 262144 AND json_valid(intent_jcs)),
  state TEXT NOT NULL CHECK(state='prepared'),
  UNIQUE(supervisor_instance_id,member_id),
  UNIQUE(supervisor_instance_id,group_id,group_generation),
  UNIQUE(transaction_id,launch_id,preparation_id,intent_digest),
  FOREIGN KEY(transaction_id,launch_id,preparation_id,intent_digest)
    REFERENCES worker_launch_preparation_commit(transaction_id,launch_id,preparation_id,intent_digest) DEFERRABLE INITIALLY DEFERRED,
  CHECK(json_extract(intent_jcs,'$.launch_id') IS launch_id AND json_extract(intent_jcs,'$.role') IS 'worker'
    AND json_extract(intent_jcs,'$.supervisor_instance_id') IS supervisor_instance_id
    AND json_extract(intent_jcs,'$.runtime_generation') IS runtime_generation AND json_extract(intent_jcs,'$.member_id') IS member_id
    AND json_extract(intent_jcs,'$.containment_ref.group_id') IS group_id
    AND json_extract(intent_jcs,'$.containment_ref.generation') IS group_generation
    AND json_extract(intent_jcs,'$.containment_ref.backend') IS 'windows_job'
    AND json_extract(intent_jcs,'$.object_scope.kind') IS 'devices'
    AND coalesce(json_array_length(intent_jcs,'$.object_scope.device_ids'),0) BETWEEN 1 AND 64)
) STRICT;
CREATE TABLE worker_launch_device (
  launch_id TEXT NOT NULL REFERENCES worker_launch_preparation(launch_id),
  device_id TEXT NOT NULL REFERENCES device_record(device_id),
  PRIMARY KEY(launch_id,device_id)
) STRICT;
CREATE TABLE worker_launch_preparation_commit (
  transaction_id TEXT PRIMARY KEY NOT NULL,
  launch_id TEXT NOT NULL UNIQUE,
  preparation_id TEXT NOT NULL UNIQUE,
  intent_digest TEXT NOT NULL,
  audit_jcs TEXT NOT NULL CHECK(length(audit_jcs) BETWEEN 1 AND 8192 AND json_valid(audit_jcs)),
  UNIQUE(transaction_id,launch_id,preparation_id,intent_digest),
  FOREIGN KEY(transaction_id,launch_id,preparation_id,intent_digest)
    REFERENCES worker_launch_preparation(transaction_id,launch_id,preparation_id,intent_digest),
  CHECK(json_extract(audit_jcs,'$.kind') IS 'worker_launch_prepared'
    AND json_extract(audit_jcs,'$.transaction_id') IS transaction_id
    AND json_extract(audit_jcs,'$.launch_id') IS launch_id
    AND json_extract(audit_jcs,'$.preparation_id') IS preparation_id
    AND json_extract(audit_jcs,'$.intent_digest') IS intent_digest)
) STRICT;
CREATE TRIGGER worker_launch_parent BEFORE INSERT ON worker_launch_preparation
WHEN NOT EXISTS (
  SELECT 1 FROM core_runtime_binding r JOIN service_boot b USING(service_boot_id)
  WHERE r.service_boot_id=NEW.service_boot_id AND b.state='started'
    AND b.service_id IS json_extract(NEW.intent_jcs,'$.service_id')
    AND json_extract(r.descriptor_jcs,'$.supervisor_instance_id') IS NEW.supervisor_instance_id
    AND json_extract(r.descriptor_jcs,'$.runtime_generation') IS NEW.runtime_generation
    AND json_extract(r.intent_jcs,'$.artifact_manifest_ref') IS json_extract(NEW.intent_jcs,'$.artifact_manifest_ref')
    AND json_extract(r.policy_jcs,'$.policy_revision') IS json_extract(NEW.intent_jcs,'$.policy_revision')
    AND json_extract(r.descriptor_jcs,'$.platform_profile_id') IS json_extract(NEW.intent_jcs,'$.extension_binding.platform_profile_ref.object_id')
    AND json_extract(r.descriptor_jcs,'$.platform_profile_revision') IS json_extract(NEW.intent_jcs,'$.extension_binding.platform_profile_ref.revision')
    AND json_extract(r.intent_jcs,'$.member_id') IS NOT NEW.member_id
    AND json_extract(r.intent_jcs,'$.launch_id') IS NOT NEW.launch_id
    AND json_extract(r.intent_jcs,'$.containment_ref.group_id') IS NOT NEW.group_id)
BEGIN SELECT RAISE(ABORT,'worker_launch_parent'); END;
CREATE TRIGGER worker_launch_device_binding BEFORE INSERT ON worker_launch_device
WHEN EXISTS(SELECT 1 FROM worker_launch_preparation_commit WHERE launch_id=NEW.launch_id)
  OR NOT EXISTS(SELECT 1 FROM worker_launch_preparation p,json_each(p.intent_jcs,'$.object_scope.device_ids') d
    WHERE p.launch_id=NEW.launch_id AND d.type='text' AND d.value=NEW.device_id)
BEGIN SELECT RAISE(ABORT,'worker_launch_device_binding'); END;
CREATE TRIGGER worker_launch_complete BEFORE INSERT ON worker_launch_preparation_commit
WHEN NOT EXISTS(SELECT 1 FROM worker_launch_preparation p WHERE p.launch_id=NEW.launch_id
  AND json_extract(NEW.audit_jcs,'$.service_boot_id') IS p.service_boot_id
  AND (SELECT count(*) FROM worker_launch_device d WHERE d.launch_id=p.launch_id)=json_array_length(p.intent_jcs,'$.object_scope.device_ids'))
BEGIN SELECT RAISE(ABORT,'worker_launch_incomplete'); END;
CREATE TRIGGER worker_launch_no_update BEFORE UPDATE ON worker_launch_preparation
BEGIN SELECT RAISE(ABORT,'immutable_worker_launch'); END;
CREATE TRIGGER worker_launch_no_delete BEFORE DELETE ON worker_launch_preparation
BEGIN SELECT RAISE(ABORT,'worker_launch_history_required'); END;
CREATE TRIGGER worker_launch_device_no_update BEFORE UPDATE ON worker_launch_device
BEGIN SELECT RAISE(ABORT,'immutable_worker_launch'); END;
CREATE TRIGGER worker_launch_device_no_delete BEFORE DELETE ON worker_launch_device
BEGIN SELECT RAISE(ABORT,'worker_launch_history_required'); END;
CREATE TRIGGER worker_launch_commit_no_update BEFORE UPDATE ON worker_launch_preparation_commit
BEGIN SELECT RAISE(ABORT,'immutable_worker_launch'); END;
CREATE TRIGGER worker_launch_commit_no_delete BEFORE DELETE ON worker_launch_preparation_commit
BEGIN SELECT RAISE(ABORT,'worker_launch_history_required'); END;
