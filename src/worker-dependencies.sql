DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v20 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '20'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v20 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '20', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v20 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v20 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20')),
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
    OR (from_revision = '19' AND to_revision = '20' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v20 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v20 RENAME TO schema_migration;
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

CREATE TABLE virtual_device_resource (
 device_id TEXT PRIMARY KEY NOT NULL REFERENCES device_record(device_id),
 resource_id TEXT NOT NULL UNIQUE,
 request_id TEXT NOT NULL UNIQUE,
 input_digest TEXT NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 body_digest TEXT NOT NULL,
 transaction_id TEXT NOT NULL UNIQUE,
 FOREIGN KEY(transaction_id,device_id) REFERENCES virtual_device_resource_commit(transaction_id,device_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE virtual_device_resource_commit (
 transaction_id TEXT PRIMARY KEY NOT NULL,
 device_id TEXT NOT NULL UNIQUE REFERENCES virtual_device_resource(device_id),
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 UNIQUE(transaction_id,device_id)
) STRICT;
CREATE TABLE worker_launch_dependencies (
 launch_id TEXT PRIMARY KEY NOT NULL REFERENCES worker_launch_preparation(launch_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=4194304),
 body_digest TEXT NOT NULL
) STRICT;
ALTER TABLE worker_launch_preparation ADD COLUMN dependency_launch_id TEXT REFERENCES worker_launch_dependencies(launch_id) DEFERRABLE INITIALLY DEFERRED;
CREATE TRIGGER worker_launch_dependency_required BEFORE INSERT ON worker_launch_preparation
WHEN NEW.dependency_launch_id IS NOT NEW.launch_id BEGIN SELECT RAISE(ABORT,'worker_launch_dependencies_required'); END;
CREATE TRIGGER worker_launch_dependency_binding BEFORE INSERT ON worker_launch_dependencies
WHEN NOT EXISTS(SELECT 1 FROM worker_launch_preparation p WHERE p.launch_id=NEW.launch_id
 AND json_extract(NEW.body_jcs,'$.launch_id')=p.launch_id
 AND json_extract(NEW.body_jcs,'$.launch_intent_digest')=p.intent_digest)
BEGIN SELECT RAISE(ABORT,'worker_launch_dependency_binding'); END;
CREATE TRIGGER virtual_device_resource_no_update BEFORE UPDATE ON virtual_device_resource BEGIN SELECT RAISE(ABORT,'immutable_dependency'); END;
CREATE TRIGGER virtual_device_resource_no_delete BEFORE DELETE ON virtual_device_resource BEGIN SELECT RAISE(ABORT,'immutable_dependency'); END;
CREATE TRIGGER virtual_device_resource_commit_no_update BEFORE UPDATE ON virtual_device_resource_commit BEGIN SELECT RAISE(ABORT,'immutable_dependency'); END;
CREATE TRIGGER virtual_device_resource_commit_no_delete BEFORE DELETE ON virtual_device_resource_commit BEGIN SELECT RAISE(ABORT,'immutable_dependency'); END;
CREATE TRIGGER worker_launch_dependencies_no_update BEFORE UPDATE ON worker_launch_dependencies BEGIN SELECT RAISE(ABORT,'immutable_dependency'); END;
CREATE TRIGGER worker_launch_dependencies_no_delete BEFORE DELETE ON worker_launch_dependencies BEGIN SELECT RAISE(ABORT,'immutable_dependency'); END;
