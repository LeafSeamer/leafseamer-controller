DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v10 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '10'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v10 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '10', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v10 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v10 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10')),
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
    OR (from_revision = '9' AND to_revision = '10' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v10 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v10 RENAME TO schema_migration;
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

CREATE TABLE device_catalog (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 4096)
) STRICT;
INSERT INTO device_catalog VALUES (1,0);
CREATE TABLE device_registration (
  request_id TEXT PRIMARY KEY NOT NULL,
  request_digest TEXT NOT NULL,
  device_id TEXT NOT NULL UNIQUE,
  tx_id TEXT NOT NULL UNIQUE,
  request_body BLOB NOT NULL CHECK(length(request_body) BETWEEN 1 AND 8192),
  FOREIGN KEY(tx_id,device_id,request_id) REFERENCES device_registration_commit(tx_id,device_id,request_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE device_record (
  device_id TEXT PRIMARY KEY NOT NULL,
  sequence INTEGER NOT NULL UNIQUE CHECK(sequence BETWEEN 1 AND 4096),
  request_id TEXT NOT NULL UNIQUE REFERENCES device_registration(request_id),
  descriptor_body BLOB NOT NULL CHECK(length(descriptor_body) BETWEEN 1 AND 8192),
  descriptor_digest TEXT NOT NULL,
  initial_control_id TEXT NOT NULL UNIQUE,
  tx_id TEXT NOT NULL UNIQUE,
  UNIQUE(device_id,initial_control_id), UNIQUE(device_id,request_id),
  FOREIGN KEY(device_id,initial_control_id) REFERENCES device_control_history(device_id,record_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(tx_id,device_id,request_id) REFERENCES device_registration_commit(tx_id,device_id,request_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE device_control_history (
  record_id TEXT PRIMARY KEY NOT NULL,
  device_id TEXT NOT NULL REFERENCES device_record(device_id),
  revision TEXT NOT NULL CHECK(revision='1'),
  control_epoch TEXT NOT NULL,
  body BLOB NOT NULL CHECK(length(body) BETWEEN 1 AND 8192),
  digest TEXT NOT NULL,
  UNIQUE(device_id,record_id), UNIQUE(device_id,revision),
  FOREIGN KEY(device_id,record_id) REFERENCES device_record(device_id,initial_control_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE device_registration_commit (
  tx_id TEXT PRIMARY KEY NOT NULL,
  device_id TEXT NOT NULL UNIQUE,
  request_id TEXT NOT NULL UNIQUE REFERENCES device_registration(request_id),
  receipt_body BLOB NOT NULL CHECK(length(receipt_body) BETWEEN 1 AND 8192),
  receipt_digest TEXT NOT NULL,
  audit_body BLOB NOT NULL CHECK(length(audit_body) BETWEEN 1 AND 8192),
  event_id TEXT NOT NULL UNIQUE,
  notification_body BLOB NOT NULL CHECK(length(notification_body) BETWEEN 1 AND 8192),
  UNIQUE(tx_id,device_id,request_id),
  FOREIGN KEY(device_id,request_id) REFERENCES device_record(device_id,request_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER device_sequence BEFORE INSERT ON device_record
WHEN NEW.sequence != (SELECT revision+1 FROM device_catalog WHERE singleton=1)
BEGIN SELECT RAISE(ABORT,'device_catalog_sequence'); END;
CREATE TRIGGER device_catalog_advance AFTER INSERT ON device_record
BEGIN UPDATE device_catalog SET revision=NEW.sequence WHERE singleton=1; END;
CREATE TRIGGER device_catalog_revision BEFORE UPDATE ON device_catalog
WHEN NEW.singleton!=OLD.singleton OR NEW.revision!=OLD.revision+1 OR NEW.revision!=(SELECT count(*) FROM device_record)
BEGIN SELECT RAISE(ABORT,'device_catalog_revision'); END;
CREATE TRIGGER device_catalog_no_delete BEFORE DELETE ON device_catalog
BEGIN SELECT RAISE(ABORT,'device_catalog_required'); END;
CREATE TRIGGER device_registration_no_update BEFORE UPDATE ON device_registration
BEGIN SELECT RAISE(ABORT,'immutable_device_registration'); END;
CREATE TRIGGER device_registration_no_delete BEFORE DELETE ON device_registration
BEGIN SELECT RAISE(ABORT,'immutable_device_registration'); END;
CREATE TRIGGER device_record_no_update BEFORE UPDATE ON device_record
BEGIN SELECT RAISE(ABORT,'immutable_device_registration'); END;
CREATE TRIGGER device_record_no_delete BEFORE DELETE ON device_record
BEGIN SELECT RAISE(ABORT,'device_history_required'); END;
CREATE TRIGGER device_control_no_update BEFORE UPDATE ON device_control_history
BEGIN SELECT RAISE(ABORT,'immutable_control_history'); END;
CREATE TRIGGER device_control_no_delete BEFORE DELETE ON device_control_history
BEGIN SELECT RAISE(ABORT,'control_history_required'); END;
CREATE TRIGGER device_commit_no_update BEFORE UPDATE ON device_registration_commit
BEGIN SELECT RAISE(ABORT,'immutable_device_commit'); END;
CREATE TRIGGER device_commit_no_delete BEFORE DELETE ON device_registration_commit
BEGIN SELECT RAISE(ABORT,'device_commit_required'); END;
