DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v13 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '13'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v13 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '13', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v13 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v13 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13')),
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
    OR (from_revision = '12' AND to_revision = '13' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v13 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v13 RENAME TO schema_migration;
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

CREATE TABLE extension_operation (
  request_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  operation_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  kind TEXT NOT NULL CHECK(kind IN ('create_slot','stage')),
  slot_id TEXT NOT NULL COLLATE BINARY,
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 4096),
  installation_id TEXT UNIQUE COLLATE BINARY,
  input_jcs TEXT NOT NULL CHECK(json_valid(input_jcs)),
  input_digest TEXT NOT NULL COLLATE BINARY,
  result_jcs TEXT NOT NULL CHECK(json_valid(result_jcs)),
  result_digest TEXT NOT NULL COLLATE BINARY,
  audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
  UNIQUE(operation_id,slot_id,revision),
  UNIQUE(operation_id,installation_id),
  CHECK((kind='create_slot' AND installation_id IS NULL AND revision=1)
    OR (kind='stage' AND installation_id IS NOT NULL AND revision>1)),
  FOREIGN KEY(slot_id,revision,operation_id) REFERENCES extension_slot_revision(slot_id,revision,operation_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(installation_id,operation_id) REFERENCES extension_candidate(installation_id,operation_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE extension_slot_revision (
  slot_id TEXT NOT NULL COLLATE BINARY,
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 4096),
  operation_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  extension_id TEXT NOT NULL COLLATE BINARY,
  body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
  body_digest TEXT NOT NULL COLLATE BINARY,
  PRIMARY KEY(slot_id,revision),
  UNIQUE(slot_id,revision,operation_id),
  CHECK(json_extract(body_jcs,'$.slot_id') IS slot_id AND json_extract(body_jcs,'$.extension_id') IS extension_id
    AND json_extract(body_jcs,'$.revision') IS CAST(revision AS TEXT) AND json_extract(body_jcs,'$.active_installation_id') IS NULL),
  FOREIGN KEY(operation_id,slot_id,revision) REFERENCES extension_operation(operation_id,slot_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE extension_slot_head (
  slot_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  revision INTEGER NOT NULL,
  FOREIGN KEY(slot_id,revision) REFERENCES extension_slot_revision(slot_id,revision)
) STRICT;
CREATE TABLE extension_candidate (
  installation_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  operation_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  slot_id TEXT NOT NULL COLLATE BINARY,
  slot_revision INTEGER NOT NULL,
  content_jcs TEXT NOT NULL CHECK(json_valid(content_jcs)),
  content_digest TEXT NOT NULL COLLATE BINARY,
  state TEXT NOT NULL CHECK(state='verified'),
  UNIQUE(installation_id,operation_id),
  CHECK(json_extract(content_jcs,'$.installation_id') IS installation_id
    AND json_extract(content_jcs,'$.slot_id') IS slot_id),
  FOREIGN KEY(operation_id,installation_id) REFERENCES extension_operation(operation_id,installation_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(slot_id,slot_revision,operation_id) REFERENCES extension_slot_revision(slot_id,revision,operation_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER extension_slot_order BEFORE INSERT ON extension_slot_revision
WHEN (NEW.revision=1 AND EXISTS(SELECT 1 FROM extension_slot_head WHERE slot_id=NEW.slot_id)) OR
  (NEW.revision>1 AND NOT EXISTS(SELECT 1 FROM extension_slot_head h JOIN extension_slot_revision r USING(slot_id,revision)
    WHERE h.slot_id=NEW.slot_id AND h.revision=NEW.revision-1 AND r.extension_id=NEW.extension_id))
BEGIN SELECT RAISE(ABORT,'extension_slot_revision'); END;
CREATE TRIGGER extension_head_insert BEFORE INSERT ON extension_slot_head WHEN NEW.revision!=1
BEGIN SELECT RAISE(ABORT,'extension_slot_revision'); END;
CREATE TRIGGER extension_head_update BEFORE UPDATE ON extension_slot_head
WHEN NEW.slot_id!=OLD.slot_id OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'extension_slot_revision'); END;
CREATE TRIGGER extension_head_no_delete BEFORE DELETE ON extension_slot_head
BEGIN SELECT RAISE(ABORT,'extension_history_required'); END;
CREATE TRIGGER extension_operation_complete BEFORE INSERT ON extension_operation
WHEN NOT EXISTS(SELECT 1 FROM extension_slot_head WHERE slot_id=NEW.slot_id AND revision=NEW.revision)
  OR json_extract(NEW.audit_jcs,'$.operation_id') IS NOT NEW.operation_id
  OR json_extract(NEW.audit_jcs,'$.request_id') IS NOT NEW.request_id
  OR json_extract(NEW.audit_jcs,'$.slot_id') IS NOT NEW.slot_id
  OR json_extract(NEW.audit_jcs,'$.installation_id') IS NOT NEW.installation_id
  OR json_extract(NEW.audit_jcs,'$.result_digest') IS NOT NEW.result_digest
BEGIN SELECT RAISE(ABORT,'extension_operation_incomplete'); END;
CREATE TRIGGER extension_operation_no_update BEFORE UPDATE ON extension_operation
BEGIN SELECT RAISE(ABORT,'immutable_extension_operation'); END;
CREATE TRIGGER extension_operation_no_delete BEFORE DELETE ON extension_operation
BEGIN SELECT RAISE(ABORT,'extension_history_required'); END;
CREATE TRIGGER extension_slot_no_update BEFORE UPDATE ON extension_slot_revision
BEGIN SELECT RAISE(ABORT,'immutable_extension_slot'); END;
CREATE TRIGGER extension_slot_no_delete BEFORE DELETE ON extension_slot_revision
BEGIN SELECT RAISE(ABORT,'extension_history_required'); END;
CREATE TRIGGER extension_candidate_no_update BEFORE UPDATE ON extension_candidate
BEGIN SELECT RAISE(ABORT,'immutable_extension_candidate'); END;
CREATE TRIGGER extension_candidate_no_delete BEFORE DELETE ON extension_candidate
BEGIN SELECT RAISE(ABORT,'extension_history_required'); END;
