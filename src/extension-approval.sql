DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v17 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '17'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v17 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '17', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v17 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v17 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17')),
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
    OR (from_revision = '16' AND to_revision = '17' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v17 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v17 RENAME TO schema_migration;
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

CREATE TABLE extension_approval (
 approval_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
 installation_id TEXT NOT NULL UNIQUE COLLATE BINARY,
 review_id TEXT NOT NULL COLLATE BINARY,
 review_revision INTEGER NOT NULL,
 operation_id TEXT NOT NULL UNIQUE COLLATE BINARY,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 body_digest TEXT NOT NULL COLLATE BINARY,
 permissions_jcs TEXT NOT NULL CHECK(json_valid(permissions_jcs)),
 permissions_digest TEXT NOT NULL COLLATE BINARY,
 FOREIGN KEY(review_id,review_revision,installation_id) REFERENCES extension_permission_review(review_id,revision,installation_id),
 FOREIGN KEY(operation_id) REFERENCES extension_approval_operation(operation_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE extension_approval_deny (
 deny_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
 approval_id TEXT NOT NULL UNIQUE COLLATE BINARY REFERENCES extension_approval(approval_id),
 operation_id TEXT NOT NULL UNIQUE COLLATE BINARY,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 body_digest TEXT NOT NULL COLLATE BINARY,
 FOREIGN KEY(operation_id) REFERENCES extension_approval_operation(operation_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE extension_approval_operation (
 credential_id TEXT NOT NULL COLLATE BINARY REFERENCES session_refresh_credential(credential_id),
 request_id TEXT NOT NULL COLLATE BINARY,
 operation_id TEXT NOT NULL UNIQUE COLLATE BINARY,
 kind TEXT NOT NULL CHECK(kind IN ('approve','revoke')),
 approval_id TEXT NOT NULL COLLATE BINARY REFERENCES extension_approval(approval_id) DEFERRABLE INITIALLY DEFERRED,
 principal_id TEXT NOT NULL COLLATE BINARY REFERENCES local_principal(principal_id),
 session_id TEXT NOT NULL COLLATE BINARY REFERENCES auth_session(session_id),
 input_jcs TEXT NOT NULL CHECK(json_valid(input_jcs)),
 input_digest TEXT NOT NULL COLLATE BINARY,
 operation_jcs TEXT NOT NULL CHECK(json_valid(operation_jcs)),
 operation_digest TEXT NOT NULL COLLATE BINARY,
 result_jcs TEXT NOT NULL CHECK(json_valid(result_jcs)),
 result_digest TEXT NOT NULL COLLATE BINARY,
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 PRIMARY KEY(credential_id,request_id)
) STRICT;
CREATE TRIGGER extension_approval_operation_actor BEFORE INSERT ON extension_approval_operation
WHEN NOT EXISTS(SELECT 1 FROM auth_session s JOIN session_refresh_credential c USING(session_id)
 JOIN local_principal p USING(principal_id) WHERE s.session_id=NEW.session_id AND c.credential_id=NEW.credential_id
 AND s.principal_id=NEW.principal_id AND s.state='active' AND c.state!='revoked' AND p.state='active')
 OR json_extract(NEW.audit_jcs,'$.operation_id') IS NOT NEW.operation_id
 OR json_extract(NEW.audit_jcs,'$.result_digest') IS NOT NEW.result_digest
 OR (NEW.kind='approve' AND NOT EXISTS(SELECT 1 FROM extension_approval WHERE approval_id=NEW.approval_id AND operation_id=NEW.operation_id))
 OR (NEW.kind='revoke' AND NOT EXISTS(SELECT 1 FROM extension_approval_deny WHERE approval_id=NEW.approval_id))
BEGIN SELECT RAISE(ABORT,'extension_approval_actor_or_write_set'); END;
CREATE TRIGGER extension_approval_no_update BEFORE UPDATE ON extension_approval
BEGIN SELECT RAISE(ABORT,'extension_approval_history'); END;
CREATE TRIGGER extension_approval_no_delete BEFORE DELETE ON extension_approval
BEGIN SELECT RAISE(ABORT,'extension_approval_history'); END;
CREATE TRIGGER extension_approval_deny_no_update BEFORE UPDATE ON extension_approval_deny
BEGIN SELECT RAISE(ABORT,'extension_approval_history'); END;
CREATE TRIGGER extension_approval_deny_no_delete BEFORE DELETE ON extension_approval_deny
BEGIN SELECT RAISE(ABORT,'extension_approval_history'); END;
CREATE TRIGGER extension_approval_operation_no_update BEFORE UPDATE ON extension_approval_operation
BEGIN SELECT RAISE(ABORT,'extension_approval_history'); END;
CREATE TRIGGER extension_approval_operation_no_delete BEFORE DELETE ON extension_approval_operation
BEGIN SELECT RAISE(ABORT,'extension_approval_history'); END;
CREATE TRIGGER extension_configuration_approved BEFORE INSERT ON extension_configuration
WHEN EXISTS(SELECT 1 FROM extension_approval WHERE installation_id=NEW.installation_id)
BEGIN SELECT RAISE(ABORT,'extension_approved_frozen'); END;
CREATE TRIGGER extension_role_resolution_approved BEFORE INSERT ON extension_role_resolution
WHEN EXISTS(SELECT 1 FROM extension_approval WHERE installation_id=NEW.installation_id)
BEGIN SELECT RAISE(ABORT,'extension_approved_frozen'); END;
CREATE TRIGGER extension_permission_review_approved BEFORE INSERT ON extension_permission_review
WHEN EXISTS(SELECT 1 FROM extension_approval WHERE installation_id=NEW.installation_id)
BEGIN SELECT RAISE(ABORT,'extension_approved_frozen'); END;
