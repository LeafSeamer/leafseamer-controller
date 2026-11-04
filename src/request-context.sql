DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v8 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '8'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v8 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '8', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v8 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v8 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8')),
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
    OR (from_revision = '7' AND to_revision = '8' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v8 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v8 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

CREATE TABLE request_context (
  context_id TEXT PRIMARY KEY NOT NULL,
  service_id TEXT NOT NULL, database_instance_id TEXT NOT NULL,
  issuer_id TEXT NOT NULL, issuer_epoch TEXT NOT NULL, principal_id TEXT NOT NULL,
  context_epoch TEXT NOT NULL, service_boot_id TEXT NOT NULL REFERENCES service_boot(service_boot_id),
  session_id TEXT NOT NULL REFERENCES auth_session(session_id),
  credential_id TEXT NOT NULL REFERENCES session_refresh_credential(credential_id),
  token_id TEXT NOT NULL REFERENCES access_token(token_id),
  not_before_ns TEXT NOT NULL CHECK(length(not_before_ns) = 20),
  expires_ns TEXT NOT NULL CHECK(length(expires_ns) = 20 AND expires_ns > not_before_ns),
  max_unique_requests INTEGER NOT NULL CHECK(max_unique_requests BETWEEN 1 AND 256),
  used_count INTEGER NOT NULL DEFAULT 0 CHECK(used_count BETWEEN 0 AND max_unique_requests),
  state TEXT NOT NULL CHECK(state IN ('active', 'closed', 'expired')),
  closed_reason TEXT,
  body BLOB NOT NULL CHECK(length(body) <= 16384), body_digest TEXT NOT NULL,
  acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
  tx_id TEXT NOT NULL UNIQUE,
  CHECK((state = 'active' AND closed_reason IS NULL) OR (state != 'active' AND closed_reason IS NOT NULL)),
  FOREIGN KEY(service_id, database_instance_id) REFERENCES service_state(service_id, database_instance_id),
  FOREIGN KEY(issuer_id, issuer_epoch, principal_id) REFERENCES subject(issuer_id, issuer_epoch, principal_id),
  UNIQUE(service_id, database_instance_id, issuer_id, issuer_epoch, principal_id, context_epoch, context_id)
) STRICT;
CREATE INDEX request_context_principal_issued ON request_context(principal_id, not_before_ns);
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
CREATE TRIGGER request_context_transition BEFORE UPDATE ON request_context
WHEN OLD.state != 'active' OR NEW.context_id != OLD.context_id OR NEW.service_id != OLD.service_id
  OR NEW.database_instance_id != OLD.database_instance_id OR NEW.issuer_id != OLD.issuer_id
  OR NEW.issuer_epoch != OLD.issuer_epoch OR NEW.principal_id != OLD.principal_id
  OR NEW.context_epoch != OLD.context_epoch OR NEW.service_boot_id != OLD.service_boot_id
  OR NEW.session_id != OLD.session_id OR NEW.credential_id != OLD.credential_id OR NEW.token_id != OLD.token_id
  OR NEW.not_before_ns != OLD.not_before_ns OR NEW.expires_ns != OLD.expires_ns
  OR NEW.max_unique_requests != OLD.max_unique_requests OR NEW.used_count < OLD.used_count
  OR NEW.body != OLD.body OR NEW.body_digest != OLD.body_digest OR NEW.acquisition_id != OLD.acquisition_id OR NEW.tx_id != OLD.tx_id
BEGIN SELECT RAISE(ABORT, 'request_context_immutable'); END;
CREATE TRIGGER request_context_no_delete BEFORE DELETE ON request_context
BEGIN SELECT RAISE(ABORT, 'request_context_history_required'); END;
CREATE TRIGGER request_context_token_closed AFTER UPDATE OF state ON access_token
WHEN NEW.state != 'active'
BEGIN UPDATE request_context SET state = 'closed', closed_reason = 'token_closed' WHERE token_id = NEW.token_id AND state = 'active'; END;
CREATE TRIGGER request_context_session_closed AFTER UPDATE OF state ON auth_session
WHEN NEW.state != 'active'
BEGIN UPDATE request_context SET state = 'closed', closed_reason = 'session_closed' WHERE session_id = NEW.session_id AND state = 'active'; END;
