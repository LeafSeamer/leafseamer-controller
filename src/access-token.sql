DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v6 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '6'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v6 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '6', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v6 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v6 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6')),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK((from_revision = '0' AND to_revision = '1' AND backup_ref IS NULL)
    OR (from_revision = '1' AND to_revision = '2' AND backup_ref IS NOT NULL)
    OR (from_revision = '2' AND to_revision = '3' AND backup_ref IS NOT NULL)
    OR (from_revision = '3' AND to_revision = '4' AND backup_ref IS NOT NULL)
    OR (from_revision = '4' AND to_revision = '5' AND backup_ref IS NOT NULL)
    OR (from_revision = '5' AND to_revision = '6' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v6 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v6 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

CREATE TABLE access_token (
  token_id TEXT PRIMARY KEY NOT NULL,
  credential_id TEXT NOT NULL REFERENCES session_refresh_credential(credential_id),
  session_id TEXT NOT NULL REFERENCES auth_session(session_id),
  request_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  verifier BLOB NOT NULL CHECK(length(verifier) = 32),
  verifier_profile TEXT NOT NULL CHECK(verifier_profile = 'identity-runtime/1:access_token'),
  audience TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('active', 'expired', 'revoked')),
  not_before_ns TEXT NOT NULL CHECK(length(not_before_ns) = 20),
  expires_ns TEXT NOT NULL CHECK(length(expires_ns) = 20 AND expires_ns > not_before_ns),
  authorization_digest TEXT NOT NULL,
  authorization_body BLOB NOT NULL CHECK(length(authorization_body) <= 32768),
  acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
  tx_id TEXT NOT NULL UNIQUE,
  UNIQUE(credential_id, request_id)
) STRICT;
CREATE INDEX access_token_capacity ON access_token(credential_id, state, expires_ns);
CREATE INDEX access_token_session ON access_token(session_id, state);
CREATE TRIGGER access_token_parent BEFORE INSERT ON access_token
WHEN NOT EXISTS (SELECT 1 FROM auth_session s JOIN session_refresh_credential c ON c.session_id = s.session_id
  WHERE s.session_id = NEW.session_id AND c.credential_id = NEW.credential_id AND s.state = 'active' AND c.state = 'active')
BEGIN SELECT RAISE(ABORT, 'access_token_parent_closed'); END;
CREATE TRIGGER access_token_transition BEFORE UPDATE ON access_token
WHEN OLD.state != 'active' OR NEW.state = 'active' OR NEW.token_id != OLD.token_id
  OR NEW.credential_id != OLD.credential_id OR NEW.session_id != OLD.session_id OR NEW.request_id != OLD.request_id
  OR NEW.request_digest != OLD.request_digest OR NEW.verifier != OLD.verifier OR NEW.verifier_profile != OLD.verifier_profile
  OR NEW.audience != OLD.audience OR NEW.not_before_ns != OLD.not_before_ns OR NEW.expires_ns != OLD.expires_ns
  OR NEW.authorization_digest != OLD.authorization_digest OR NEW.authorization_body != OLD.authorization_body
  OR NEW.acquisition_id != OLD.acquisition_id OR NEW.tx_id != OLD.tx_id
BEGIN SELECT RAISE(ABORT, 'invalid_access_token_transition'); END;
CREATE TRIGGER access_token_no_delete BEFORE DELETE ON access_token
BEGIN SELECT RAISE(ABORT, 'access_token_history_required'); END;
CREATE TRIGGER auth_session_revoke_tokens AFTER UPDATE OF state ON auth_session
WHEN OLD.state = 'active' AND NEW.state != 'active'
BEGIN UPDATE access_token SET state = 'revoked' WHERE session_id = NEW.session_id AND state = 'active'; END;
