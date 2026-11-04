DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v5 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '5'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v5 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '5', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v5 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v5 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5')),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK((from_revision = '0' AND to_revision = '1' AND backup_ref IS NULL)
    OR (from_revision = '1' AND to_revision = '2' AND backup_ref IS NOT NULL)
    OR (from_revision = '2' AND to_revision = '3' AND backup_ref IS NOT NULL)
    OR (from_revision = '3' AND to_revision = '4' AND backup_ref IS NOT NULL)
    OR (from_revision = '4' AND to_revision = '5' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v5 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v5 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

CREATE TABLE auth_session (
  session_id TEXT PRIMARY KEY NOT NULL,
  principal_id TEXT NOT NULL REFERENCES local_principal(principal_id),
  issuer_id TEXT NOT NULL, issuer_epoch TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('active', 'revoked', 'expired')),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  not_before_ns TEXT NOT NULL CHECK(length(not_before_ns) = 20),
  expires_ns TEXT NOT NULL CHECK(length(expires_ns) = 20),
  idle_before_ns TEXT NOT NULL CHECK(length(idle_before_ns) = 20 AND idle_before_ns <= expires_ns),
  recent_before_ns TEXT NOT NULL CHECK(length(recent_before_ns) = 20 AND recent_before_ns <= expires_ns),
  csrf_verifier BLOB NOT NULL CHECK(length(csrf_verifier) = 32),
  created_acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
  created_tx_id TEXT NOT NULL UNIQUE,
  terminal_operation_id TEXT UNIQUE REFERENCES session_revocation(operation_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK((state = 'active' AND terminal_operation_id IS NULL) OR (state != 'active' AND terminal_operation_id IS NOT NULL)),
  FOREIGN KEY(issuer_id, issuer_epoch, principal_id) REFERENCES subject(issuer_id, issuer_epoch, principal_id)
) STRICT;
CREATE TRIGGER auth_session_transition BEFORE UPDATE ON auth_session
WHEN OLD.state != 'active' OR NEW.session_id != OLD.session_id OR NEW.principal_id != OLD.principal_id
  OR NEW.issuer_id != OLD.issuer_id OR NEW.issuer_epoch != OLD.issuer_epoch
  OR NEW.not_before_ns != OLD.not_before_ns OR NEW.expires_ns != OLD.expires_ns
  OR NEW.recent_before_ns != OLD.recent_before_ns OR NEW.csrf_verifier != OLD.csrf_verifier
  OR NEW.created_acquisition_id != OLD.created_acquisition_id OR NEW.created_tx_id != OLD.created_tx_id
  OR NEW.idle_before_ns < OLD.idle_before_ns OR NEW.revision < OLD.revision
BEGIN SELECT RAISE(ABORT, 'invalid_session_transition'); END;
CREATE TRIGGER auth_session_no_delete BEFORE DELETE ON auth_session
BEGIN SELECT RAISE(ABORT, 'session_history_required'); END;

CREATE TABLE session_refresh_credential (
  credential_id TEXT PRIMARY KEY NOT NULL,
  session_id TEXT NOT NULL REFERENCES auth_session(session_id),
  verifier BLOB NOT NULL CHECK(length(verifier) = 32),
  state TEXT NOT NULL CHECK(state IN ('active', 'consumed', 'revoked')),
  created_acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
  created_tx_id TEXT NOT NULL,
  consumed_tx_id TEXT,
  CHECK((state = 'consumed' AND consumed_tx_id IS NOT NULL) OR (state != 'consumed' AND consumed_tx_id IS NULL))
) STRICT;
CREATE UNIQUE INDEX session_one_refresh ON session_refresh_credential(session_id) WHERE state = 'active';
CREATE TRIGGER session_refresh_transition BEFORE UPDATE ON session_refresh_credential
WHEN OLD.state != 'active' OR NEW.state = 'active' OR NEW.credential_id != OLD.credential_id
  OR NEW.session_id != OLD.session_id OR NEW.verifier != OLD.verifier
  OR NEW.created_acquisition_id != OLD.created_acquisition_id OR NEW.created_tx_id != OLD.created_tx_id
BEGIN SELECT RAISE(ABORT, 'invalid_refresh_transition'); END;
CREATE TRIGGER session_refresh_no_delete BEFORE DELETE ON session_refresh_credential
BEGIN SELECT RAISE(ABORT, 'refresh_history_required'); END;

CREATE TABLE session_audience (
  session_id TEXT NOT NULL REFERENCES auth_session(session_id), audience TEXT NOT NULL,
  first_tx_id TEXT NOT NULL, PRIMARY KEY(session_id, audience)
) STRICT;
CREATE TABLE session_target_binding (
  session_id TEXT NOT NULL REFERENCES auth_session(session_id), target_service_id TEXT NOT NULL,
  binding_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('execution', 'subscription')),
  PRIMARY KEY(session_id, target_service_id, binding_id)
) STRICT;
CREATE TABLE session_revocation (
  operation_id TEXT PRIMARY KEY NOT NULL,
  session_id TEXT NOT NULL UNIQUE REFERENCES auth_session(session_id),
  cause TEXT NOT NULL CHECK(cause IN ('logout', 'expired', 'refresh_reuse')),
  revision_floor INTEGER NOT NULL CHECK(revision_floor >= 2),
  acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
  tx_id TEXT NOT NULL UNIQUE,
  digest TEXT NOT NULL, body BLOB NOT NULL CHECK(length(body) <= 32768)
) STRICT;
CREATE TABLE session_revocation_floor (
  session_id TEXT PRIMARY KEY NOT NULL REFERENCES auth_session(session_id),
  revision_floor INTEGER NOT NULL CHECK(revision_floor >= 2),
  operation_id TEXT NOT NULL UNIQUE REFERENCES session_revocation(operation_id)
) STRICT;
CREATE TABLE session_revocation_target (
  operation_id TEXT NOT NULL REFERENCES session_revocation(operation_id), target_service_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state = 'pending'), PRIMARY KEY(operation_id, target_service_id)
) STRICT;
CREATE TABLE session_revocation_outbox (
  operation_id TEXT NOT NULL, target_service_id TEXT NOT NULL,
  PRIMARY KEY(operation_id, target_service_id),
  FOREIGN KEY(operation_id, target_service_id) REFERENCES session_revocation_target(operation_id, target_service_id)
) STRICT;
CREATE TABLE session_refresh_reuse (
  credential_id TEXT PRIMARY KEY NOT NULL REFERENCES session_refresh_credential(credential_id),
  operation_id TEXT NOT NULL REFERENCES session_revocation(operation_id),
  acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id)
) STRICT;
CREATE TRIGGER session_revocation_no_update BEFORE UPDATE ON session_revocation
BEGIN SELECT RAISE(ABORT, 'immutable_session_revocation'); END;
CREATE TRIGGER session_revocation_no_delete BEFORE DELETE ON session_revocation
BEGIN SELECT RAISE(ABORT, 'immutable_session_revocation'); END;
CREATE TRIGGER session_floor_no_update BEFORE UPDATE ON session_revocation_floor
BEGIN SELECT RAISE(ABORT, 'session_floor_required'); END;
CREATE TRIGGER session_floor_no_delete BEFORE DELETE ON session_revocation_floor
BEGIN SELECT RAISE(ABORT, 'session_floor_required'); END;
CREATE TRIGGER session_target_no_delete BEFORE DELETE ON session_revocation_target
BEGIN SELECT RAISE(ABORT, 'revocation_target_required'); END;
CREATE TRIGGER session_target_no_update BEFORE UPDATE ON session_revocation_target
BEGIN SELECT RAISE(ABORT, 'immutable_revocation_target'); END;
CREATE TRIGGER session_audience_active BEFORE INSERT ON session_audience
WHEN NOT EXISTS (SELECT 1 FROM auth_session WHERE session_id = NEW.session_id AND state = 'active')
BEGIN SELECT RAISE(ABORT, 'session_closed'); END;
CREATE TRIGGER session_binding_active BEFORE INSERT ON session_target_binding
WHEN NOT EXISTS (SELECT 1 FROM auth_session WHERE session_id = NEW.session_id AND state = 'active')
BEGIN SELECT RAISE(ABORT, 'session_closed'); END;
CREATE TRIGGER session_audience_no_update BEFORE UPDATE ON session_audience
BEGIN SELECT RAISE(ABORT, 'immutable_session_audience'); END;
CREATE TRIGGER session_audience_no_delete BEFORE DELETE ON session_audience
BEGIN SELECT RAISE(ABORT, 'session_audience_required'); END;
CREATE TRIGGER session_binding_no_update BEFORE UPDATE ON session_target_binding
BEGIN SELECT RAISE(ABORT, 'immutable_session_binding'); END;
