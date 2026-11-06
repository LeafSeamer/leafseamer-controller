DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v40 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '40'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v40 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '40', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v40 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v40 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40')),
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
    OR (from_revision = '28' AND to_revision = '29' AND backup_ref IS NOT NULL)
    OR (from_revision = '29' AND to_revision = '30' AND backup_ref IS NOT NULL)
    OR (from_revision = '30' AND to_revision = '31' AND backup_ref IS NOT NULL)
    OR (from_revision = '31' AND to_revision = '32' AND backup_ref IS NOT NULL)
    OR (from_revision = '32' AND to_revision = '33' AND backup_ref IS NOT NULL)
    OR (from_revision = '33' AND to_revision = '34' AND backup_ref IS NOT NULL)
    OR (from_revision = '34' AND to_revision = '35' AND backup_ref IS NOT NULL)
    OR (from_revision = '35' AND to_revision = '36' AND backup_ref IS NOT NULL)
    OR (from_revision = '36' AND to_revision = '37' AND backup_ref IS NOT NULL)
    OR (from_revision = '37' AND to_revision = '38' AND backup_ref IS NOT NULL)
    OR (from_revision = '38' AND to_revision = '39' AND backup_ref IS NOT NULL)
    OR (from_revision = '39' AND to_revision = '40' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v40 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v40 RENAME TO schema_migration;
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

CREATE TRIGGER device_authorization_state_parent BEFORE INSERT ON device_authorization_state
WHEN NOT EXISTS (SELECT 1 FROM control_state_source s JOIN control_record_head h ON h.device_id=s.device_id AND h.revision=s.revision
 JOIN service_state v ON v.singleton=1 WHERE s.source_id=NEW.control_source_id AND s.device_id=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.format_version')='device-authorization-state/0.1.0-draft.1'
 AND json_extract(NEW.body_jcs,'$.state_id')=NEW.state_id
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.revision'),-20)=NEW.revision
 AND json_extract(NEW.body_jcs,'$.state_digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.parent_ref.id') IS NEW.parent_id
 AND json_extract(NEW.body_jcs,'$.status')='protected' AND json_extract(NEW.body_jcs,'$.recovery_ref') IS NULL
 AND json_extract(NEW.body_jcs,'$.context.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.context.scope.authority_service_id')=v.service_id
 AND json_extract(NEW.body_jcs,'$.context.scope.database_instance_id')=v.database_instance_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.id')=s.source_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.revision')=CAST(s.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'device_authorization_state_parent'); END;

CREATE TABLE device_recovery_request (
 request_id TEXT PRIMARY KEY NOT NULL,key_digest TEXT NOT NULL UNIQUE,request_digest TEXT NOT NULL,
 device_id TEXT NOT NULL,principal_id TEXT NOT NULL,token_id TEXT NOT NULL,state_id TEXT NOT NULL,
 body_jcs TEXT NOT NULL,body_digest TEXT NOT NULL,authorization_id TEXT NOT NULL UNIQUE,commit_id TEXT NOT NULL UNIQUE,
 FOREIGN KEY(device_id) REFERENCES device_record(device_id), FOREIGN KEY(principal_id) REFERENCES local_principal(principal_id),
 FOREIGN KEY(token_id) REFERENCES access_token(token_id), FOREIGN KEY(state_id) REFERENCES device_authorization_state(state_id),
 FOREIGN KEY(authorization_id) REFERENCES device_recovery_authorization(authorization_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(commit_id) REFERENCES device_recovery_commit(request_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(commit_id=request_id)
) STRICT;
CREATE TABLE device_recovery_authorization (
 authorization_id TEXT PRIMARY KEY NOT NULL,request_id TEXT NOT NULL UNIQUE,device_id TEXT NOT NULL,protected_state_id TEXT NOT NULL,
 manual_source_id TEXT NOT NULL,evaluator_source_id TEXT NOT NULL,body_jcs TEXT NOT NULL,body_digest TEXT NOT NULL,
 FOREIGN KEY(request_id) REFERENCES device_recovery_request(request_id),
 FOREIGN KEY(device_id,protected_state_id) REFERENCES device_authorization_state(device_id,state_id),
 FOREIGN KEY(manual_source_id) REFERENCES execution_manual_authority(source_id),
 FOREIGN KEY(evaluator_source_id) REFERENCES device_evaluator_source(source_id)
) STRICT;
CREATE TABLE device_recovery_commit (
 request_id TEXT PRIMARY KEY NOT NULL,body_jcs TEXT NOT NULL,body_digest TEXT NOT NULL,
 FOREIGN KEY(request_id) REFERENCES device_recovery_request(request_id)
) STRICT;
CREATE TRIGGER device_recovery_request_parent BEFORE INSERT ON device_recovery_request
WHEN NOT EXISTS(SELECT 1 FROM device_authorization_head h JOIN device_authorization_state s USING(state_id)
 JOIN access_token t ON t.token_id=NEW.token_id JOIN auth_session a ON a.session_id=t.session_id
 WHERE h.device_id=NEW.device_id AND s.state_id=NEW.state_id AND a.principal_id=NEW.principal_id
 AND json_extract(s.body_jcs,'$.status')='protected' AND a.state='active' AND t.state='active')
BEGIN SELECT RAISE(ABORT,'device_recovery_request_parent'); END;
CREATE TRIGGER device_recovery_authorization_parent BEFORE INSERT ON device_recovery_authorization
WHEN NOT EXISTS(SELECT 1 FROM device_recovery_request r JOIN execution_manual_authority m ON m.source_id=NEW.manual_source_id
 JOIN device_evaluator_source e ON e.source_id=NEW.evaluator_source_id JOIN device_evaluator_challenge ch ON ch.challenge_id=e.challenge_id
 WHERE r.request_id=NEW.request_id AND r.authorization_id=NEW.authorization_id AND r.device_id=NEW.device_id
 AND r.state_id=NEW.protected_state_id AND m.device_id=r.device_id AND ch.device_id=r.device_id AND m.token_id=r.token_id)
BEGIN SELECT RAISE(ABORT,'device_recovery_authorization_parent'); END;
CREATE TRIGGER device_recovery_request_no_update BEFORE UPDATE ON device_recovery_request BEGIN SELECT RAISE(ABORT,'immutable_device_recovery'); END;
CREATE TRIGGER device_recovery_request_no_delete BEFORE DELETE ON device_recovery_request BEGIN SELECT RAISE(ABORT,'immutable_device_recovery'); END;
CREATE TRIGGER device_recovery_authorization_no_update BEFORE UPDATE ON device_recovery_authorization BEGIN SELECT RAISE(ABORT,'immutable_device_recovery'); END;
CREATE TRIGGER device_recovery_authorization_no_delete BEFORE DELETE ON device_recovery_authorization BEGIN SELECT RAISE(ABORT,'immutable_device_recovery'); END;
CREATE TRIGGER device_recovery_commit_no_update BEFORE UPDATE ON device_recovery_commit BEGIN SELECT RAISE(ABORT,'immutable_device_recovery'); END;
CREATE TRIGGER device_recovery_commit_no_delete BEFORE DELETE ON device_recovery_commit BEGIN SELECT RAISE(ABORT,'immutable_device_recovery'); END;
