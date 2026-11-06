DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v38 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '38'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v38 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '38', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v38 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v38 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38')),
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
    OR (from_revision = '37' AND to_revision = '38' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v38 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v38 RENAME TO schema_migration;
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

CREATE TABLE device_evaluator_operation (
 operation_id TEXT PRIMARY KEY NOT NULL,actor_key TEXT NOT NULL,request_id TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('policy','revoke','expire','challenge','source')),
 request_digest TEXT NOT NULL,acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=65536),body_digest TEXT NOT NULL,UNIQUE(actor_key,request_id)
) STRICT;
CREATE TABLE device_evaluator_policy (
 policy_id TEXT PRIMARY KEY NOT NULL,principal_id TEXT NOT NULL UNIQUE REFERENCES service_principal_head(principal_id),approval_id TEXT NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL,
 operation_id TEXT NOT NULL REFERENCES device_evaluator_operation(operation_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(approval_id,principal_id) REFERENCES service_approval(approval_id,principal_id),
 CHECK(json_extract(body_jcs,'$.id')=policy_id AND json_extract(body_jcs,'$.principal_id')=principal_id AND json_extract(body_jcs,'$.approval_ref.id')=approval_id AND json_extract(body_jcs,'$.digest')=body_digest)
) STRICT;
CREATE TABLE device_evaluator_policy_revocation (
 revocation_id TEXT PRIMARY KEY NOT NULL,policy_id TEXT NOT NULL UNIQUE REFERENCES device_evaluator_policy(policy_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL,
 operation_id TEXT NOT NULL REFERENCES device_evaluator_operation(operation_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(json_extract(body_jcs,'$.id')=revocation_id AND json_extract(body_jcs,'$.policy_ref.id')=policy_id AND json_extract(body_jcs,'$.digest')=body_digest)
) STRICT;
CREATE TABLE device_evaluator_challenge (
 challenge_id TEXT PRIMARY KEY NOT NULL,policy_id TEXT NOT NULL REFERENCES device_evaluator_policy(policy_id),
 core_source_id TEXT NOT NULL REFERENCES core_runtime_source(source_id),device_id TEXT NOT NULL REFERENCES device_record(device_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL,
 operation_id TEXT NOT NULL REFERENCES device_evaluator_operation(operation_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(json_extract(body_jcs,'$.id')=challenge_id AND json_extract(body_jcs,'$.policy_ref.id')=policy_id
 AND json_extract(body_jcs,'$.core_runtime_source_ref.id')=core_source_id AND json_extract(body_jcs,'$.device_id')=device_id AND json_extract(body_jcs,'$.digest')=body_digest)
) STRICT;
CREATE TABLE device_evaluator_source (
 source_id TEXT PRIMARY KEY NOT NULL,challenge_id TEXT NOT NULL UNIQUE REFERENCES device_evaluator_challenge(challenge_id),
 credential_id TEXT NOT NULL REFERENCES service_credential(credential_id),request_digest TEXT NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL,
 acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
 operation_id TEXT NOT NULL REFERENCES device_evaluator_operation(operation_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(json_extract(body_jcs,'$.id')=source_id AND json_extract(body_jcs,'$.challenge_ref.id')=challenge_id AND json_extract(body_jcs,'$.credential_ref.id')=credential_id
 AND json_extract(body_jcs,'$.response_digest')=request_digest AND json_extract(body_jcs,'$.authentication_acquisition_ref.id')=acquisition_id AND json_extract(body_jcs,'$.digest')=body_digest)
) STRICT;
CREATE TRIGGER device_evaluator_source_parent BEFORE INSERT ON device_evaluator_source
WHEN NOT EXISTS(SELECT 1 FROM device_evaluator_challenge h JOIN device_evaluator_policy p USING(policy_id)
 JOIN service_credential c ON c.principal_id=p.principal_id JOIN service_credential_head ch USING(credential_id)
 JOIN service_credential_revision cr USING(credential_id,revision) WHERE h.challenge_id=NEW.challenge_id AND c.credential_id=NEW.credential_id AND cr.state='active'
 AND NOT EXISTS(SELECT 1 FROM device_evaluator_policy_revocation v WHERE v.policy_id=p.policy_id)
 AND json_extract(NEW.body_jcs,'$.credential_ref.revision')=CAST(cr.revision AS TEXT) AND json_extract(NEW.body_jcs,'$.credential_ref.digest')=cr.body_digest
 AND json_extract(NEW.body_jcs,'$.challenge_ref.digest')=h.body_digest AND json_extract(NEW.body_jcs,'$.policy_ref.digest')=p.body_digest
 AND json_extract(NEW.body_jcs,'$.core_runtime_source_ref.id')=h.core_source_id AND json_extract(NEW.body_jcs,'$.device_id')=h.device_id)
BEGIN SELECT RAISE(ABORT,'device_evaluator_source_parent'); END;

CREATE TRIGGER device_evaluator_operation_no_update BEFORE UPDATE ON device_evaluator_operation BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_operation_no_delete BEFORE DELETE ON device_evaluator_operation BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_policy_no_update BEFORE UPDATE ON device_evaluator_policy BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_policy_no_delete BEFORE DELETE ON device_evaluator_policy BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_policy_revocation_no_update BEFORE UPDATE ON device_evaluator_policy_revocation BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_policy_revocation_no_delete BEFORE DELETE ON device_evaluator_policy_revocation BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_challenge_no_update BEFORE UPDATE ON device_evaluator_challenge BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_challenge_no_delete BEFORE DELETE ON device_evaluator_challenge BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_source_no_update BEFORE UPDATE ON device_evaluator_source BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;

CREATE TRIGGER device_evaluator_source_no_delete BEFORE DELETE ON device_evaluator_source BEGIN SELECT RAISE(ABORT,'immutable_device_evaluator'); END;
