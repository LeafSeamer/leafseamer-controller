DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v34 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '34'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v34 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '34', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v34 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v34 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34')),
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
    OR (from_revision = '33' AND to_revision = '34' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v34 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v34 RENAME TO schema_migration;
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

-- 初始及控制变更保护状态；后续恢复采用完成前只允许protected。
CREATE TABLE device_authorization_state (
 state_id TEXT PRIMARY KEY NOT NULL,
 device_id TEXT NOT NULL REFERENCES device_record(device_id),
 revision TEXT NOT NULL CHECK(length(revision)=20 AND revision NOT GLOB '*[^0-9]*' AND revision>'00000000000000000000'),
 parent_id TEXT REFERENCES device_authorization_state(state_id),
 control_source_id TEXT NOT NULL REFERENCES control_state_source(source_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=16384),
 body_digest TEXT NOT NULL,commit_id TEXT NOT NULL UNIQUE,
 UNIQUE(device_id,revision),UNIQUE(device_id,state_id),UNIQUE(state_id,commit_id),
 FOREIGN KEY(commit_id,state_id) REFERENCES device_authorization_commit(commit_id,state_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE device_authorization_commit (
 commit_id TEXT PRIMARY KEY NOT NULL,device_id TEXT NOT NULL,state_id TEXT NOT NULL UNIQUE,
 parent_commit_id TEXT REFERENCES device_authorization_commit(commit_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL,
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),event_id TEXT NOT NULL UNIQUE,
 protection_jcs TEXT NOT NULL CHECK(json_valid(protection_jcs)),UNIQUE(commit_id,state_id),
 FOREIGN KEY(device_id,state_id) REFERENCES device_authorization_state(device_id,state_id),
 FOREIGN KEY(state_id,commit_id) REFERENCES device_authorization_state(state_id,commit_id)
) STRICT;
CREATE TABLE device_authorization_head (
 device_id TEXT PRIMARY KEY NOT NULL,state_id TEXT NOT NULL,commit_id TEXT NOT NULL,
 FOREIGN KEY(device_id,state_id) REFERENCES device_authorization_state(device_id,state_id),
 FOREIGN KEY(commit_id,state_id) REFERENCES device_authorization_commit(commit_id,state_id)
) STRICT;
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
CREATE TRIGGER device_authorization_initial BEFORE INSERT ON device_authorization_head
WHEN NOT EXISTS(SELECT 1 FROM device_authorization_state s WHERE s.state_id=NEW.state_id AND s.device_id=NEW.device_id
 AND s.revision='00000000000000000001' AND s.parent_id IS NULL)
BEGIN SELECT RAISE(ABORT,'device_authorization_initial'); END;
CREATE TRIGGER device_authorization_step BEFORE UPDATE ON device_authorization_head
WHEN NEW.device_id!=OLD.device_id OR NOT EXISTS(SELECT 1 FROM device_authorization_state n JOIN device_authorization_state p ON p.state_id=OLD.state_id
 WHERE n.state_id=NEW.state_id AND n.parent_id=p.state_id AND n.device_id=OLD.device_id AND n.revision>p.revision)
BEGIN SELECT RAISE(ABORT,'device_authorization_step'); END;
CREATE TRIGGER device_authorization_required BEFORE INSERT ON control_change_commit
WHEN EXISTS(SELECT 1 FROM control_state_source s WHERE s.source_id=NEW.commit_id AND NOT EXISTS(
 SELECT 1 FROM device_authorization_head h JOIN device_authorization_state a USING(state_id)
 JOIN device_authorization_commit c ON c.commit_id=h.commit_id AND c.state_id=a.state_id
 WHERE h.device_id=s.device_id AND a.control_source_id=s.source_id))
BEGIN SELECT RAISE(ABORT,'device_authorization_required'); END;
CREATE TRIGGER device_authorization_state_no_update BEFORE UPDATE ON device_authorization_state BEGIN SELECT RAISE(ABORT,'immutable_device_authorization'); END;
CREATE TRIGGER device_authorization_state_no_delete BEFORE DELETE ON device_authorization_state BEGIN SELECT RAISE(ABORT,'immutable_device_authorization'); END;
CREATE TRIGGER device_authorization_commit_no_update BEFORE UPDATE ON device_authorization_commit BEGIN SELECT RAISE(ABORT,'immutable_device_authorization'); END;
CREATE TRIGGER device_authorization_commit_no_delete BEFORE DELETE ON device_authorization_commit BEGIN SELECT RAISE(ABORT,'immutable_device_authorization'); END;
CREATE TRIGGER device_authorization_head_no_delete BEFORE DELETE ON device_authorization_head BEGIN SELECT RAISE(ABORT,'device_authorization_head_retained'); END;
CREATE TRIGGER manual_authorization_state_parent BEFORE INSERT ON execution_manual_authority
WHEN NOT EXISTS(SELECT 1 FROM device_authorization_head h JOIN device_authorization_state s USING(state_id)
 WHERE h.device_id=NEW.device_id AND s.control_source_id=NEW.control_source_id
 AND json_extract(NEW.body_jcs,'$.authorization_state_ref.id')=s.state_id
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.authorization_state_ref.revision'),-20)=s.revision
 AND json_extract(NEW.body_jcs,'$.authorization_state_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'manual_authorization_state_parent'); END;

