DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v33 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '33'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v33 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '33', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v33 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v33 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33')),
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
    OR (from_revision = '32' AND to_revision = '33' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v33 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v33 RENAME TO schema_migration;
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

-- 人员取证原件；不创建设备授权State、OPEN或Ready资格。
CREATE TABLE execution_manual_authority (
 source_id TEXT PRIMARY KEY NOT NULL,
 device_id TEXT NOT NULL REFERENCES device_record(device_id),
 binding_id TEXT NOT NULL REFERENCES device_execution_binding(binding_id),
 control_source_id TEXT NOT NULL REFERENCES control_state_source(source_id),
 token_id TEXT NOT NULL REFERENCES access_token(token_id),
 policy_id TEXT NOT NULL REFERENCES local_permission_revision(id),
 acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
 selected_tick TEXT NOT NULL CHECK(length(selected_tick)=20 AND selected_tick NOT GLOB '*[^0-9]*'),
 expires_tick TEXT NOT NULL CHECK(length(expires_tick)=20 AND expires_tick NOT GLOB '*[^0-9]*' AND expires_tick>selected_tick),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=65536),
 body_digest TEXT NOT NULL,
 commit_id TEXT NOT NULL UNIQUE CHECK(commit_id=source_id) REFERENCES execution_manual_authority_commit(source_id) DEFERRABLE INITIALLY DEFERRED,
 UNIQUE(source_id,body_digest)
) STRICT;
CREATE TABLE execution_manual_authority_commit (
 source_id TEXT PRIMARY KEY NOT NULL,
 body_digest TEXT NOT NULL,
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 event_id TEXT NOT NULL UNIQUE,
 notification_jcs TEXT NOT NULL CHECK(notification_jcs=audit_jcs),
 FOREIGN KEY(source_id,body_digest) REFERENCES execution_manual_authority(source_id,body_digest) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER manual_authority_parent BEFORE INSERT ON execution_manual_authority
WHEN NOT EXISTS(SELECT 1 FROM device_execution_binding b JOIN control_state_source c ON c.device_id=b.device_id
 JOIN control_record_head h ON h.device_id=c.device_id AND h.revision=c.revision
 JOIN access_token t ON t.token_id=NEW.token_id JOIN auth_session s ON s.session_id=t.session_id
 JOIN session_refresh_credential cr ON cr.credential_id=t.credential_id AND cr.session_id=s.session_id
 JOIN local_permission_revision p ON p.id=NEW.policy_id JOIN local_permission_head ph ON ph.id=p.id AND ph.principal_id=p.principal_id
 JOIN authentication_clock_acquisition a ON a.id=NEW.acquisition_id
 WHERE b.binding_id=NEW.binding_id AND b.device_id=NEW.device_id AND c.source_id=NEW.control_source_id
 AND t.state='active' AND s.state='active' AND cr.state!='revoked' AND p.state='active' AND p.principal_id=s.principal_id
 AND json_extract(c.body_jcs,'$.mode')='manual' AND json_extract(c.body_jcs,'$.pending_operation_id') IS NULL
 AND json_extract(c.body_jcs,'$.holder.principal_id')=s.principal_id AND json_extract(c.body_jcs,'$.holder.issuer_id')=s.issuer_id
 AND json_extract(c.body_jcs,'$.holder.issuer_epoch')=s.issuer_epoch
 AND json_extract(NEW.body_jcs,'$.format')='manual-execution-authority-source/1' AND json_extract(NEW.body_jcs,'$.id')=NEW.source_id
 AND json_extract(NEW.body_jcs,'$.revision')='1' AND json_extract(NEW.body_jcs,'$.digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.binding_ref.id')=b.binding_id AND json_extract(NEW.body_jcs,'$.binding_ref.digest')=b.body_digest
 AND json_extract(NEW.body_jcs,'$.control_state_ref.id')=c.source_id AND json_extract(NEW.body_jcs,'$.control_state_ref.digest')=c.body_digest
 AND json_extract(NEW.body_jcs,'$.policy_ref.id')=p.id AND json_extract(NEW.body_jcs,'$.policy_ref.digest')=p.digest
 AND json_extract(NEW.body_jcs,'$.token_id')=t.token_id AND json_extract(NEW.body_jcs,'$.session_id')=s.session_id
 AND json_extract(NEW.body_jcs,'$.credential_id')=cr.credential_id AND json_extract(NEW.body_jcs,'$.authorization.digest')=t.authorization_digest
 AND json_extract(NEW.body_jcs,'$.authentication_acquisition_ref.id')=a.id AND json_extract(NEW.body_jcs,'$.authentication_acquisition_ref.digest')=a.digest
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.selected_tick_ns'),-20)=NEW.selected_tick
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.expires_tick_ns'),-20)=NEW.expires_tick)
BEGIN SELECT RAISE(ABORT,'manual_authority_parent'); END;
CREATE TRIGGER manual_authority_source_no_update BEFORE UPDATE ON execution_manual_authority BEGIN SELECT RAISE(ABORT,'immutable_manual_authority'); END;
CREATE TRIGGER manual_authority_source_no_delete BEFORE DELETE ON execution_manual_authority BEGIN SELECT RAISE(ABORT,'immutable_manual_authority'); END;
CREATE TRIGGER manual_authority_commit_no_update BEFORE UPDATE ON execution_manual_authority_commit BEGIN SELECT RAISE(ABORT,'immutable_manual_authority'); END;
CREATE TRIGGER manual_authority_commit_no_delete BEFORE DELETE ON execution_manual_authority_commit BEGIN SELECT RAISE(ABORT,'immutable_manual_authority'); END;

