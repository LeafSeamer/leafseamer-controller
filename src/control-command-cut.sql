DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v58 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '58'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v58 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '58', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v58 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v58 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58')),
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
    OR (from_revision = '39' AND to_revision = '40' AND backup_ref IS NOT NULL)
    OR (from_revision = '40' AND to_revision = '41' AND backup_ref IS NOT NULL)
    OR (from_revision = '41' AND to_revision = '42' AND backup_ref IS NOT NULL)
    OR (from_revision = '42' AND to_revision = '43' AND backup_ref IS NOT NULL)
    OR (from_revision = '43' AND to_revision = '44' AND backup_ref IS NOT NULL)
    OR (from_revision = '44' AND to_revision = '45' AND backup_ref IS NOT NULL)
    OR (from_revision = '45' AND to_revision = '46' AND backup_ref IS NOT NULL)
    OR (from_revision = '46' AND to_revision = '47' AND backup_ref IS NOT NULL)
    OR (from_revision = '47' AND to_revision = '48' AND backup_ref IS NOT NULL)
    OR (from_revision = '48' AND to_revision = '49' AND backup_ref IS NOT NULL)
    OR (from_revision = '49' AND to_revision = '50' AND backup_ref IS NOT NULL)
    OR (from_revision = '50' AND to_revision = '51' AND backup_ref IS NOT NULL)
    OR (from_revision = '51' AND to_revision = '52' AND backup_ref IS NOT NULL)
    OR (from_revision = '52' AND to_revision = '53' AND backup_ref IS NOT NULL)
    OR (from_revision = '53' AND to_revision = '54' AND backup_ref IS NOT NULL)
    OR (from_revision = '54' AND to_revision = '55' AND backup_ref IS NOT NULL)
    OR (from_revision = '55' AND to_revision = '56' AND backup_ref IS NOT NULL)
    OR (from_revision = '56' AND to_revision = '57' AND backup_ref IS NOT NULL)
    OR (from_revision = '57' AND to_revision = '58' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v58 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v58 RENAME TO schema_migration;
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
WHEN NOT EXISTS (SELECT 1 FROM control_state_source s JOIN control_record_head h ON h.device_id=s.device_id AND (h.revision=s.revision OR (
 s.revision=(SELECT max(a.revision) FROM control_state_source a WHERE a.device_id=s.device_id AND a.change_kind NOT IN('ready','gate_protect'))
 AND EXISTS(SELECT 1 FROM control_state_source g WHERE g.device_id=h.device_id AND g.revision=h.revision AND g.change_kind IN('ready','gate_protect'))))
 JOIN service_state v ON v.singleton=1 WHERE s.source_id=NEW.control_source_id AND s.device_id=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.format_version')='device-authorization-state/0.1.0-draft.1'
 AND json_extract(NEW.body_jcs,'$.state_id')=NEW.state_id
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.revision'),-20)=NEW.revision
 AND json_extract(NEW.body_jcs,'$.state_digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.parent_ref.id') IS NEW.parent_id
 AND ((json_extract(NEW.body_jcs,'$.status')='protected' AND json_extract(NEW.body_jcs,'$.recovery_ref') IS NULL) OR
 (json_extract(NEW.body_jcs,'$.status')='policy_selected' AND EXISTS(SELECT 1 FROM device_recovery_consumption r
 JOIN device_recovery_authorization a USING(authorization_id) WHERE r.state_id=NEW.state_id AND r.commit_id=NEW.commit_id
 AND a.authorization_id=json_extract(NEW.body_jcs,'$.recovery_ref.id') AND a.protected_state_id=NEW.parent_id
 AND a.device_id=NEW.device_id)))
 AND json_extract(NEW.body_jcs,'$.context.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.context.scope.authority_service_id')=v.service_id
 AND json_extract(NEW.body_jcs,'$.context.scope.database_instance_id')=v.database_instance_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.id')=s.source_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.revision')=CAST(s.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'device_authorization_state_parent'); END;

CREATE TABLE control_command_cut (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES control_operation_head(operation_id) DEFERRABLE INITIALLY DEFERRED,
 device_id TEXT NOT NULL,
 commit_id TEXT UNIQUE NOT NULL REFERENCES control_change_commit(commit_id) DEFERRABLE INITIALLY DEFERRED,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=4194304),
 body_digest TEXT NOT NULL
) STRICT;
CREATE TRIGGER control_command_cut_no_update BEFORE UPDATE ON control_command_cut BEGIN SELECT RAISE(ABORT,'immutable_control_command_cut'); END;
CREATE TRIGGER control_command_cut_no_delete BEFORE DELETE ON control_command_cut BEGIN SELECT RAISE(ABORT,'immutable_control_command_cut'); END;
CREATE TRIGGER control_command_cut_parent BEFORE INSERT ON control_command_cut WHEN
 EXISTS(SELECT 1 FROM control_change_commit WHERE commit_id=NEW.commit_id) OR NOT EXISTS(
 SELECT 1 FROM control_operation_revision r WHERE r.operation_id=NEW.operation_id AND r.revision=1 AND r.commit_id=NEW.commit_id
 AND r.target_device_id=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.format')='control-command-cut/1'
 AND json_extract(NEW.body_jcs,'$.operation_id')=NEW.operation_id
 AND json_extract(NEW.body_jcs,'$.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.commit_id')=NEW.commit_id
 AND json_extract(NEW.body_jcs,'$.expected_control')=json_extract(r.body_jcs,'$.expected_control')
 AND json_extract(NEW.body_jcs,'$.target')=json_extract(r.body_jcs,'$.target')
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.issued_revision'),-20)=coalesce((SELECT max(issued_revision) FROM command_transmission_issue),'00000000000000000000')
 ) BEGIN SELECT RAISE(ABORT,'control_command_cut_parent'); END;
CREATE TRIGGER control_command_cut_seal BEFORE INSERT ON control_change_commit WHEN EXISTS(
 SELECT 1 FROM control_operation_revision r WHERE r.commit_id=NEW.commit_id AND r.revision=1 AND (
 NOT EXISTS(SELECT 1 FROM control_command_cut c WHERE c.operation_id=r.operation_id AND c.commit_id=NEW.commit_id)
 OR EXISTS(SELECT 1 FROM command_admission_source s WHERE s.device_id=r.target_device_id AND NOT EXISTS(
 SELECT 1 FROM control_command_cut c,json_each(c.body_jcs,'$.commands') m WHERE c.operation_id=r.operation_id AND json_extract(m.value,'$.command_ref.id')=s.command_id))
 OR EXISTS(SELECT 1 FROM control_command_cut c,json_each(c.body_jcs,'$.commands') m WHERE c.operation_id=r.operation_id AND (
 NOT EXISTS(SELECT 1 FROM command_admission_source s WHERE s.device_id=c.device_id AND s.command_id=json_extract(m.value,'$.command_ref.id'))
 OR (json_extract(m.value,'$.queued')=1 AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head h JOIN command_lifecycle_revision l USING(command_id,revision,commit_id)
 JOIN command_lifecycle_commit x USING(command_id,revision,commit_id) WHERE h.command_id=json_extract(m.value,'$.command_ref.id') AND h.revision=2
 AND json_extract(l.state_jcs,'$.outcome')='blocked' AND json_extract(x.body_jcs,'$.proof.control_cut_ref.id')=c.operation_id||'.commands'
 AND json_extract(x.body_jcs,'$.proof.control_cut_ref.digest')=c.body_digest))))
 OR EXISTS(SELECT 1 FROM control_command_cut c,json_each(c.body_jcs,'$.commands') m WHERE c.operation_id=r.operation_id GROUP BY json_extract(m.value,'$.command_ref.id') HAVING count(*)<>1)
 )) BEGIN SELECT RAISE(ABORT,'control_command_cut_incomplete'); END;
CREATE TRIGGER control_command_cut_sources BEFORE INSERT ON control_change_commit WHEN EXISTS(
 SELECT 1 FROM control_command_cut c,json_each(c.body_jcs,'$.commands') m WHERE c.commit_id=NEW.commit_id AND (
 NOT EXISTS(SELECT 1 FROM command_admission_source s WHERE s.command_id=json_extract(m.value,'$.command_ref.id')
 AND s.device_id=c.device_id AND s.binding_id=json_extract(m.value,'$.binding_ref.id')
 AND json_extract(s.body_jcs,'$.binding')=json_extract(m.value,'$.binding'))
 OR NOT EXISTS(SELECT 1 FROM (
 SELECT command_id,revision,record_digest FROM command_revision UNION ALL SELECT command_id,revision,record_digest FROM command_lifecycle_revision
 ) r WHERE r.command_id=json_extract(m.value,'$.command_ref.id') AND CAST(r.revision AS TEXT)=json_extract(m.value,'$.command_ref.revision') AND r.record_digest=json_extract(m.value,'$.command_ref.digest'))
 OR EXISTS(SELECT 1 FROM command_final_admission f WHERE f.command_id=json_extract(m.value,'$.command_ref.id') AND (
 json_extract(m.value,'$.transmission.final_ref.id') IS NOT f.transaction_id OR json_extract(m.value,'$.transmission.final_ref.digest') IS NOT f.body_digest
 OR json_extract(m.value,'$.transmission.permit_id') IS NOT f.permit_id OR json_extract(m.value,'$.transmission.hold_id') IS NOT f.hold_id
 OR json_extract(m.value,'$.transmission.transmission') IS NOT json_extract(f.body_jcs,'$.permit.transmission')))
 OR (json_extract(m.value,'$.transmission') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM command_final_admission f WHERE f.command_id=json_extract(m.value,'$.command_ref.id')))
 )) BEGIN SELECT RAISE(ABORT,'control_command_cut_source'); END;
-- 已冻结控制切点不得被并发新受理或签发越过；旧传输事实允许继续追加。
CREATE TRIGGER control_command_admission_gate BEFORE INSERT ON command_admission_source WHEN EXISTS(
 SELECT 1 FROM control_record_revision r JOIN control_record_head h USING(device_id,revision) WHERE r.device_id=NEW.device_id AND json_extract(r.body_jcs,'$.pending_change') IS NOT NULL
) BEGIN SELECT RAISE(ABORT,'control_command_cut_pending'); END;
CREATE TRIGGER control_command_issue_gate BEFORE INSERT ON command_final_admission WHEN EXISTS(
 SELECT 1 FROM command_admission_source s JOIN control_record_head h USING(device_id) JOIN control_record_revision r USING(device_id,revision)
 WHERE s.command_id=NEW.command_id AND json_extract(r.body_jcs,'$.pending_change') IS NOT NULL
) BEGIN SELECT RAISE(ABORT,'control_command_cut_pending'); END;
