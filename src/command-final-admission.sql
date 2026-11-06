DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v52 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '52'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v52 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '52', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v52 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v52 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52')),
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
    OR (from_revision = '51' AND to_revision = '52' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v52 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v52 RENAME TO schema_migration;
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

-- 首次固定内存传输的完整T2。后继发送/释放必须另有领域写集，不能删除这些原件退款。
CREATE TABLE command_final_admission (
 transaction_id TEXT PRIMARY KEY NOT NULL,command_id TEXT NOT NULL UNIQUE REFERENCES command_admission_source(command_id),
 prepare_id TEXT NOT NULL UNIQUE REFERENCES command_encoding_response(prepare_id),binding_id TEXT NOT NULL REFERENCES device_execution_binding(binding_id),
 permit_id TEXT NOT NULL UNIQUE,hold_id TEXT NOT NULL UNIQUE,attempt_id TEXT NOT NULL UNIQUE,seal_id TEXT NOT NULL UNIQUE,dispatch_intent_id TEXT NOT NULL UNIQUE,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=262144),body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 commit_id TEXT NOT NULL UNIQUE REFERENCES command_lifecycle_commit(commit_id) DEFERRABLE INITIALLY DEFERRED,
 UNIQUE(transaction_id,command_id),UNIQUE(transaction_id,permit_id),UNIQUE(transaction_id,hold_id),UNIQUE(transaction_id,attempt_id),
 FOREIGN KEY(transaction_id,permit_id) REFERENCES command_transmission_issue(transaction_id,permit_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(transaction_id,hold_id) REFERENCES command_device_hold(transaction_id,hold_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(transaction_id,attempt_id) REFERENCES command_attempt_inventory(transaction_id,attempt_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE command_device_hold (
 hold_id TEXT PRIMARY KEY NOT NULL,transaction_id TEXT NOT NULL UNIQUE,command_id TEXT NOT NULL UNIQUE,
 device_id TEXT NOT NULL UNIQUE,ownership_id TEXT NOT NULL UNIQUE,
 receipt_id TEXT NOT NULL UNIQUE,receipt_jcs TEXT NOT NULL CHECK(json_valid(receipt_jcs)),receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=71),
 hold_jcs TEXT NOT NULL CHECK(json_valid(hold_jcs)),hold_digest TEXT NOT NULL CHECK(length(hold_digest)=71),
 ownership_jcs TEXT NOT NULL CHECK(json_valid(ownership_jcs)),ownership_digest TEXT NOT NULL CHECK(length(ownership_digest)=71),
 UNIQUE(transaction_id,hold_id),
 FOREIGN KEY(transaction_id,hold_id) REFERENCES command_final_admission(transaction_id,hold_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(transaction_id,command_id) REFERENCES command_final_admission(transaction_id,command_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE command_transmission_issue (
 permit_id TEXT PRIMARY KEY NOT NULL,transaction_id TEXT NOT NULL UNIQUE,
 issued_revision TEXT NOT NULL UNIQUE CHECK(length(issued_revision)=20 AND issued_revision NOT GLOB '*[^0-9]*' AND issued_revision>'00000000000000000000'),
 previous_revision TEXT NOT NULL UNIQUE CHECK(length(previous_revision)=20 AND previous_revision NOT GLOB '*[^0-9]*'),
 charged_bytes INTEGER NOT NULL CHECK(charged_bytes=8),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 UNIQUE(transaction_id,permit_id),
 FOREIGN KEY(transaction_id,permit_id) REFERENCES command_final_admission(transaction_id,permit_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE command_attempt_inventory (
 command_id TEXT PRIMARY KEY NOT NULL,revision INTEGER NOT NULL CHECK(revision=2),transaction_id TEXT NOT NULL UNIQUE,attempt_id TEXT NOT NULL UNIQUE,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 UNIQUE(transaction_id,attempt_id),
 FOREIGN KEY(transaction_id,attempt_id) REFERENCES command_final_admission(transaction_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(transaction_id,command_id) REFERENCES command_final_admission(transaction_id,command_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(command_id,revision) REFERENCES command_lifecycle_revision(command_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER command_final_admission_parent BEFORE INSERT ON command_final_admission
WHEN NOT EXISTS(SELECT 1 FROM command_encoding_request q JOIN command_encoding_response r USING(prepare_id)
 JOIN command_admission_source s ON s.command_id=q.command_id JOIN command_revision c ON c.command_id=s.command_id AND c.revision=1
 JOIN execution_write_result w ON w.attempt_id=r.write_attempt_id
 WHERE q.prepare_id=NEW.prepare_id AND q.command_id=NEW.command_id AND q.binding_id=NEW.binding_id AND r.disposition='prepared' AND w.result='complete'
 AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head h WHERE h.command_id=NEW.command_id)
 AND NOT EXISTS(SELECT 1 FROM execution_session_end e WHERE e.ipc_session_id=json_extract(s.body_jcs,'$.binding.ipc_session_id'))
 AND json_extract(NEW.body_jcs,'$.transaction_id')=NEW.transaction_id AND json_extract(NEW.body_jcs,'$.command_id')=NEW.command_id
 AND json_extract(NEW.body_jcs,'$.prepare_id')=NEW.prepare_id AND json_extract(NEW.body_jcs,'$.permit.permit_id')=NEW.permit_id
 AND json_extract(NEW.body_jcs,'$.permit.dispatch_intent_id')=NEW.dispatch_intent_id
 AND json_extract(NEW.body_jcs,'$.hold.hold_id')=NEW.hold_id AND json_extract(NEW.body_jcs,'$.attempt.attempt_id')=NEW.attempt_id
 AND json_extract(NEW.body_jcs,'$.seal.seal_id')=NEW.seal_id AND json_extract(NEW.body_jcs,'$.commit_id')=NEW.commit_id
 AND json_extract(NEW.body_jcs,'$.seal.command_state_ref.digest')=c.state_digest
 AND json_extract(NEW.body_jcs,'$.encoding_ref.digest')=q.body_digest
 AND json_extract(NEW.body_jcs,'$.encoding_response_ref.digest')=r.body_digest
) BEGIN SELECT RAISE(ABORT,'command_final_admission_parent'); END;
CREATE TRIGGER command_transmission_issue_parent BEFORE INSERT ON command_transmission_issue
WHEN (SELECT count(*) FROM command_transmission_issue)>=4096
 OR NEW.previous_revision!=coalesce((SELECT max(issued_revision) FROM command_transmission_issue),'00000000000000000000')
 OR NOT EXISTS(SELECT 1 FROM command_final_admission f WHERE f.transaction_id=NEW.transaction_id AND f.permit_id=NEW.permit_id
 AND json_extract(f.body_jcs,'$.transmission_charge')=json(NEW.body_jcs)
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.issued_revision'),-20)=NEW.issued_revision
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.previous_revision'),-20)=NEW.previous_revision)
BEGIN SELECT RAISE(ABORT,'command_transmission_issue_parent'); END;
CREATE TRIGGER command_device_hold_parent BEFORE INSERT ON command_device_hold
WHEN NOT EXISTS(SELECT 1 FROM command_final_admission f JOIN command_admission_source s USING(command_id)
 WHERE f.transaction_id=NEW.transaction_id AND f.hold_id=NEW.hold_id AND f.command_id=NEW.command_id AND s.device_id=NEW.device_id
 AND json_extract(f.body_jcs,'$.hold')=json(NEW.hold_jcs) AND json_extract(f.body_jcs,'$.ownership')=json(NEW.ownership_jcs)
 AND json_extract(f.body_jcs,'$.ownership_receipt')=json(NEW.receipt_jcs) AND json_extract(NEW.receipt_jcs,'$.receipt_id')=NEW.receipt_id
 AND json_extract(NEW.ownership_jcs,'$.source_receipt_ref.id')=NEW.receipt_id AND json_extract(NEW.ownership_jcs,'$.source_receipt_ref.digest')=NEW.receipt_digest
 AND json_extract(NEW.ownership_jcs,'$.ownership_id')=NEW.ownership_id AND json_extract(NEW.ownership_jcs,'$.ownership_digest')=NEW.ownership_digest)
BEGIN SELECT RAISE(ABORT,'command_device_hold_parent'); END;
CREATE TRIGGER command_attempt_inventory_parent BEFORE INSERT ON command_attempt_inventory
WHEN NOT EXISTS(SELECT 1 FROM command_final_admission f WHERE f.transaction_id=NEW.transaction_id AND f.command_id=NEW.command_id
 AND f.attempt_id=NEW.attempt_id AND json_extract(f.body_jcs,'$.inventory')=json(NEW.body_jcs))
BEGIN SELECT RAISE(ABORT,'command_attempt_inventory_parent'); END;
-- 可靠COMMIT返回后另一个短事务记录观察；观察失败不能撤销已存在的hold或重新签发。
CREATE TABLE command_final_observation (
 transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES command_final_admission(transaction_id),
 observation_id TEXT NOT NULL UNIQUE,service_boot_id TEXT NOT NULL REFERENCES core_runtime_binding(service_boot_id),
 observer_jcs TEXT NOT NULL CHECK(json_valid(observer_jcs)),observer_digest TEXT NOT NULL CHECK(length(observer_digest)=71),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71)
) STRICT;
CREATE TRIGGER command_final_observation_parent BEFORE INSERT ON command_final_observation
WHEN NOT EXISTS(SELECT 1 FROM command_final_admission f JOIN command_lifecycle_commit c ON c.commit_id=f.commit_id
 JOIN command_lifecycle_head h ON h.commit_id=c.commit_id JOIN core_runtime_binding r ON r.service_boot_id=NEW.service_boot_id
 WHERE f.transaction_id=NEW.transaction_id AND json_extract(NEW.body_jcs,'$.transaction_id')=f.transaction_id
 AND json_extract(NEW.body_jcs,'$.observation_id')=NEW.observation_id AND json_extract(NEW.body_jcs,'$.permit_id')=f.permit_id
 AND json_extract(NEW.body_jcs,'$.outcome')='committed' AND json_extract(NEW.body_jcs,'$.seal_ref.digest')=json_extract(f.body_jcs,'$.seal.seal_digest')
 AND json_extract(NEW.observer_jcs,'$.core_receipt')=json(r.receipt_jcs)
 AND json_extract(NEW.body_jcs,'$.observer_ref.digest')=NEW.observer_digest)
BEGIN SELECT RAISE(ABORT,'command_final_observation_parent'); END;
CREATE TRIGGER command_final_observation_no_update BEFORE UPDATE ON command_final_observation BEGIN SELECT RAISE(ABORT,'immutable_command_final_observation'); END;
CREATE TRIGGER command_final_observation_no_delete BEFORE DELETE ON command_final_observation BEGIN SELECT RAISE(ABORT,'immutable_command_final_observation'); END;

CREATE TRIGGER command_final_admission_no_update BEFORE UPDATE ON command_final_admission BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

CREATE TRIGGER command_final_admission_no_delete BEFORE DELETE ON command_final_admission BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

CREATE TRIGGER command_device_hold_no_update BEFORE UPDATE ON command_device_hold BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

CREATE TRIGGER command_device_hold_no_delete BEFORE DELETE ON command_device_hold BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

CREATE TRIGGER command_transmission_issue_no_update BEFORE UPDATE ON command_transmission_issue BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

CREATE TRIGGER command_transmission_issue_no_delete BEFORE DELETE ON command_transmission_issue BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

CREATE TRIGGER command_attempt_inventory_no_update BEFORE UPDATE ON command_attempt_inventory BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

CREATE TRIGGER command_attempt_inventory_no_delete BEFORE DELETE ON command_attempt_inventory BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

DROP TRIGGER command_lifecycle_parent;
CREATE TRIGGER command_lifecycle_parent BEFORE INSERT ON command_lifecycle_commit WHEN NOT (EXISTS(
 SELECT 1 FROM command_revision i JOIN command_lifecycle_revision r USING(command_id)
 JOIN command_admission_source s USING(command_id)
 WHERE r.commit_id=NEW.commit_id AND r.command_id=NEW.command_id AND r.revision=NEW.revision AND NEW.revision=2
 AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head h WHERE h.command_id=NEW.command_id)
 AND json_extract(i.state_jcs,'$.phase')='queued' AND json_array_length(i.state_jcs,'$.attempt_ids')=0
 AND json_extract(NEW.body_jcs,'$.format')='command-queued-closure/1'
 AND json_extract(NEW.body_jcs,'$.command_id')=NEW.command_id
 AND json_extract(NEW.body_jcs,'$.previous_state_ref.digest')=i.state_digest
 AND json_extract(NEW.body_jcs,'$.record_digest')=r.record_digest
 AND json_extract(NEW.body_jcs,'$.state_digest')=r.state_digest
 AND json_extract(r.record_jcs,'$.state')=json(r.state_jcs)
 AND json_extract(r.state_jcs,'$.revision')='2' AND json_extract(r.state_jcs,'$.terminal_revision')='2'
 AND json_extract(r.state_jcs,'$.phase')='finished' AND json_extract(r.state_jcs,'$.outcome') IN ('blocked','expired')
 AND json_extract(r.state_jcs,'$.effect_status')='not_sent' AND json_extract(r.state_jcs,'$.resource_status')='clear'
 AND json_extract(r.state_jcs,'$.automation_continuation')='paused_latched'
 AND json_array_length(r.state_jcs,'$.attempt_ids')=0 AND json_array_length(r.manifest_jcs,'$.members')=0
 AND NOT EXISTS(SELECT 1 FROM command_final_admission f WHERE f.command_id=NEW.command_id)
) OR EXISTS(SELECT 1 FROM command_final_admission f JOIN command_lifecycle_revision r ON r.command_id=f.command_id AND r.commit_id=f.commit_id
 JOIN command_attempt_inventory a ON a.transaction_id=f.transaction_id AND a.command_id=f.command_id
 JOIN command_device_hold h ON h.transaction_id=f.transaction_id AND h.hold_id=f.hold_id
 JOIN command_transmission_issue i ON i.transaction_id=f.transaction_id AND i.permit_id=f.permit_id
 WHERE f.commit_id=NEW.commit_id AND f.command_id=NEW.command_id AND r.revision=2 AND NEW.revision=2
 AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head x WHERE x.command_id=NEW.command_id)
 AND json_extract(NEW.body_jcs,'$.format')='command-final-admission-commit/1'
 AND json_extract(NEW.body_jcs,'$.transaction_ref.digest')=f.body_digest
 AND json_extract(NEW.body_jcs,'$.transaction_ref.id')=f.transaction_id
 AND json_extract(NEW.body_jcs,'$.record_digest')=r.record_digest AND json_extract(NEW.body_jcs,'$.state_digest')=r.state_digest
 AND json_extract(r.record_jcs,'$.state')=json(r.state_jcs)
 AND json_extract(r.state_jcs,'$.revision')='2' AND json_extract(r.state_jcs,'$.terminal_revision') IS NULL
 AND json_extract(r.state_jcs,'$.phase')='queued' AND json_extract(r.state_jcs,'$.outcome')='pending'
 AND json_extract(r.state_jcs,'$.resource_status')='held' AND json_extract(r.state_jcs,'$.effect_status')='not_sent'
 AND json_array_length(r.state_jcs,'$.attempt_ids')=1 AND json_extract(r.state_jcs,'$.attempt_ids[0]')=f.attempt_id
 AND json_array_length(r.record_jcs,'$.attempts')=1 AND json_extract(r.record_jcs,'$.attempts[0].attempt_id')=f.attempt_id
 AND json_array_length(r.manifest_jcs,'$.members')=0 AND (SELECT count(*) FROM json_each(f.body_jcs,'$.projections'))=18
)) BEGIN SELECT RAISE(ABORT,'command_lifecycle_parent'); END;
