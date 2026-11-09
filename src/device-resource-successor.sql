DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v57 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '57'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v57 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '57', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v57 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v57 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57')),
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
    OR (from_revision = '56' AND to_revision = '57' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v57 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v57 RENAME TO schema_migration;
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



-- 已释放占用保留在永久账本；后继开放绑定实际非空关闭屏障。
DROP TRIGGER device_initial_resource_parent;
DROP TRIGGER device_initial_resource_no_update;
DROP TRIGGER device_initial_resource_no_delete;
DROP TRIGGER device_initial_open_parent;
DROP TRIGGER device_initial_open_no_update;
DROP TRIGGER device_initial_open_no_delete;
DROP TRIGGER initial_ready_parent;
DROP TRIGGER command_device_hold_parent;
DROP TRIGGER command_device_hold_no_update;
DROP TRIGGER command_device_hold_no_delete;
DROP TRIGGER execution_initial_open_parent;
DROP TRIGGER command_hold_release_parent;
DROP TRIGGER command_lifecycle_parent;
CREATE TABLE device_initial_open_v57 (
 opening_id TEXT PRIMARY KEY NOT NULL,request_id TEXT NOT NULL UNIQUE,request_digest TEXT NOT NULL,request_jcs TEXT NOT NULL CHECK(json_valid(request_jcs)),
 binding_id TEXT NOT NULL REFERENCES device_execution_binding(binding_id),resource_source_id TEXT NOT NULL REFERENCES device_initial_resource(source_id),
 evidence_id TEXT NOT NULL REFERENCES device_authorization_evidence(evidence_id),fence_id TEXT NOT NULL REFERENCES execution_initial_fence(fence_id),
 gate_token TEXT NOT NULL UNIQUE,body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL,commit_id TEXT NOT NULL UNIQUE,
 UNIQUE(opening_id,commit_id),FOREIGN KEY(commit_id,opening_id) REFERENCES device_initial_open_commit(commit_id,opening_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO device_initial_open_v57 SELECT * FROM device_initial_open;
DROP TABLE device_initial_open;
ALTER TABLE device_initial_open_v57 RENAME TO device_initial_open;
CREATE TABLE command_device_hold_v57 (
 hold_id TEXT PRIMARY KEY NOT NULL,transaction_id TEXT NOT NULL UNIQUE,command_id TEXT NOT NULL UNIQUE,
 device_id TEXT NOT NULL,ownership_id TEXT NOT NULL UNIQUE,
 receipt_id TEXT NOT NULL UNIQUE,receipt_jcs TEXT NOT NULL CHECK(json_valid(receipt_jcs)),receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=71),
 hold_jcs TEXT NOT NULL CHECK(json_valid(hold_jcs)),hold_digest TEXT NOT NULL CHECK(length(hold_digest)=71),
 ownership_jcs TEXT NOT NULL CHECK(json_valid(ownership_jcs)),ownership_digest TEXT NOT NULL CHECK(length(ownership_digest)=71),
 UNIQUE(transaction_id,hold_id),
 FOREIGN KEY(transaction_id,hold_id) REFERENCES command_final_admission(transaction_id,hold_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(transaction_id,command_id) REFERENCES command_final_admission(transaction_id,command_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO command_device_hold_v57 SELECT * FROM command_device_hold;
DROP TABLE command_device_hold;
ALTER TABLE command_device_hold_v57 RENAME TO command_device_hold;
CREATE TRIGGER device_initial_resource_parent BEFORE INSERT ON device_initial_resource
WHEN NOT EXISTS (SELECT 1 FROM device_execution_binding b JOIN execution_initial_fence f ON f.binding_id=b.binding_id
 JOIN execution_initial_fence_ack a USING(fence_id) JOIN device_baseline_sample s ON s.sample_id=NEW.sample_id
 JOIN device_authorization_evidence e ON e.evidence_id=NEW.evidence_id
 JOIN device_authorization_evidence_head h ON h.evidence_id=e.evidence_id
 JOIN device_authorization_head d ON d.state_id=h.state_id AND d.device_id=NEW.device_id
 WHERE b.binding_id=NEW.binding_id AND b.device_id=NEW.device_id AND f.fence_id=NEW.fence_id
 AND s.approval_id=b.catalog_approval_id AND (
 (json_extract(s.body_jcs,'$.value.write_sequence')='0' AND NOT EXISTS(SELECT 1 FROM ca_command_initial c JOIN ca_request_key k USING(key_id) WHERE k.device_id=NEW.device_id)) OR
 (json_extract(NEW.body_jcs,'$.format')='leafseamer-device-resource-successor/1'
 AND EXISTS(SELECT 1 FROM command_closure_request c JOIN command_closure_ack k USING(permit_id)
  JOIN command_final_admission t USING(permit_id) JOIN command_hold_release r ON r.hold_id=t.hold_id
  JOIN command_preparation_cleanup p ON p.permit_id=t.permit_id AND p.phase='release_ack'
  WHERE t.binding_id=b.binding_id AND json_extract(NEW.body_jcs,'$.inventory.closing_ref.id')=t.permit_id||'.fence_request'
  AND json_extract(NEW.body_jcs,'$.inventory.closing_ref.digest')=c.body_digest
  AND json_extract(NEW.body_jcs,'$.inventory.closing_ack_ref.digest')=k.body_digest)
 AND NOT EXISTS(SELECT 1 FROM command_device_hold x WHERE x.device_id=NEW.device_id AND NOT EXISTS(
  SELECT 1 FROM command_hold_release r JOIN command_final_admission t ON t.hold_id=r.hold_id
  JOIN command_preparation_cleanup p ON p.permit_id=t.permit_id AND p.phase='release_ack' WHERE r.hold_id=x.hold_id))
 AND NOT EXISTS(SELECT 1 FROM ca_command_initial c JOIN ca_request_key k USING(key_id) WHERE k.device_id=NEW.device_id AND NOT EXISTS(
  SELECT 1 FROM command_settlement t JOIN command_hold_release r USING(command_id) WHERE t.command_id=c.command_id)))))
BEGIN SELECT RAISE(ABORT,'initial_resource_parent'); END;
CREATE TRIGGER device_initial_resource_no_update BEFORE UPDATE ON device_initial_resource
BEGIN SELECT RAISE(ABORT,'immutable_initial_resource'); END;
CREATE TRIGGER device_initial_resource_no_delete BEFORE DELETE ON device_initial_resource
BEGIN SELECT RAISE(ABORT,'immutable_initial_resource'); END;
CREATE TRIGGER device_initial_open_parent BEFORE INSERT ON device_initial_open
WHEN NOT EXISTS(SELECT 1 FROM device_initial_resource r JOIN device_initial_resource_commit c USING(source_id,commit_id)
 JOIN device_authorization_evidence_head h ON h.evidence_id=r.evidence_id
 JOIN device_authorization_head a ON a.device_id=r.device_id AND a.state_id=h.state_id
 JOIN execution_initial_fence_ack f ON f.fence_id=r.fence_id
 WHERE r.source_id=NEW.resource_source_id AND r.binding_id=NEW.binding_id AND r.evidence_id=NEW.evidence_id AND r.fence_id=NEW.fence_id)
BEGIN SELECT RAISE(ABORT,'initial_open_parent'); END;
CREATE TRIGGER device_initial_open_no_update BEFORE UPDATE ON device_initial_open BEGIN SELECT RAISE(ABORT,'immutable_initial_open'); END;
CREATE TRIGGER device_initial_open_no_delete BEFORE DELETE ON device_initial_open BEGIN SELECT RAISE(ABORT,'immutable_initial_open'); END;
CREATE TRIGGER initial_ready_parent BEFORE INSERT ON device_initial_ready WHEN NOT EXISTS (
 SELECT 1 FROM execution_initial_open_ack a JOIN execution_initial_open_dispatch d USING(opening_id)
 JOIN device_initial_open o USING(opening_id) JOIN execution_write_result w ON w.attempt_id=a.write_attempt_id
 JOIN control_state_source b ON b.source_id=json_extract(NEW.body_jcs,'$.control_before_ref.id')
 JOIN control_record_revision r ON r.commit_id=NEW.control_source_id
 JOIN control_record_head h ON h.device_id=r.device_id AND h.revision=r.revision
 WHERE a.opening_id=NEW.opening_id AND w.result='complete' AND r.revision=NEW.control_revision AND b.device_id=r.device_id AND b.revision+1=r.revision
 AND b.body_digest=json_extract(NEW.body_jcs,'$.control_before_ref.digest')
 AND json_extract(o.body_jcs,'$.plan.state_refs.control')=json_extract(NEW.body_jcs,'$.control_before_ref')
 AND json_extract(o.body_jcs,'$.plan.binding')=json_extract(NEW.body_jcs,'$.binding')
 AND json_extract(NEW.body_jcs,'$.format')='initial-device-ready/1'
 AND json_extract(NEW.body_jcs,'$.id')=NEW.ready_id AND json_extract(NEW.body_jcs,'$.revision')='1'
 AND json_extract(NEW.body_jcs,'$.digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.control_after_ref.id')=NEW.control_source_id
 AND json_extract(NEW.body_jcs,'$.control_after_ref.revision')=CAST(r.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.dispatch_ref.digest')=d.body_digest
 AND json_extract(NEW.body_jcs,'$.confirmation_ref.digest')=a.body_digest
 AND json_extract(b.body_jcs,'$.gate_state')='protected' AND json_extract(r.body_jcs,'$.gate_state')='ready'
 AND json_extract(r.body_jcs,'$.pending_change') IS NULL AND json_extract(NEW.body_jcs,'$.gate_after.phase')='ready'
 AND json_extract(NEW.body_jcs,'$.expires_tick_ns')=json_extract(o.body_jcs,'$.plan.expires_tick_ns')
) BEGIN SELECT RAISE(ABORT,'initial_ready_parent'); END;
CREATE TRIGGER command_device_hold_parent BEFORE INSERT ON command_device_hold
WHEN NOT EXISTS(SELECT 1 FROM command_final_admission f JOIN command_admission_source s USING(command_id)
 WHERE f.transaction_id=NEW.transaction_id AND f.hold_id=NEW.hold_id AND f.command_id=NEW.command_id AND s.device_id=NEW.device_id
 AND json_extract(f.body_jcs,'$.hold')=json(NEW.hold_jcs) AND json_extract(f.body_jcs,'$.ownership')=json(NEW.ownership_jcs)
 AND json_extract(f.body_jcs,'$.ownership_receipt')=json(NEW.receipt_jcs) AND json_extract(NEW.receipt_jcs,'$.receipt_id')=NEW.receipt_id
 AND json_extract(NEW.ownership_jcs,'$.source_receipt_ref.id')=NEW.receipt_id AND json_extract(NEW.ownership_jcs,'$.source_receipt_ref.digest')=NEW.receipt_digest
 AND json_extract(NEW.ownership_jcs,'$.ownership_id')=NEW.ownership_id AND json_extract(NEW.ownership_jcs,'$.ownership_digest')=NEW.ownership_digest)
BEGIN SELECT RAISE(ABORT,'command_device_hold_parent'); END;
CREATE TRIGGER command_device_hold_no_update BEFORE UPDATE ON command_device_hold BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;
CREATE TRIGGER command_device_hold_no_delete BEFORE DELETE ON command_device_hold BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;
CREATE TRIGGER execution_initial_open_parent BEFORE INSERT ON execution_initial_open_dispatch WHEN NOT EXISTS (
 SELECT 1 FROM device_initial_open o JOIN device_initial_resource r ON r.source_id=o.resource_source_id
 JOIN device_execution_binding b ON b.binding_id=o.binding_id JOIN device_authorization_evidence_head h ON h.evidence_id=o.evidence_id
 JOIN device_module_frame a ON a.message_id=NEW.configuration_message_id JOIN device_module_frame q ON q.message_id=a.reply_to
 JOIN execution_frame_record f ON f.record_id=NEW.request_record_id AND f.transaction_id=NEW.request_transaction_id
 WHERE o.opening_id=NEW.opening_id AND f.ipc_session_id=b.ipc_session_id AND f.device_id=b.device_id AND f.direction='c2w' AND f.message_type='OPEN_GATE' AND f.domain_kind='initial_open'
 AND a.message_type='EXECUTION_BOUND' AND a.direction='w2c' AND q.message_type='BIND_EXECUTION' AND q.direction='c2w' AND a.channel_id=q.channel_id
 AND json_extract(q.frame_jcs,'$.body.execution.value')=b.body_jcs AND json_extract(q.frame_jcs,'$.body.execution.ref.digest')=b.body_digest
 AND json_extract(a.frame_jcs,'$.body.execution_ref.id')=b.binding_id AND json_extract(a.frame_jcs,'$.body.execution_ref.digest')=b.body_digest
 AND json_extract(f.frame_jcs,'$.body')=json_extract(o.body_jcs,'$.plan.body')
 AND json_extract(NEW.body_jcs,'$.opening_ref.id')=o.opening_id AND json_extract(NEW.body_jcs,'$.opening_ref.digest')=o.body_digest
 AND json_extract(NEW.body_jcs,'$.worker_configuration_ref.id')=a.message_id AND json_extract(NEW.body_jcs,'$.worker_configuration_ref.digest')=a.frame_digest
 AND json_extract(NEW.body_jcs,'$.request_record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.request_record_ref.digest')=f.record_digest
) BEGIN SELECT RAISE(ABORT,'execution_initial_open_binding'); END;
CREATE TRIGGER command_hold_release_parent BEFORE INSERT ON command_hold_release WHEN NOT EXISTS(
 SELECT 1 FROM command_settlement s JOIN command_device_hold h ON h.command_id=s.command_id
 JOIN command_evidence_record e ON e.command_id=s.command_id AND e.commit_id=s.commit_id
 WHERE s.command_id=NEW.command_id AND s.commit_id=NEW.commit_id AND h.hold_id=NEW.hold_id
 AND e.evidence_id=NEW.evidence_id AND e.kind='release' AND json_extract(e.body_jcs,'$.body.hold_id')=h.hold_id
 AND json_extract(s.body_jcs,'$.module_settlement.module_settled')=1
) BEGIN SELECT RAISE(ABORT,'command_hold_release_parent'); END;
CREATE TRIGGER command_lifecycle_parent BEFORE INSERT ON command_lifecycle_commit WHEN NEW.revision<>5 AND NOT (EXISTS(
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
) OR EXISTS(SELECT 1 FROM command_final_admission f JOIN command_dispatch_request d ON d.final_transaction_id=f.transaction_id
 JOIN command_dispatch_write w ON w.permit_id=d.permit_id LEFT JOIN command_dispatch_report t ON t.permit_id=d.permit_id
 JOIN command_lifecycle_head h ON h.command_id=f.command_id AND h.revision=NEW.revision AND h.commit_id=NEW.commit_id
 JOIN command_lifecycle_revision r ON r.command_id=h.command_id AND r.revision=h.revision AND r.commit_id=h.commit_id
 JOIN command_lifecycle_revision p ON p.command_id=h.command_id AND p.revision=h.revision-1
 WHERE f.command_id=NEW.command_id AND ((NEW.revision=3 AND w.commit_id=NEW.commit_id) OR (NEW.revision=4 AND t.commit_id=NEW.commit_id))
 AND json_extract(NEW.body_jcs,'$.format')='command-dispatch-state/1'
 AND json_extract(NEW.body_jcs,'$.dispatch_ref.id')=d.permit_id AND json_extract(NEW.body_jcs,'$.dispatch_ref.digest')=d.body_digest
 AND json_extract(NEW.body_jcs,'$.previous_state_ref.digest')=p.state_digest
 AND json_extract(NEW.body_jcs,'$.record_digest')=r.record_digest AND json_extract(NEW.body_jcs,'$.state_digest')=r.state_digest
 AND json_extract(r.record_jcs,'$.state')=json(r.state_jcs) AND json_extract(r.state_jcs,'$.revision')=CAST(NEW.revision AS TEXT)
 AND json_extract(r.state_jcs,'$.phase')=CASE NEW.revision WHEN 3 THEN 'dispatching' ELSE 'awaiting_evidence' END
 AND json_extract(r.state_jcs,'$.outcome')='pending' AND json_extract(r.state_jcs,'$.effect_status')='possible'
 AND json_extract(r.state_jcs,'$.resource_status')='held' AND json_extract(r.state_jcs,'$.terminal_revision') IS NULL
 AND json_array_length(r.state_jcs,'$.attempt_ids')=1 AND json_extract(r.state_jcs,'$.attempt_ids[0]')=f.attempt_id
 AND json_array_length(r.record_jcs,'$.attempts')=1 AND json_extract(r.record_jcs,'$.attempts[0].attempt_id')=f.attempt_id
 AND json_array_length(r.manifest_jcs,'$.members')=0)
) BEGIN SELECT RAISE(ABORT,'command_lifecycle_parent'); END;
CREATE UNIQUE INDEX device_open_barrier ON device_initial_open(binding_id,json_extract(body_jcs,'$.gate.barrier_id'));
CREATE TRIGGER command_device_hold_exclusive BEFORE INSERT ON command_device_hold WHEN EXISTS(SELECT 1 FROM command_device_hold h WHERE h.device_id=NEW.device_id AND NOT EXISTS(SELECT 1 FROM command_hold_release r WHERE r.hold_id=h.hold_id)) BEGIN SELECT RAISE(ABORT,'command_resource_busy'); END;
