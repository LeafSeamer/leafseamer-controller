DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
DROP TRIGGER device_recovery_consumption_parent;
DROP TRIGGER control_gate_successor;
CREATE TABLE service_state_v96 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '96'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v96 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '96', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v96 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v96 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '90', '91', '92', '93', '94', '95')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '90', '91', '92', '93', '94', '95', '96')),
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
    OR (from_revision = '57' AND to_revision = '58' AND backup_ref IS NOT NULL)
    OR (from_revision = '58' AND to_revision = '59' AND backup_ref IS NOT NULL)
    OR (from_revision = '59' AND to_revision = '60' AND backup_ref IS NOT NULL)
    OR (from_revision = '60' AND to_revision = '61' AND backup_ref IS NOT NULL)
    OR (from_revision = '61' AND to_revision = '62' AND backup_ref IS NOT NULL)
    OR (from_revision = '62' AND to_revision = '63' AND backup_ref IS NOT NULL)
    OR (from_revision = '63' AND to_revision = '64' AND backup_ref IS NOT NULL)
    OR (from_revision = '64' AND to_revision = '65' AND backup_ref IS NOT NULL)
    OR (from_revision = '65' AND to_revision = '66' AND backup_ref IS NOT NULL)
    OR (from_revision = '66' AND to_revision = '67' AND backup_ref IS NOT NULL)
    OR (from_revision = '67' AND to_revision = '68' AND backup_ref IS NOT NULL)
    OR (from_revision = '68' AND to_revision = '69' AND backup_ref IS NOT NULL)
    OR (from_revision = '69' AND to_revision = '70' AND backup_ref IS NOT NULL)
    OR (from_revision = '70' AND to_revision = '71' AND backup_ref IS NOT NULL)
    OR (from_revision = '71' AND to_revision = '72' AND backup_ref IS NOT NULL)
    OR (from_revision = '72' AND to_revision = '73' AND backup_ref IS NOT NULL)
    OR (from_revision = '73' AND to_revision = '74' AND backup_ref IS NOT NULL)
    OR (from_revision = '74' AND to_revision = '75' AND backup_ref IS NOT NULL)
    OR (from_revision = '75' AND to_revision = '76' AND backup_ref IS NOT NULL)
    OR (from_revision = '76' AND to_revision = '77' AND backup_ref IS NOT NULL)
    OR (from_revision = '77' AND to_revision = '78' AND backup_ref IS NOT NULL)
    OR (from_revision = '78' AND to_revision = '79' AND backup_ref IS NOT NULL)
    OR (from_revision = '79' AND to_revision = '80' AND backup_ref IS NOT NULL)
    OR (from_revision = '80' AND to_revision = '81' AND backup_ref IS NOT NULL)
    OR (from_revision = '81' AND to_revision = '82' AND backup_ref IS NOT NULL)
    OR (from_revision = '82' AND to_revision = '83' AND backup_ref IS NOT NULL)
    OR (from_revision = '83' AND to_revision = '84' AND backup_ref IS NOT NULL)
    OR (from_revision = '84' AND to_revision = '85' AND backup_ref IS NOT NULL)
    OR (from_revision = '85' AND to_revision = '86' AND backup_ref IS NOT NULL)
    OR (from_revision = '86' AND to_revision = '87' AND backup_ref IS NOT NULL)
    OR (from_revision = '87' AND to_revision = '88' AND backup_ref IS NOT NULL)
    OR (from_revision = '88' AND to_revision = '89' AND backup_ref IS NOT NULL)
    OR (from_revision = '89' AND to_revision = '90' AND backup_ref IS NOT NULL)
    OR (from_revision = '90' AND to_revision = '91' AND backup_ref IS NOT NULL)
    OR (from_revision = '91' AND to_revision = '92' AND backup_ref IS NOT NULL)
    OR (from_revision = '92' AND to_revision = '93' AND backup_ref IS NOT NULL)
    OR (from_revision = '93' AND to_revision = '94' AND backup_ref IS NOT NULL)
    OR (from_revision = '94' AND to_revision = '95' AND backup_ref IS NOT NULL)
    OR (from_revision = '95' AND to_revision = '96' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v96 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v96 RENAME TO schema_migration;
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

CREATE TABLE device_recovery_authorization_v96 (
 authorization_id TEXT PRIMARY KEY NOT NULL,request_id TEXT NOT NULL UNIQUE,device_id TEXT NOT NULL,protected_state_id TEXT NOT NULL,
 manual_source_id TEXT,evaluator_source_id TEXT NOT NULL,body_jcs TEXT NOT NULL,body_digest TEXT NOT NULL,
 FOREIGN KEY(request_id) REFERENCES device_recovery_request(request_id),
 FOREIGN KEY(device_id,protected_state_id) REFERENCES device_authorization_state(device_id,state_id),
 FOREIGN KEY(manual_source_id) REFERENCES execution_manual_authority(source_id),
 FOREIGN KEY(evaluator_source_id) REFERENCES device_evaluator_source(source_id)
) STRICT;
INSERT INTO device_recovery_authorization_v96 SELECT * FROM device_recovery_authorization;
DROP TABLE device_recovery_authorization;
ALTER TABLE device_recovery_authorization_v96 RENAME TO device_recovery_authorization;
CREATE TRIGGER device_recovery_authorization_parent BEFORE INSERT ON device_recovery_authorization
WHEN NOT EXISTS(SELECT 1 FROM device_recovery_request r JOIN device_authorization_state s USING(state_id)
 JOIN device_evaluator_source e ON e.source_id=NEW.evaluator_source_id JOIN device_evaluator_challenge ch ON ch.challenge_id=e.challenge_id
 LEFT JOIN execution_manual_authority m ON m.source_id=NEW.manual_source_id
 WHERE r.request_id=NEW.request_id AND r.authorization_id=NEW.authorization_id AND r.device_id=NEW.device_id
 AND r.state_id=NEW.protected_state_id AND ch.device_id=r.device_id
 AND json_extract(r.body_jcs,'$.request.evaluator_source_ref.id') IS NEW.evaluator_source_id
 AND json_extract(r.body_jcs,'$.request.manual_source_ref.id') IS NEW.manual_source_id
 AND json_extract(r.body_jcs,'$.selection.context.mode') IS json_extract(s.body_jcs,'$.context.mode')
 AND ((json_extract(s.body_jcs,'$.context.mode')='manual' AND m.device_id=r.device_id AND m.token_id=r.token_id)
 OR (json_extract(s.body_jcs,'$.context.mode')='automatic' AND NEW.manual_source_id IS NULL
 AND json_type(r.body_jcs,'$.request.manual_source_ref')='null' AND json_type(s.body_jcs,'$.context.holder')='null')))
BEGIN SELECT RAISE(ABORT,'device_recovery_authorization_parent'); END;
CREATE TRIGGER device_recovery_authorization_no_update BEFORE UPDATE ON device_recovery_authorization BEGIN SELECT RAISE(ABORT,'immutable_device_recovery'); END;
CREATE TRIGGER device_recovery_authorization_no_delete BEFORE DELETE ON device_recovery_authorization BEGIN SELECT RAISE(ABORT,'immutable_device_recovery'); END;
CREATE TRIGGER device_recovery_consumption_parent BEFORE INSERT ON device_recovery_consumption
WHEN NOT EXISTS(SELECT 1 FROM device_recovery_authorization a JOIN device_recovery_request r USING(request_id)
 JOIN device_authorization_head h ON h.device_id=a.device_id AND h.state_id=a.protected_state_id
 WHERE a.authorization_id=NEW.authorization_id AND a.request_id=NEW.request_id AND r.authorization_id=a.authorization_id)
BEGIN SELECT RAISE(ABORT,'device_recovery_consumption_parent'); END;

CREATE TRIGGER control_gate_successor BEFORE INSERT ON control_state_source
WHEN NEW.change_kind IN('ready','gate_protect') AND NOT EXISTS (
 SELECT 1 FROM control_state_source b WHERE b.device_id=NEW.device_id AND b.revision+1=NEW.revision
 AND json_extract(NEW.body_jcs,'$.scope')=json_extract(b.body_jcs,'$.scope')
 AND json_extract(NEW.body_jcs,'$.holder') IS json_extract(b.body_jcs,'$.holder')
 AND json_extract(NEW.body_jcs,'$.mode')=json_extract(b.body_jcs,'$.mode')
 AND ((json_extract(b.body_jcs,'$.mode')='manual' AND json_type(b.body_jcs,'$.holder')='object')
 OR (json_extract(b.body_jcs,'$.mode')='automatic' AND json_type(b.body_jcs,'$.holder')='null'))
 AND json_extract(NEW.body_jcs,'$.control_epoch')=json_extract(b.body_jcs,'$.control_epoch')
 AND json_extract(NEW.body_jcs,'$.effective_version')=json_extract(b.body_jcs,'$.effective_version')
 AND json_extract(NEW.body_jcs,'$.reserved_version')=json_extract(b.body_jcs,'$.reserved_version')
 AND json_extract(NEW.body_jcs,'$.pending_operation_id') IS NULL
 AND b.clock_domain_id=NEW.clock_domain_id AND b.descriptor_digest=NEW.descriptor_digest
 AND ((NEW.change_kind='ready' AND json_extract(b.body_jcs,'$.gate_state')='protected'
 AND json_extract(NEW.body_jcs,'$.gate_state')='ready' AND EXISTS(SELECT 1 FROM device_initial_ready r
 JOIN device_authorization_evidence e ON e.evidence_id=json_extract(r.body_jcs,'$.authorization_evidence_ref.id')
 WHERE r.control_source_id=NEW.source_id AND json_extract(r.body_jcs,'$.control_before_ref.id')=b.source_id
 AND json_extract(r.body_jcs,'$.control_after_ref.digest')=NEW.body_digest
 AND json_extract(e.body_jcs,'$.requirement.control_mode')=json_extract(b.body_jcs,'$.mode')
 AND json_extract(e.body_jcs,'$.requirement.control_state_ref.id')=b.source_id))
 OR (NEW.change_kind='gate_protect' AND b.change_kind='ready' AND json_extract(b.body_jcs,'$.gate_state')='ready'
 AND json_extract(NEW.body_jcs,'$.gate_state')='protected'))
) BEGIN SELECT RAISE(ABORT,'control_gate_successor'); END;

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


DROP TRIGGER execution_initial_fence_parent;
CREATE TRIGGER execution_initial_fence_parent BEFORE INSERT ON execution_initial_fence BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM device_execution_binding b
 JOIN control_record_revision c ON c.device_id=NEW.control_device_id AND c.revision=NEW.control_revision
 JOIN control_record_head h ON h.device_id=c.device_id AND h.revision=c.revision
 JOIN execution_frame_record f ON f.record_id=NEW.request_record_id AND f.transaction_id=NEW.request_transaction_id
 JOIN execution_handshake n ON n.ipc_session_id=b.ipc_session_id
 WHERE b.binding_id=NEW.binding_id AND b.device_id=c.device_id AND f.ipc_session_id=b.ipc_session_id AND f.device_id=b.device_id
 AND f.direction='c2w' AND f.message_type='FENCE' AND f.domain_kind='initial_control'
 AND (json_extract(c.body_jcs,'$.mode')='manual' OR
  (json_extract(c.body_jcs,'$.mode')='automatic' AND json_type(c.body_jcs,'$.holder')='null'
  AND (SELECT count(DISTINCT value) FROM json_each(n.body_jcs,'$.selected_features')
   WHERE value IN ('automation_origin_binding','run_generation_fence','run_deny_snapshot'))=3))
 AND json_extract(c.body_jcs,'$.gate_state')='protected'
 AND json_type(c.body_jcs,'$.pending_change')='null'
 AND json_array_length(c.body_jcs,'$.in_flight_command_ids')=0 AND json_array_length(c.body_jcs,'$.unresolved_command_ids')=0
 AND json_extract(NEW.body_jcs,'$.fence_id')=NEW.fence_id
 AND json_extract(NEW.body_jcs,'$.gate_state')='closed'
 AND json_extract(NEW.body_jcs,'$.binding_ref.id')=b.binding_id AND json_extract(NEW.body_jcs,'$.binding_ref.digest')=b.body_digest
 AND json_extract(NEW.body_jcs,'$.control_record')=c.body_jcs
 AND json_extract(NEW.body_jcs,'$.request_record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.request_record_ref.digest')=f.record_digest
 AND json_extract(f.frame_jcs,'$.body.barrier_id')=NEW.fence_id
 AND json_extract(f.frame_jcs,'$.body.control_epoch')=json_extract(c.body_jcs,'$.control_epoch')
 AND json_extract(f.frame_jcs,'$.body.target_version')=json_extract(c.body_jcs,'$.effective_version')
 AND json_extract(f.frame_jcs,'$.body.target_gate_revision')='1' AND json_extract(f.frame_jcs,'$.body.issued_cut_revision')='0'
 AND json_array_length(f.frame_jcs,'$.body.open_intents')=0 AND json_array_length(f.frame_jcs,'$.body.open_transmission_intents')=0
 AND json_array_length(f.frame_jcs,'$.body.cancel_transmissions')=0
 AND json_extract(f.frame_jcs,'$.body.attempt_binding.target_exit_id')=b.writer_exit_id
 AND json_extract(f.frame_jcs,'$.body.attempt_binding.attempt_ordinal')='1' AND json_type(f.frame_jcs,'$.body.attempt_binding.previous_barrier_id')='null'
 AND EXISTS(SELECT 1 FROM json_each(n.body_jcs,'$.selected_features') WHERE value='initial_control_fence')
 AND NOT EXISTS(SELECT 1 FROM ca_adjudication a JOIN ca_request_key k USING(key_id) WHERE k.device_id=b.device_id AND a.decision!='rejected'))
 THEN RAISE(ABORT,'execution_initial_fence_binding') END;
END;
