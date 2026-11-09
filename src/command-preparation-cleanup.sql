DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v56 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '56'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v56 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '56', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v56 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v56 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56')),
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
    OR (from_revision = '55' AND to_revision = '56' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v56 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v56 RENAME TO schema_migration;
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


CREATE TABLE command_preparation_retirement (
 permit_id TEXT PRIMARY KEY NOT NULL REFERENCES command_settlement(permit_id),prepare_id TEXT NOT NULL UNIQUE REFERENCES command_encoding_request(prepare_id),
 command_id TEXT NOT NULL UNIQUE REFERENCES command_settlement(command_id),body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71)
) STRICT;
CREATE TABLE command_preparation_cleanup (
 permit_id TEXT NOT NULL REFERENCES command_preparation_retirement(permit_id),phase TEXT NOT NULL CHECK(phase IN('deny_request','deny_ack','release_request','release_ack')),
 record_id TEXT NOT NULL UNIQUE,transaction_id TEXT NOT NULL UNIQUE,write_attempt_id TEXT REFERENCES execution_write_attempt(attempt_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 CHECK((phase IN('deny_request','release_request') AND write_attempt_id IS NULL) OR (phase IN('deny_ack','release_ack') AND write_attempt_id IS NOT NULL)),
 PRIMARY KEY(permit_id,phase),UNIQUE(permit_id,phase,record_id,transaction_id),
 FOREIGN KEY(record_id,transaction_id) REFERENCES execution_frame_record(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
DROP TRIGGER execution_dispatch_effect;
DROP TRIGGER execution_dispatch_frame_no_update;
DROP TRIGGER execution_dispatch_frame_no_delete;
CREATE TABLE execution_dispatch_frame_v56 (
 record_id TEXT PRIMARY KEY NOT NULL,transaction_id TEXT NOT NULL UNIQUE,
 permit_id TEXT NOT NULL REFERENCES command_dispatch_request(permit_id) DEFERRABLE INITIALLY DEFERRED,
 phase TEXT NOT NULL CHECK(phase IN('request','report','evidence','fence_request','fence_ack','deny_request','deny_ack','release_request','release_ack')),domain_jcs TEXT NOT NULL CHECK(json_valid(domain_jcs)),domain_digest TEXT NOT NULL CHECK(length(domain_digest)=71),
 request_permit_id TEXT GENERATED ALWAYS AS(CASE WHEN phase='request' THEN permit_id END) VIRTUAL,
 report_permit_id TEXT GENERATED ALWAYS AS(CASE WHEN phase='report' THEN permit_id END) VIRTUAL,
 evidence_permit_id TEXT GENERATED ALWAYS AS(CASE WHEN phase='evidence' THEN permit_id END) VIRTUAL,
 fence_request_permit_id TEXT GENERATED ALWAYS AS(CASE WHEN phase='fence_request' THEN permit_id END) VIRTUAL,
 fence_ack_permit_id TEXT GENERATED ALWAYS AS(CASE WHEN phase='fence_ack' THEN permit_id END) VIRTUAL,
 cleanup_permit_id TEXT GENERATED ALWAYS AS(CASE WHEN phase IN('deny_request','deny_ack','release_request','release_ack') THEN permit_id END) VIRTUAL,
 UNIQUE(record_id,transaction_id),UNIQUE(permit_id,phase),
 FOREIGN KEY(cleanup_permit_id,phase,record_id,transaction_id) REFERENCES command_preparation_cleanup(permit_id,phase,record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(record_id,transaction_id) REFERENCES execution_frame_record(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(request_permit_id,record_id,transaction_id) REFERENCES command_dispatch_request(permit_id,record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(report_permit_id,record_id,transaction_id) REFERENCES command_dispatch_report(permit_id,record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(fence_request_permit_id,record_id,transaction_id) REFERENCES command_closure_request(permit_id,record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(fence_ack_permit_id,record_id,transaction_id) REFERENCES command_closure_ack(permit_id,record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(evidence_permit_id,record_id,transaction_id) REFERENCES command_dispatch_evidence(permit_id,record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO execution_dispatch_frame_v56(record_id,transaction_id,permit_id,phase,domain_jcs,domain_digest) SELECT record_id,transaction_id,permit_id,phase,domain_jcs,domain_digest FROM execution_dispatch_frame;
DROP TABLE execution_dispatch_frame;
ALTER TABLE execution_dispatch_frame_v56 RENAME TO execution_dispatch_frame;
CREATE TRIGGER execution_dispatch_frame_no_update BEFORE UPDATE ON execution_dispatch_frame BEGIN SELECT RAISE(ABORT,'immutable_command_dispatch'); END;
CREATE TRIGGER execution_dispatch_frame_no_delete BEFORE DELETE ON execution_dispatch_frame BEGIN SELECT RAISE(ABORT,'immutable_command_dispatch'); END;
DROP TRIGGER execution_frame_parent;
CREATE TRIGGER execution_frame_parent BEFORE INSERT ON execution_frame_record BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_session s JOIN service_boot b USING(service_boot_id)
 WHERE s.ipc_session_id=NEW.ipc_session_id AND b.state='started'
 AND NOT EXISTS(SELECT 1 FROM execution_session_end e WHERE e.ipc_session_id=s.ipc_session_id)
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=s.runtime_id)
 AND json_extract(NEW.frame_jcs,'$.ipc_session_id')=s.ipc_session_id
 AND json_extract(NEW.frame_jcs,'$.ipc_version')=json_extract(s.binding_jcs,'$.ipc_version')
 AND json_extract(NEW.frame_jcs,'$.controller_boot_id')=s.controller_boot_id
 AND json_extract(NEW.frame_jcs,'$.worker_boot_id')=s.worker_boot_id
 AND json_extract(NEW.frame_jcs,'$.clock_domain_id')=s.clock_domain_id
 AND json_extract(NEW.frame_jcs,'$.descriptor_digest')=s.descriptor_digest
 AND json_extract(NEW.frame_jcs,'$.message_id')=NEW.message_id
 AND json_extract(NEW.frame_jcs,'$.type')=NEW.message_type
 AND json_extract(NEW.frame_jcs,'$.journal_mode')='durable'
 AND json_type(NEW.frame_jcs,'$.seq')='text'
 AND substr('00000000000000000000'||json_extract(NEW.frame_jcs,'$.seq'),-20)=NEW.sequence
 AND json_extract(NEW.frame_jcs,'$.device_id') IS NEW.device_id
 AND json_extract(NEW.record_jcs,'$.record_id')=NEW.record_id
 AND json_extract(NEW.record_jcs,'$.session_ref.id')=s.ipc_session_id
 AND json_extract(NEW.record_jcs,'$.session_ref.revision')='1'
 AND json_extract(NEW.record_jcs,'$.session_ref.digest')=s.binding_digest
 AND json_extract(NEW.record_jcs,'$.direction')=NEW.direction
 AND json_extract(NEW.record_jcs,'$.sequence')=json_extract(NEW.frame_jcs,'$.seq')
 AND json_extract(NEW.record_jcs,'$.message_id')=NEW.message_id
 AND json_extract(NEW.record_jcs,'$.message_type')=NEW.message_type
 AND json_extract(NEW.record_jcs,'$.frame_digest')=NEW.frame_digest
 AND json_extract(NEW.record_jcs,'$.wire_digest')=NEW.wire_digest
 AND json_extract(NEW.record_jcs,'$.wire_length')=length(NEW.wire)
 AND json_extract(NEW.record_jcs,'$.record_digest')=NEW.record_digest
 AND json_extract(NEW.record_jcs,'$.frame_object_ref.id')=NEW.record_id||'.frame'
 AND json_extract(NEW.record_jcs,'$.frame_object_ref.revision')='1'
 AND json_extract(NEW.record_jcs,'$.frame_object_ref.digest')=NEW.frame_digest
 AND json_extract(NEW.record_jcs,'$.wire_object_ref.id')=NEW.record_id||'.wire'
 AND json_extract(NEW.record_jcs,'$.wire_object_ref.revision')='1'
 AND json_extract(NEW.record_jcs,'$.wire_object_ref.digest')=NEW.wire_digest)
 THEN RAISE(ABORT,'execution_frame_binding') END;
 SELECT CASE WHEN NEW.sequence!=coalesce((SELECT CASE WHEN substr(sequence,11,10)='9999999999'
 THEN printf('%010d',CAST(substr(sequence,1,10) AS INTEGER)+1)||'0000000000'
 ELSE substr(sequence,1,10)||printf('%010d',CAST(substr(sequence,11,10) AS INTEGER)+1) END
 FROM execution_frame_record WHERE ipc_session_id=NEW.ipc_session_id AND direction=NEW.direction ORDER BY sequence DESC LIMIT 1),'00000000000000000001')
 THEN RAISE(ABORT,'execution_frame_sequence') END;
 -- 每个已实现领域必须显式连接真实写集；尚未连接的类型不能以通用applied绕过。
 SELECT CASE WHEN NOT (NEW.sequence='00000000000000000001' AND NEW.device_id IS NULL AND (
 (NEW.direction='w2c' AND NEW.message_type='HELLO' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
 (NEW.domain_kind='hello_negotiation' AND NEW.direction='c2w' AND NEW.message_type='HELLO_ACK' AND EXISTS(SELECT 1 FROM execution_frame_record h
 WHERE h.record_id=NEW.reply_record_id AND h.ipc_session_id=NEW.ipc_session_id AND h.direction='w2c' AND h.message_type='HELLO' AND h.domain_kind='hello_negotiation'
 AND h.message_id=json_extract(NEW.frame_jcs,'$.reply_to')))) OR
 (NEW.domain_kind='initial_control' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001' AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND (
 (NEW.direction='c2w' AND NEW.message_type='FENCE' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
 (NEW.direction='w2c' AND NEW.message_type='FENCE_ACK' AND EXISTS(SELECT 1 FROM execution_frame_record p WHERE p.record_id=NEW.reply_record_id AND p.ipc_session_id=NEW.ipc_session_id AND p.direction='c2w' AND p.message_type='FENCE' AND p.domain_kind='initial_control' AND p.message_id=json_extract(NEW.frame_jcs,'$.reply_to'))))) OR (NEW.domain_kind='initial_open' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001'
   AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND (
    (NEW.direction='c2w' AND NEW.message_type='OPEN_GATE' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
    (NEW.direction='w2c' AND NEW.message_type='OPEN_GATE_ACK' AND EXISTS(SELECT 1 FROM execution_frame_record p
     WHERE p.record_id=NEW.reply_record_id AND p.ipc_session_id=NEW.ipc_session_id AND p.direction='c2w' AND p.message_type='OPEN_GATE'
      AND p.domain_kind='initial_open' AND p.message_id=json_extract(NEW.frame_jcs,'$.reply_to'))))) OR
 (NEW.domain_kind='command_encoding' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001'
 AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND (
  (NEW.direction='c2w' AND NEW.message_type='ENCODE_PACKET' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
  (NEW.direction='w2c' AND NEW.message_type IN('PREPARE_PACKET','PACKET_ENCODING_FAILED') AND EXISTS(SELECT 1 FROM execution_frame_record p
   WHERE p.record_id=NEW.reply_record_id AND p.ipc_session_id=NEW.ipc_session_id AND p.device_id=NEW.device_id AND p.direction='c2w'
    AND p.message_type='ENCODE_PACKET' AND p.domain_kind='command_encoding' AND p.message_id=json_extract(NEW.frame_jcs,'$.reply_to'))))) OR
 (NEW.domain_kind='command_guard' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001'
 AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND (
 (NEW.direction='c2w' AND NEW.message_type='GUARD_INSTALL' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
 (NEW.direction='w2c' AND NEW.message_type='GUARD_ACK' AND EXISTS(SELECT 1 FROM execution_frame_record p WHERE p.record_id=NEW.reply_record_id
 AND p.ipc_session_id=NEW.ipc_session_id AND p.device_id=NEW.device_id AND p.direction='c2w' AND p.message_type='GUARD_INSTALL'
 AND p.domain_kind='command_guard' AND p.message_id=json_extract(NEW.frame_jcs,'$.reply_to'))))) OR
 (NEW.domain_kind='command_dispatch' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001'
 AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null' AND (
 (NEW.direction='c2w' AND NEW.message_type='DISPATCH') OR
 (NEW.direction='w2c' AND NEW.message_type IN('SEND_REPORT','EVIDENCE_CANDIDATE')))) OR
 (NEW.domain_kind='command_dispatch' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001'
 AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND (
 (NEW.direction='c2w' AND NEW.message_type='FENCE' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
 (NEW.direction='w2c' AND NEW.message_type='FENCE_ACK' AND EXISTS(SELECT 1 FROM execution_frame_record p JOIN command_closure_request c ON c.record_id=p.record_id
 WHERE p.record_id=NEW.reply_record_id AND p.ipc_session_id=NEW.ipc_session_id AND p.device_id=NEW.device_id AND p.direction='c2w'
 AND p.message_type='FENCE' AND p.domain_kind='command_dispatch' AND p.message_id=json_extract(NEW.frame_jcs,'$.reply_to')))))
 OR
 (NEW.domain_kind='command_dispatch' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001'
 AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND (
 (NEW.direction='c2w' AND NEW.message_type IN('DENY_ENCODING','RELEASE_ENCODING') AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
 (NEW.direction='w2c' AND NEW.message_type IN('DENY_ENCODING_ACK','RELEASE_ENCODING_ACK') AND EXISTS(
 SELECT 1 FROM execution_frame_record p JOIN command_preparation_cleanup c ON c.record_id=p.record_id
 WHERE p.record_id=NEW.reply_record_id AND p.ipc_session_id=NEW.ipc_session_id AND p.device_id=NEW.device_id AND p.direction='c2w'
 AND p.domain_kind='command_dispatch' AND p.message_type||'_ACK'=NEW.message_type AND p.message_id=json_extract(NEW.frame_jcs,'$.reply_to'))))))
 THEN RAISE(ABORT,'execution_frame_domain') END;
 SELECT CASE WHEN (SELECT count(*) FROM execution_frame_record)>=65536 OR
 (SELECT coalesce(sum(length(wire)+length(CAST(frame_jcs AS BLOB))+length(CAST(record_jcs AS BLOB))+32768),0) FROM execution_frame_record)
 +length(NEW.wire)+length(CAST(NEW.frame_jcs AS BLOB))+length(CAST(NEW.record_jcs AS BLOB))+32768>67108864
 THEN RAISE(ABORT,'execution_frame_capacity') END;
END;
DROP TRIGGER execution_write_parent;
CREATE TRIGGER execution_write_parent BEFORE INSERT ON execution_write_attempt BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
 LEFT JOIN execution_handshake n ON n.ack_record_id=f.record_id LEFT JOIN execution_initial_fence c ON c.request_record_id=f.record_id LEFT JOIN execution_initial_open_dispatch o ON o.request_record_id=f.record_id LEFT JOIN command_encoding_request q ON q.record_id=f.record_id LEFT JOIN command_guard_request g ON g.record_id=f.record_id LEFT JOIN command_dispatch_request d ON d.record_id=f.record_id LEFT JOIN command_closure_request z ON z.record_id=f.record_id LEFT JOIN command_preparation_cleanup u ON u.record_id=f.record_id JOIN execution_session s ON s.ipc_session_id=f.ipc_session_id
 JOIN service_boot b USING(service_boot_id)
 WHERE f.record_id=NEW.record_id AND f.direction='c2w' AND ((f.message_type='HELLO_ACK' AND n.ack_record_id=f.record_id) OR (f.message_type='FENCE' AND (c.request_record_id=f.record_id OR (z.record_id=f.record_id AND NOT EXISTS(SELECT 1 FROM execution_write_attempt prior WHERE prior.record_id=f.record_id)))) OR (f.message_type='OPEN_GATE' AND o.request_record_id=f.record_id) OR (f.message_type='ENCODE_PACKET' AND q.record_id=f.record_id AND NOT EXISTS(SELECT 1 FROM execution_write_attempt prior WHERE prior.record_id=f.record_id)) OR (f.message_type='GUARD_INSTALL' AND g.record_id=f.record_id AND NOT EXISTS(SELECT 1 FROM execution_write_attempt prior WHERE prior.record_id=f.record_id)) OR (f.message_type='DISPATCH' AND d.record_id=f.record_id AND NOT EXISTS(SELECT 1 FROM execution_write_attempt prior WHERE prior.record_id=f.record_id)) OR (f.message_type IN('DENY_ENCODING','RELEASE_ENCODING') AND u.record_id=f.record_id AND NOT EXISTS(SELECT 1 FROM execution_write_attempt prior WHERE prior.record_id=f.record_id))) AND e.disposition='applied'
 AND e.committed_tick<=NEW.started_tick AND b.state='started'
 AND NOT EXISTS(SELECT 1 FROM execution_session_end x WHERE x.ipc_session_id=s.ipc_session_id)
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=s.runtime_id))
 THEN RAISE(ABORT,'execution_write_binding') END;
END;
CREATE TRIGGER execution_dispatch_effect BEFORE INSERT ON execution_effect_commit
WHEN (SELECT domain_kind FROM execution_frame_record WHERE record_id=NEW.record_id)='command_dispatch' BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_frame_record f JOIN execution_dispatch_frame x USING(record_id,transaction_id)
 JOIN command_dispatch_request p USING(permit_id) LEFT JOIN command_dispatch_report r USING(permit_id) LEFT JOIN command_dispatch_evidence o USING(permit_id) LEFT JOIN command_closure_request c USING(permit_id) LEFT JOIN command_closure_ack k USING(permit_id) LEFT JOIN command_preparation_cleanup z ON z.permit_id=x.permit_id AND z.phase=x.phase
 WHERE f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id AND f.observed_tick<=NEW.committed_tick AND NEW.disposition='applied'
 AND ((x.phase='request' AND f.record_id=p.record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=p.body_digest)
  OR (x.phase='report' AND f.record_id=r.record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=r.body_digest)
  OR (x.phase='fence_request' AND f.record_id=c.record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=c.body_digest)
  OR (x.phase='fence_ack' AND f.record_id=k.record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=k.body_digest)
  OR (x.phase IN('deny_request','deny_ack','release_request','release_ack') AND f.record_id=z.record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=z.body_digest)
  OR (x.phase='evidence' AND f.record_id=o.record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=o.body_digest))
 AND json_extract(x.domain_jcs,'$.transaction_id')=f.transaction_id
 AND json_extract(x.domain_jcs,'$.source_ref.id')=p.permit_id||CASE WHEN x.phase='request' THEN '' ELSE '.'||x.phase END
 AND json_extract(NEW.effect_jcs,'$.record_ref.id')=f.record_id AND json_extract(NEW.effect_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].id')=f.transaction_id AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].digest')=x.domain_digest
 AND json_extract(NEW.effect_jcs,'$.audit_ref.digest')=NEW.audit_digest AND json_extract(NEW.audit_jcs,'$.kind')='command_dispatch_'||x.phase
 AND json_extract(NEW.audit_jcs,'$.permit_id')=p.permit_id AND json_extract(NEW.audit_jcs,'$.source_digest')=json_extract(x.domain_jcs,'$.source_ref.digest'))
 THEN RAISE(ABORT,'execution_dispatch_effect_binding') END;
END;


CREATE TRIGGER command_preparation_retirement_parent BEFORE INSERT ON command_preparation_retirement WHEN NOT EXISTS(
 SELECT 1 FROM command_settlement s JOIN command_final_admission a USING(permit_id,command_id)
 JOIN command_encoding_request e ON e.prepare_id=NEW.prepare_id AND e.command_id=s.command_id
 JOIN command_lifecycle_head h ON h.command_id=s.command_id AND h.commit_id=s.commit_id AND h.revision=5
 WHERE s.permit_id=NEW.permit_id AND s.command_id=NEW.command_id AND json_extract(a.body_jcs,'$.prepare_id')=e.prepare_id
 AND json_extract(NEW.body_jcs,'$.settlement_ref.digest')=s.body_digest AND json_extract(NEW.body_jcs,'$.encoding_ref.digest')=e.body_digest
) BEGIN SELECT RAISE(ABORT,'command_preparation_retirement_binding'); END;
CREATE TRIGGER command_preparation_cleanup_parent BEFORE INSERT ON command_preparation_cleanup WHEN NOT EXISTS(
 SELECT 1 FROM command_preparation_retirement p JOIN execution_frame_record f ON f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id
 WHERE p.permit_id=NEW.permit_id AND f.domain_kind='command_dispatch'
 AND json_extract(NEW.body_jcs,'$.retirement_ref.digest')=p.body_digest
 AND json_extract(NEW.body_jcs,'$.record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.record_ref.digest')=f.record_digest
 AND ((NEW.phase IN('deny_request','release_request') AND f.direction='c2w' AND f.message_type=CASE NEW.phase WHEN 'deny_request' THEN 'DENY_ENCODING' ELSE 'RELEASE_ENCODING' END
  AND (NEW.phase='deny_request' OR EXISTS(SELECT 1 FROM command_preparation_cleanup x WHERE x.permit_id=p.permit_id AND x.phase='deny_ack')))
 OR (NEW.phase IN('deny_ack','release_ack') AND f.direction='w2c' AND f.message_type=CASE NEW.phase WHEN 'deny_ack' THEN 'DENY_ENCODING_ACK' ELSE 'RELEASE_ENCODING_ACK' END
  AND EXISTS(SELECT 1 FROM command_preparation_cleanup x JOIN execution_write_attempt w ON w.record_id=x.record_id
   WHERE x.permit_id=p.permit_id AND x.phase=CASE NEW.phase WHEN 'deny_ack' THEN 'deny_request' ELSE 'release_request' END
   AND w.attempt_id=NEW.write_attempt_id AND f.reply_record_id=x.record_id AND w.started_tick<=f.observed_tick)))
) BEGIN SELECT RAISE(ABORT,'command_preparation_cleanup_binding'); END;
CREATE TRIGGER command_preparation_retirement_no_update BEFORE UPDATE ON command_preparation_retirement BEGIN SELECT RAISE(ABORT,'immutable_preparation_cleanup'); END;
CREATE TRIGGER command_preparation_retirement_no_delete BEFORE DELETE ON command_preparation_retirement BEGIN SELECT RAISE(ABORT,'immutable_preparation_cleanup'); END;
CREATE TRIGGER command_preparation_cleanup_no_update BEFORE UPDATE ON command_preparation_cleanup BEGIN SELECT RAISE(ABORT,'immutable_preparation_cleanup'); END;
CREATE TRIGGER command_preparation_cleanup_no_delete BEFORE DELETE ON command_preparation_cleanup BEGIN SELECT RAISE(ABORT,'immutable_preparation_cleanup'); END;
