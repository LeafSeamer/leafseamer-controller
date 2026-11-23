DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER extension_owner_binding;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v103 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '103'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v103 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '103', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v103 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v103 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 103),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v103 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v103 RENAME TO schema_migration;
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

CREATE TRIGGER ca_namespace_parent BEFORE INSERT ON ca_namespace
WHEN NEW.owner_evidence_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM request_context c JOIN service_state s ON c.service_id=s.service_id
 WHERE c.context_id=NEW.owner_evidence_id AND c.database_instance_id=s.database_instance_id
 AND c.issuer_id=NEW.issuer_id AND c.issuer_epoch=NEW.issuer_epoch AND c.principal_id=NEW.principal_id
 AND c.context_epoch=NEW.request_epoch AND c.body=NEW.owner_evidence_body)
BEGIN SELECT RAISE(ABORT,'namespace_context_binding'); END;


CREATE TRIGGER obs_local_resource_parent BEFORE INSERT ON obs_local_resource
WHEN NOT EXISTS (
  SELECT 1 FROM device_record d JOIN service_state s ON s.singleton = 1
  WHERE d.device_id = NEW.device_id AND json_extract(CAST(d.descriptor_body AS TEXT), '$.device_kind') = 'obs'
    AND json_extract(NEW.body_jcs, '$.format') = 'leafseamer-obs-local-resource/1'
    AND json_extract(NEW.body_jcs, '$.resource_id') = NEW.resource_id
    AND json_extract(NEW.body_jcs, '$.device_ref.object_id') = NEW.device_id
    AND json_extract(NEW.body_jcs, '$.device_ref.digest') = d.descriptor_digest
    AND json_extract(NEW.body_jcs, '$.device_ref.authority_service_id') = s.service_id
    AND json_extract(NEW.body_jcs, '$.device_ref.database_instance_id') = s.database_instance_id
    AND json_extract(NEW.body_jcs, '$.endpoint.address') = '127.0.0.1'
    AND json_extract(NEW.body_jcs, '$.endpoint.port') = NEW.endpoint_port
    AND json_extract(NEW.body_jcs, '$.profile') = 'obs_isolated_empty_cut/1')
BEGIN SELECT RAISE(ABORT, 'obs_local_resource_parent'); END;

CREATE TRIGGER extension_owner_binding BEFORE INSERT ON extension_resource_owner
WHEN NOT EXISTS (
  SELECT 1 FROM device_resource_identity r JOIN service_state s ON s.singleton = 1
  WHERE r.resource_id = NEW.resource_id AND r.device_id = NEW.device_id
    AND json_extract(NEW.resource_ref_jcs, '$.kind') = 'resource'
    AND json_extract(NEW.resource_ref_jcs, '$.revision') = '1'
    AND json_extract(NEW.resource_ref_jcs, '$.digest') = r.body_digest
    AND json_extract(NEW.resource_ref_jcs, '$.authority_service_id') = s.service_id
    AND json_extract(NEW.resource_ref_jcs, '$.database_instance_id') = s.database_instance_id)
BEGIN SELECT RAISE(ABORT, 'extension_owner_binding'); END;

-- 保留原命令字节、预留与扣费。只为固定 OBS Cut 增加 52 字节记录。

PRAGMA legacy_alter_table=ON;

CREATE TABLE command_encoding_reservation_v103 (
 prepare_id TEXT PRIMARY KEY NOT NULL REFERENCES command_encoding_request(prepare_id) DEFERRABLE INITIALLY DEFERRED,
 command_id TEXT NOT NULL UNIQUE REFERENCES command_admission_source(command_id),max_bytes INTEGER NOT NULL CHECK(max_bytes IN(8,52)),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71)
) STRICT;
INSERT INTO command_encoding_reservation_v103 SELECT * FROM command_encoding_reservation;
DROP TABLE command_encoding_reservation;
ALTER TABLE command_encoding_reservation_v103 RENAME TO command_encoding_reservation;

CREATE TABLE command_encoding_response_v103 (
 prepare_id TEXT PRIMARY KEY NOT NULL REFERENCES command_encoding_request(prepare_id),record_id TEXT NOT NULL UNIQUE,transaction_id TEXT NOT NULL UNIQUE,
 write_attempt_id TEXT NOT NULL REFERENCES execution_write_attempt(attempt_id),
 disposition TEXT NOT NULL CHECK(disposition IN('prepared','failed','historical')),
 packet_bytes BLOB,body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 CHECK(packet_bytes IS NULL OR length(packet_bytes) IN(8,52)),UNIQUE(prepare_id,record_id,transaction_id),
 FOREIGN KEY(record_id,transaction_id) REFERENCES execution_frame_record(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO command_encoding_response_v103 SELECT * FROM command_encoding_response;
DROP TABLE command_encoding_response;
ALTER TABLE command_encoding_response_v103 RENAME TO command_encoding_response;

CREATE TABLE command_transmission_issue_v103 (
 permit_id TEXT PRIMARY KEY NOT NULL,transaction_id TEXT NOT NULL UNIQUE,
 issued_revision TEXT NOT NULL UNIQUE CHECK(length(issued_revision)=20 AND issued_revision NOT GLOB '*[^0-9]*' AND issued_revision>'00000000000000000000'),
 previous_revision TEXT NOT NULL UNIQUE CHECK(length(previous_revision)=20 AND previous_revision NOT GLOB '*[^0-9]*'),
 charged_bytes INTEGER NOT NULL CHECK(charged_bytes IN(8,52)),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 UNIQUE(transaction_id,permit_id),
 FOREIGN KEY(transaction_id,permit_id) REFERENCES command_final_admission(transaction_id,permit_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO command_transmission_issue_v103 SELECT * FROM command_transmission_issue;
DROP TABLE command_transmission_issue;
ALTER TABLE command_transmission_issue_v103 RENAME TO command_transmission_issue;

PRAGMA legacy_alter_table=OFF;

CREATE TRIGGER command_encoding_reservation_capacity BEFORE INSERT ON command_encoding_reservation
WHEN (SELECT count(*) FROM command_encoding_reservation)>=256
OR (SELECT coalesce(sum(max_bytes),0) FROM command_encoding_reservation)+NEW.max_bytes>13312
OR json_extract(NEW.body_jcs,'$.max_bytes') IS NOT NEW.max_bytes
OR NOT EXISTS(SELECT 1 FROM command_admission_source s JOIN device_execution_binding b USING(binding_id)
 WHERE s.command_id=NEW.command_id AND NEW.max_bytes=CASE json_extract(b.body_jcs,'$.primitive_plan.primitive_id')
  WHEN 'obs_program_scene_cut' THEN 52 WHEN 'simulator_value_set' THEN 8 END)
BEGIN SELECT RAISE(ABORT,'command_encoding_capacity'); END;

CREATE TRIGGER command_encoding_response_parent BEFORE INSERT ON command_encoding_response WHEN NOT EXISTS(
 SELECT 1 FROM command_encoding_request p JOIN execution_frame_record q ON q.record_id=p.record_id
 JOIN execution_frame_record f ON f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id
 JOIN execution_write_attempt w ON w.attempt_id=NEW.write_attempt_id AND w.record_id=q.record_id
 WHERE p.prepare_id=NEW.prepare_id AND f.direction='w2c' AND f.domain_kind='command_encoding'
 AND f.message_type IN('PREPARE_PACKET','PACKET_ENCODING_FAILED') AND f.reply_record_id=q.record_id
 AND f.ipc_session_id=q.ipc_session_id AND f.device_id=q.device_id AND w.started_tick<=f.observed_tick
 AND json_extract(NEW.body_jcs,'$.prepare_id')=p.prepare_id AND json_extract(NEW.body_jcs,'$.disposition')=NEW.disposition
 AND json_extract(NEW.body_jcs,'$.request_ref.digest')=p.body_digest
 AND json_extract(NEW.body_jcs,'$.record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(f.frame_jcs,'$.body.prepare_id')=p.prepare_id
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization_ref.id')=json_extract(p.body_jcs,'$.authorization.authorization_id')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization_ref.digest')=json_extract(p.body_jcs,'$.authorization.authorization_digest')
 AND ((f.message_type='PREPARE_PACKET' AND length(NEW.packet_bytes)=json_extract(p.body_jcs,'$.authorization.max_bytes')
  AND length(NEW.packet_bytes)=json_extract(f.frame_jcs,'$.body.packet.byte_length') AND lower(hex(NEW.packet_bytes))=json_extract(f.frame_jcs,'$.body.bytes_hex'))
  OR (f.message_type='PACKET_ENCODING_FAILED' AND NEW.packet_bytes IS NULL AND NEW.disposition!='prepared'))
 AND (NEW.disposition='historical' OR (NOT EXISTS(SELECT 1 FROM execution_write_result r WHERE r.attempt_id=w.attempt_id AND r.result='unknown')
  AND f.observed_tick<substr('00000000000000000000'||json_extract(p.body_jcs,'$.authorization.expires_tick_ns'),-20)))
) BEGIN SELECT RAISE(ABORT,'command_encoding_response_binding'); END;

CREATE TRIGGER command_transmission_issue_parent BEFORE INSERT ON command_transmission_issue
WHEN (SELECT count(*) FROM command_transmission_issue)>=4096
 OR NEW.previous_revision!=coalesce((SELECT max(issued_revision) FROM command_issue_order),'00000000000000000000')
 OR NOT EXISTS(SELECT 1 FROM command_final_admission f WHERE f.transaction_id=NEW.transaction_id AND f.permit_id=NEW.permit_id
 AND json_extract(f.body_jcs,'$.transmission_charge')=json(NEW.body_jcs)
 AND json_extract(NEW.body_jcs,'$.charged.bytes')=NEW.charged_bytes
 AND NEW.charged_bytes=CASE json_extract(f.body_jcs,'$.permit.transmission.primitive_id')
  WHEN 'obs_program_scene_cut' THEN 52 WHEN 'simulator_value_set' THEN 8 END
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.issued_revision'),-20)=NEW.issued_revision
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.previous_revision'),-20)=NEW.previous_revision)
BEGIN SELECT RAISE(ABORT,'command_transmission_issue_parent'); END;

CREATE TRIGGER command_transmission_issue_register AFTER INSERT ON command_transmission_issue
BEGIN
 INSERT INTO command_issue_order VALUES(NEW.issued_revision,NEW.previous_revision,NEW.permit_id,'ordinary');
END;

CREATE TRIGGER command_encoding_reservation_no_update BEFORE UPDATE ON command_encoding_reservation BEGIN SELECT RAISE(ABORT,'immutable_command_encoding'); END;

CREATE TRIGGER command_encoding_reservation_no_delete BEFORE DELETE ON command_encoding_reservation BEGIN SELECT RAISE(ABORT,'immutable_command_encoding'); END;

CREATE TRIGGER command_encoding_response_no_update BEFORE UPDATE ON command_encoding_response BEGIN SELECT RAISE(ABORT,'immutable_command_encoding'); END;

CREATE TRIGGER command_encoding_response_no_delete BEFORE DELETE ON command_encoding_response BEGIN SELECT RAISE(ABORT,'immutable_command_encoding'); END;

CREATE TRIGGER command_transmission_issue_no_update BEFORE UPDATE ON command_transmission_issue BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;

CREATE TRIGGER command_transmission_issue_no_delete BEFORE DELETE ON command_transmission_issue BEGIN SELECT RAISE(ABORT,'immutable_command_final_admission'); END;
