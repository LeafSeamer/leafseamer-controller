DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v25 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '25'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v25 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '25', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v25 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v25 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25')),
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
    OR (from_revision = '24' AND to_revision = '25' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v25 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v25 RENAME TO schema_migration;
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

DROP TRIGGER device_module_frame_parent;
CREATE TRIGGER device_module_frame_parent BEFORE INSERT ON device_module_frame WHEN NOT EXISTS(
 SELECT 1 FROM device_module_channel c JOIN worker_runtime_binding r USING(runtime_id) JOIN service_boot b USING(service_boot_id)
 WHERE c.channel_id=NEW.channel_id AND b.state='started'
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)
 AND json_extract(NEW.frame_jcs,'$.binding')=c.binding_jcs
 AND json_extract(NEW.frame_jcs,'$.version')IN ('device-module/1','device-module/2')
 AND json_extract(NEW.frame_jcs,'$.sequence')=NEW.sequence
 AND json_extract(NEW.frame_jcs,'$.request_id')=NEW.message_id
 AND json_extract(NEW.frame_jcs,'$.reply_to') IS NEW.reply_to
 AND json_extract(NEW.frame_jcs,'$.type')=NEW.message_type
 AND NEW.sequence=CAST((SELECT count(*)+1 FROM device_module_frame f WHERE f.channel_id=NEW.channel_id AND f.direction=NEW.direction) AS TEXT)
 AND ((NEW.direction='c2w' AND NEW.message_type IN('LOAD','CONNECT','CAPTURE','DISCONNECT')) OR EXISTS(
   SELECT 1 FROM device_module_frame q WHERE q.message_id=NEW.reply_to AND q.channel_id=NEW.channel_id AND q.direction='c2w' AND q.sequence=NEW.sequence
   AND NEW.message_type=CASE q.message_type WHEN 'LOAD' THEN 'LOADED' WHEN 'CONNECT' THEN 'CONNECTED' WHEN 'CAPTURE' THEN 'CAPTURED' WHEN 'DISCONNECT' THEN 'DISCONNECTED' END))
) BEGIN SELECT RAISE(ABORT,'module_frame_binding'); END;
CREATE TABLE device_catalog_approval (
 approval_id TEXT PRIMARY KEY NOT NULL,
 channel_id TEXT NOT NULL REFERENCES device_module_channel(channel_id),
 device_id TEXT NOT NULL REFERENCES device_record(device_id),
 device_session_id TEXT NOT NULL UNIQUE,
 connected_message_id TEXT NOT NULL UNIQUE REFERENCES device_module_frame(message_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=65536),
 body_digest TEXT NOT NULL,
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 UNIQUE(channel_id,device_id,device_session_id)
) STRICT;
CREATE TABLE device_baseline_sample (
 sample_id TEXT PRIMARY KEY NOT NULL,
 approval_id TEXT NOT NULL REFERENCES device_catalog_approval(approval_id),
 captured_message_id TEXT NOT NULL UNIQUE REFERENCES device_module_frame(message_id),
 sample_sequence TEXT NOT NULL CHECK(length(sample_sequence) BETWEEN 1 AND 20 AND sample_sequence NOT GLOB '*[^0-9]*' AND substr(sample_sequence,1,1)!='0'),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=65536),
 body_digest TEXT NOT NULL,
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 UNIQUE(approval_id,sample_sequence)
) STRICT;
CREATE TRIGGER readonly_catalog_parent BEFORE INSERT ON device_catalog_approval WHEN NOT EXISTS (
 SELECT 1 FROM device_module_frame f JOIN device_module_channel c USING(channel_id)
 JOIN worker_runtime_binding r USING(runtime_id) JOIN service_boot b USING(service_boot_id)
 WHERE f.message_id=NEW.connected_message_id AND f.channel_id=NEW.channel_id AND f.direction='w2c' AND f.message_type='CONNECTED'
 AND json_extract(f.frame_jcs,'$.version')='device-module/2'
 AND json_extract(f.frame_jcs,'$.body.device_id')=NEW.device_id AND json_extract(f.frame_jcs,'$.body.device_session_id')=NEW.device_session_id
 AND b.state='started' AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)
) BEGIN SELECT RAISE(ABORT,'module_catalog_parent'); END;
CREATE TRIGGER device_baseline_parent BEFORE INSERT ON device_baseline_sample WHEN NOT EXISTS (
 SELECT 1 FROM device_module_frame f JOIN device_catalog_approval a ON a.approval_id=NEW.approval_id
 JOIN device_module_channel c ON c.channel_id=a.channel_id JOIN worker_runtime_binding r USING(runtime_id) JOIN service_boot b USING(service_boot_id)
 WHERE f.message_id=NEW.captured_message_id AND f.channel_id=a.channel_id AND f.direction='w2c' AND f.message_type='CAPTURED'
 AND json_extract(f.frame_jcs,'$.body.device_id')=a.device_id AND json_extract(f.frame_jcs,'$.body.device_session_id')=a.device_session_id
 AND json_extract(f.frame_jcs,'$.body.value.sample_sequence')=NEW.sample_sequence
 AND b.state='started' AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)
 AND NOT EXISTS(SELECT 1 FROM device_module_frame d WHERE d.channel_id=a.channel_id AND d.message_type='DISCONNECTED' AND json_extract(d.frame_jcs,'$.body.device_session_id')=a.device_session_id)
) BEGIN SELECT RAISE(ABORT,'module_baseline_parent'); END;
CREATE TRIGGER readonly_catalog_no_update BEFORE UPDATE ON device_catalog_approval BEGIN SELECT RAISE(ABORT,'immutable_device_catalog'); END;
CREATE TRIGGER readonly_catalog_no_delete BEFORE DELETE ON device_catalog_approval BEGIN SELECT RAISE(ABORT,'immutable_device_catalog'); END;
CREATE TRIGGER device_baseline_no_update BEFORE UPDATE ON device_baseline_sample BEGIN SELECT RAISE(ABORT,'immutable_device_baseline'); END;
CREATE TRIGGER device_baseline_no_delete BEFORE DELETE ON device_baseline_sample BEGIN SELECT RAISE(ABORT,'immutable_device_baseline'); END;
