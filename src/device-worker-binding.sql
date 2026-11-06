DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v46 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '46'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v46 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '46', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v46 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v46 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46')),
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
    OR (from_revision = '45' AND to_revision = '46' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v46 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v46 RENAME TO schema_migration;
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

DROP TRIGGER device_baseline_parent;
DROP TRIGGER device_execution_binding_parent;
DROP TRIGGER device_module_frame_commit_no_delete;
DROP TRIGGER device_module_frame_commit_no_update;
DROP TRIGGER device_module_frame_no_delete;
DROP TRIGGER device_module_frame_no_update;
DROP TRIGGER device_module_frame_parent;
DROP TRIGGER readonly_catalog_parent;
CREATE TABLE device_module_frame_v46 (
 channel_id TEXT NOT NULL REFERENCES device_module_channel(channel_id),
 direction TEXT NOT NULL CHECK(direction IN('c2w','w2c')),
 sequence TEXT NOT NULL CHECK(length(sequence) BETWEEN 1 AND 20 AND sequence NOT GLOB '*[^0-9]*' AND substr(sequence,1,1)!='0'),
 message_id TEXT NOT NULL UNIQUE,
 reply_to TEXT REFERENCES device_module_frame(message_id),
 message_type TEXT NOT NULL CHECK(message_type IN('LOAD','LOADED','CONNECT','CONNECTED','CAPTURE','CAPTURED','DISCONNECT','DISCONNECTED','BIND_EXECUTION','EXECUTION_BOUND')),
 frame_jcs TEXT NOT NULL CHECK(json_valid(frame_jcs) AND length(CAST(frame_jcs AS BLOB))<=1048576),
 frame_digest TEXT NOT NULL,
 transaction_id TEXT NOT NULL UNIQUE,
 PRIMARY KEY(channel_id,direction,sequence),
 UNIQUE(transaction_id,message_id),
 CHECK((direction='c2w' AND reply_to IS NULL) OR (direction='w2c' AND reply_to IS NOT NULL)),
 FOREIGN KEY(transaction_id,message_id) REFERENCES device_module_frame_commit(transaction_id,message_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO device_module_frame_v46 SELECT * FROM device_module_frame;
DROP TABLE device_module_frame;
ALTER TABLE device_module_frame_v46 RENAME TO device_module_frame;
CREATE TRIGGER device_baseline_parent BEFORE INSERT ON device_baseline_sample WHEN NOT EXISTS (
 SELECT 1 FROM device_module_frame f JOIN device_catalog_approval a ON a.approval_id=NEW.approval_id
 JOIN device_module_channel c ON c.channel_id=a.channel_id JOIN worker_runtime_binding r USING(runtime_id) JOIN service_boot b USING(service_boot_id)
 WHERE f.message_id=NEW.captured_message_id AND f.channel_id=a.channel_id AND f.direction='w2c' AND f.message_type='CAPTURED'
 AND json_extract(f.frame_jcs,'$.body.device_id')=a.device_id AND json_extract(f.frame_jcs,'$.body.device_session_id')=a.device_session_id
 AND json_extract(f.frame_jcs,'$.body.value.sample_sequence')=NEW.sample_sequence
 AND b.state='started' AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)
 AND NOT EXISTS(SELECT 1 FROM device_module_frame d WHERE d.channel_id=a.channel_id AND d.message_type='DISCONNECTED' AND json_extract(d.frame_jcs,'$.body.device_session_id')=a.device_session_id)
) BEGIN SELECT RAISE(ABORT,'module_baseline_parent'); END;
CREATE TRIGGER device_execution_binding_parent BEFORE INSERT ON device_execution_binding WHEN NOT EXISTS(
 SELECT 1 FROM execution_session s JOIN device_catalog_approval a ON a.approval_id=NEW.catalog_approval_id
 JOIN device_module_channel c ON c.channel_id=a.channel_id AND c.runtime_id=s.runtime_id
 JOIN device_baseline_sample b ON b.sample_id=NEW.baseline_sample_id AND b.approval_id=a.approval_id
 JOIN service_boot boot ON boot.service_boot_id=s.service_boot_id
 WHERE s.ipc_session_id=NEW.ipc_session_id AND boot.state='started'
 AND NOT EXISTS(SELECT 1 FROM execution_session_end e WHERE e.ipc_session_id=s.ipc_session_id)
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=s.runtime_id)
 AND NOT EXISTS(SELECT 1 FROM device_module_frame f WHERE f.channel_id=a.channel_id AND f.message_type='DISCONNECTED'
 AND json_extract(f.frame_jcs,'$.body.device_session_id')=a.device_session_id)
 AND a.device_id=NEW.device_id AND a.device_session_id=NEW.device_session_id
 AND json_extract(a.body_jcs,'$.qualification.qualification')='fixed_memory_control_catalog/1'
 AND json_extract(NEW.body_jcs,'$.format')='leafseamer-device-execution-binding/1'
 AND json_extract(NEW.body_jcs,'$.binding_id')=NEW.binding_id
 AND json_extract(NEW.body_jcs,'$.state')='bound_closed'
 AND json_extract(NEW.body_jcs,'$.write_eligible')=0
 AND json_extract(NEW.body_jcs,'$.catalog_approval_ref.id')=a.approval_id
 AND json_extract(NEW.body_jcs,'$.catalog_approval_ref.digest')=a.body_digest
 AND json_extract(NEW.body_jcs,'$.initial_sample_ref.id')=b.sample_id
 AND json_extract(NEW.body_jcs,'$.initial_sample_ref.digest')=b.body_digest
 AND json_extract(NEW.body_jcs,'$.session_ref.id')=s.ipc_session_id
 AND json_extract(NEW.body_jcs,'$.session_ref.digest')=s.binding_digest
 AND json_extract(NEW.body_jcs,'$.binding.writer_exit_id')=NEW.writer_exit_id
 AND json_extract(NEW.body_jcs,'$.binding.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.binding.device_session_id')=NEW.device_session_id
 AND json_extract(NEW.body_jcs,'$.binding.ipc_session_id')=s.ipc_session_id
 AND json_extract(NEW.body_jcs,'$.binding.controller_boot_id')=s.controller_boot_id
 AND json_extract(NEW.body_jcs,'$.binding.worker_boot_id')=s.worker_boot_id
 AND json_extract(NEW.body_jcs,'$.binding.clock_domain_id')=s.clock_domain_id
 AND json_extract(NEW.body_jcs,'$.binding.descriptor_digest')=s.descriptor_digest
 AND json_extract(NEW.body_jcs,'$.binding.scope.authority_service_id')=boot.service_id
 AND json_extract(NEW.body_jcs,'$.binding.scope.database_instance_id')=boot.database_instance_id
 AND json_extract(NEW.body_jcs,'$.runtime_binding_ref')=json_extract(a.body_jcs,'$.runtime_binding_ref')
) BEGIN SELECT RAISE(ABORT,'device_execution_binding_parent'); END;
CREATE TRIGGER device_module_frame_commit_no_delete BEFORE DELETE ON device_module_frame_commit BEGIN SELECT RAISE(ABORT,'immutable_module_frame'); END;
CREATE TRIGGER device_module_frame_commit_no_update BEFORE UPDATE ON device_module_frame_commit BEGIN SELECT RAISE(ABORT,'immutable_module_frame'); END;
CREATE TRIGGER device_module_frame_no_delete BEFORE DELETE ON device_module_frame BEGIN SELECT RAISE(ABORT,'immutable_module_frame'); END;
CREATE TRIGGER device_module_frame_no_update BEFORE UPDATE ON device_module_frame BEGIN SELECT RAISE(ABORT,'immutable_module_frame'); END;
CREATE TRIGGER device_module_frame_parent BEFORE INSERT ON device_module_frame WHEN NOT EXISTS(
 SELECT 1 FROM device_module_channel c JOIN worker_runtime_binding r USING(runtime_id) JOIN service_boot b USING(service_boot_id)
 WHERE c.channel_id=NEW.channel_id AND b.state='started'
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)
 AND json_extract(NEW.frame_jcs,'$.binding')=c.binding_jcs
 AND json_extract(NEW.frame_jcs,'$.version')='device-module/3'
 AND json_extract(NEW.frame_jcs,'$.sequence')=NEW.sequence
 AND json_extract(NEW.frame_jcs,'$.request_id')=NEW.message_id
 AND json_extract(NEW.frame_jcs,'$.reply_to') IS NEW.reply_to
 AND json_extract(NEW.frame_jcs,'$.type')=NEW.message_type
 AND NEW.sequence=CAST((SELECT count(*)+1 FROM device_module_frame f WHERE f.channel_id=NEW.channel_id AND f.direction=NEW.direction) AS TEXT)
 AND ((NEW.direction='c2w' AND NEW.message_type IN('LOAD','CONNECT','CAPTURE','DISCONNECT','BIND_EXECUTION')) OR EXISTS(
   SELECT 1 FROM device_module_frame q WHERE q.message_id=NEW.reply_to AND q.channel_id=NEW.channel_id AND q.direction='c2w' AND q.sequence=NEW.sequence
   AND NEW.message_type=CASE q.message_type WHEN 'LOAD' THEN 'LOADED' WHEN 'CONNECT' THEN 'CONNECTED' WHEN 'CAPTURE' THEN 'CAPTURED' WHEN 'DISCONNECT' THEN 'DISCONNECTED' WHEN 'BIND_EXECUTION' THEN 'EXECUTION_BOUND' END))
) BEGIN SELECT RAISE(ABORT,'module_frame_binding'); END;
CREATE TRIGGER readonly_catalog_parent BEFORE INSERT ON device_catalog_approval WHEN NOT EXISTS (
 SELECT 1 FROM device_module_frame f JOIN device_module_channel c USING(channel_id)
 JOIN worker_runtime_binding r USING(runtime_id) JOIN service_boot b USING(service_boot_id)
 WHERE f.message_id=NEW.connected_message_id AND f.channel_id=NEW.channel_id AND f.direction='w2c' AND f.message_type='CONNECTED'
 AND json_extract(f.frame_jcs,'$.version')='device-module/3'
 AND json_extract(f.frame_jcs,'$.body.device_id')=NEW.device_id AND json_extract(f.frame_jcs,'$.body.device_session_id')=NEW.device_session_id
 AND b.state='started' AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)
) BEGIN SELECT RAISE(ABORT,'module_catalog_parent'); END;
