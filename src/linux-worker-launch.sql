DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER extension_owner_binding;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v109 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '109'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v109 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '109', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v109 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v109 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 109),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v109 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v109 RENAME TO schema_migration;
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

-- 保留完整启动准备、关联审计、依赖及占用。Linux 准备须与同代核心采用同一容纳后端。
PRAGMA legacy_alter_table=ON;

CREATE TABLE worker_launch_preparation_v109 (
  launch_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  preparation_id TEXT NOT NULL UNIQUE,
  transaction_id TEXT NOT NULL UNIQUE,
  service_boot_id TEXT NOT NULL REFERENCES core_runtime_binding(service_boot_id),
  supervisor_instance_id TEXT NOT NULL,
  runtime_generation TEXT NOT NULL,
  member_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  group_generation TEXT NOT NULL,
  intent_digest TEXT NOT NULL CHECK(length(intent_digest)=71),
  intent_jcs TEXT NOT NULL CHECK(length(CAST(intent_jcs AS BLOB)) BETWEEN 1 AND 262144 AND json_valid(intent_jcs)),
  state TEXT NOT NULL CHECK(state='prepared'),
  dependency_launch_id TEXT REFERENCES worker_launch_dependencies(launch_id) DEFERRABLE INITIALLY DEFERRED,
  activation_operation_id TEXT REFERENCES extension_activation(operation_id),
  UNIQUE(supervisor_instance_id,member_id),
  UNIQUE(supervisor_instance_id,group_id,group_generation),
  UNIQUE(transaction_id,launch_id,preparation_id,intent_digest),
  FOREIGN KEY(transaction_id,launch_id,preparation_id,intent_digest)
    REFERENCES worker_launch_preparation_commit(transaction_id,launch_id,preparation_id,intent_digest) DEFERRABLE INITIALLY DEFERRED,
  CHECK(json_extract(intent_jcs,'$.launch_id') IS launch_id AND json_extract(intent_jcs,'$.role') IS 'worker'
    AND json_extract(intent_jcs,'$.supervisor_instance_id') IS supervisor_instance_id
    AND json_extract(intent_jcs,'$.runtime_generation') IS runtime_generation AND json_extract(intent_jcs,'$.member_id') IS member_id
    AND json_extract(intent_jcs,'$.containment_ref.group_id') IS group_id
    AND json_extract(intent_jcs,'$.containment_ref.generation') IS group_generation
    AND (json_extract(intent_jcs,'$.containment_ref.backend') IS 'windows_job'
      OR (json_extract(intent_jcs,'$.containment_ref.backend') IS 'linux_cgroup_v2' AND group_generation IS runtime_generation))
    AND json_extract(intent_jcs,'$.object_scope.kind') IS 'devices'
    AND coalesce(json_array_length(intent_jcs,'$.object_scope.device_ids'),0) BETWEEN 1 AND 64)
) STRICT;
INSERT INTO worker_launch_preparation_v109 (
  launch_id,preparation_id,transaction_id,service_boot_id,supervisor_instance_id,runtime_generation,member_id,
  group_id,group_generation,intent_digest,intent_jcs,state,dependency_launch_id,activation_operation_id
) SELECT
  launch_id,preparation_id,transaction_id,service_boot_id,supervisor_instance_id,runtime_generation,member_id,
  group_id,group_generation,intent_digest,intent_jcs,state,dependency_launch_id,activation_operation_id
FROM worker_launch_preparation;
DROP TABLE worker_launch_preparation;
ALTER TABLE worker_launch_preparation_v109 RENAME TO worker_launch_preparation;

PRAGMA legacy_alter_table=OFF;

CREATE INDEX worker_launch_activation_history ON worker_launch_preparation(activation_operation_id);

CREATE TRIGGER worker_launch_parent BEFORE INSERT ON worker_launch_preparation
WHEN NOT EXISTS (
  SELECT 1 FROM core_runtime_binding r JOIN service_boot b USING(service_boot_id)
  WHERE r.service_boot_id=NEW.service_boot_id AND b.state='started'
    AND b.service_id IS json_extract(NEW.intent_jcs,'$.service_id')
    AND json_extract(r.descriptor_jcs,'$.supervisor_instance_id') IS NEW.supervisor_instance_id
    AND json_extract(r.descriptor_jcs,'$.runtime_generation') IS NEW.runtime_generation
    AND json_extract(r.intent_jcs,'$.artifact_manifest_ref') IS json_extract(NEW.intent_jcs,'$.artifact_manifest_ref')
    AND json_extract(r.policy_jcs,'$.policy_revision') IS json_extract(NEW.intent_jcs,'$.policy_revision')
    AND json_extract(r.descriptor_jcs,'$.platform_profile_id') IS json_extract(NEW.intent_jcs,'$.extension_binding.platform_profile_ref.object_id')
    AND json_extract(r.descriptor_jcs,'$.platform_profile_revision') IS json_extract(NEW.intent_jcs,'$.extension_binding.platform_profile_ref.revision')
    AND json_extract(r.intent_jcs,'$.member_id') IS NOT NEW.member_id
    AND json_extract(r.intent_jcs,'$.launch_id') IS NOT NEW.launch_id
    AND json_extract(r.intent_jcs,'$.containment_ref.backend') IS json_extract(NEW.intent_jcs,'$.containment_ref.backend')
    AND json_extract(r.intent_jcs,'$.containment_ref.group_id') IS NOT NEW.group_id)
BEGIN SELECT RAISE(ABORT,'worker_launch_parent'); END;

CREATE TRIGGER worker_launch_no_update BEFORE UPDATE ON worker_launch_preparation
BEGIN SELECT RAISE(ABORT,'immutable_worker_launch'); END;

CREATE TRIGGER worker_launch_no_delete BEFORE DELETE ON worker_launch_preparation
BEGIN SELECT RAISE(ABORT,'worker_launch_history_required'); END;

CREATE TRIGGER worker_launch_dependency_required BEFORE INSERT ON worker_launch_preparation
WHEN NEW.dependency_launch_id IS NOT NEW.launch_id BEGIN SELECT RAISE(ABORT,'worker_launch_dependencies_required'); END;

CREATE TRIGGER dependency_generation_worker_launch_preparation_insert AFTER INSERT ON worker_launch_preparation
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER worker_launch_activation_required BEFORE INSERT ON worker_launch_preparation
WHEN NEW.activation_operation_id IS NULL OR NOT EXISTS(SELECT 1 FROM extension_activation a
 WHERE a.operation_id=NEW.activation_operation_id
 AND a.installation_id IS json_extract(NEW.intent_jcs,'$.extension_binding.installation_ref.object_id')
 AND a.approval_id IS json_extract(NEW.intent_jcs,'$.extension_binding.approval_ref.object_id')
 AND (a.service_boot_id=NEW.service_boot_id OR EXISTS(
  SELECT 1 FROM obs_worker_launch_replacement x JOIN worker_launch_preparation p ON p.launch_id=x.previous_launch_id
  JOIN control_barrier_evidence e ON e.operation_id=x.control_operation_id
  WHERE x.launch_id=NEW.launch_id AND x.activation_operation_id=a.operation_id
  AND json_extract(x.body_jcs,'$.launch_intent_digest')=NEW.intent_digest
  AND json_extract(e.body_jcs,'$.service_boot_id')=NEW.service_boot_id
  AND json_remove(p.intent_jcs,'$.launch_id','$.member_id','$.containment_ref.group_id','$.supervisor_instance_id','$.runtime_generation')=
      json_remove(NEW.intent_jcs,'$.launch_id','$.member_id','$.containment_ref.group_id','$.supervisor_instance_id','$.runtime_generation')
  AND (p.service_boot_id<>NEW.service_boot_id OR
   (p.supervisor_instance_id=NEW.supervisor_instance_id AND p.runtime_generation=NEW.runtime_generation))
 )))
BEGIN SELECT RAISE(ABORT,'worker_launch_activation_required'); END;

CREATE TRIGGER worker_launch_activation_replacement BEFORE INSERT ON worker_launch_preparation
WHEN EXISTS(SELECT 1 FROM worker_launch_preparation p WHERE p.activation_operation_id=NEW.activation_operation_id)
AND NOT EXISTS(SELECT 1 FROM obs_worker_launch_replacement x WHERE x.launch_id=NEW.launch_id
 AND x.activation_operation_id=NEW.activation_operation_id
 AND json_extract(x.body_jcs,'$.launch_intent_digest')=NEW.intent_digest)
BEGIN SELECT RAISE(ABORT,'worker_launch_activation_replacement'); END;
