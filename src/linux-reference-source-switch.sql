DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER extension_owner_binding;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v111 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '111'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v111 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '111', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v111 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v111 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 111),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v111 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v111 RENAME TO schema_migration;
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

-- 保留原运行绑定及其依赖，同时为 Linux 增加精确的绑定格式。

DROP TRIGGER time_provider_source_recovery_parent;
CREATE TRIGGER time_provider_source_recovery_parent BEFORE INSERT ON time_provider_source_recovery
WHEN NOT EXISTS (
  SELECT 1 FROM time_provider_poll_reservation p JOIN time_provider_runtime_binding old USING(service_boot_id)
  JOIN time_provider_runtime_binding current ON current.service_boot_id=NEW.receiver_boot_id
  JOIN service_boot b ON b.service_boot_id=current.service_boot_id
  WHERE p.poll_id=NEW.predecessor_poll_id
    AND (
      (json_type(NEW.body_jcs,'$.transition') IS NULL AND p.source_digest=NEW.source_digest
        AND p.rowid=(SELECT max(x.rowid) FROM time_provider_poll_reservation x WHERE x.source_digest=NEW.source_digest))
      OR (json_type(NEW.body_jcs,'$.transition') IS 'object' AND p.source_digest<>NEW.source_digest
        AND json_extract(old.body_jcs,'$.format') IS 'leafseamer-time-provider-runtime-binding/2'
        AND json_extract(current.body_jcs,'$.format') IS 'leafseamer-time-provider-runtime-binding/2'
        AND json_extract(NEW.body_jcs,'$.observation.record.format') IS 'leafseamer-linux-reference-retired/1'
        AND json_extract(NEW.body_jcs,'$.transition.prior_source_digest') IS p.source_digest
        AND json_extract(NEW.body_jcs,'$.transition.source_slot') IS p.source_slot
        AND json_extract(NEW.body_jcs,'$.transition.authorization.source_slot') IS p.source_slot
        AND json_extract(NEW.body_jcs,'$.transition.authorization.source_digest') IS NEW.source_digest
        AND p.rowid=(SELECT max(x.rowid) FROM time_provider_poll_reservation x
          WHERE x.source_slot=p.source_slot OR x.source_digest=NEW.source_digest)))
    AND p.service_boot_id<>NEW.receiver_boot_id AND b.state='started' AND b.rowid=(SELECT max(rowid) FROM service_boot)
    AND json_extract(NEW.body_jcs,'$.predecessor_digest') IS p.body_digest
    AND json_extract(NEW.body_jcs,'$.old_runtime_digest') IS old.body_digest
    AND json_extract(NEW.body_jcs,'$.observation.record.launch_intent.launch_id') IS old.launch_id
    AND json_extract(NEW.body_jcs,'$.observation.record.admission_receipt.receipt_id') IS old.receipt_id
    AND json_extract(NEW.body_jcs,'$.observation.record.core_receipt_id') IS json_extract(old.body_jcs,'$.core_receipt_id')
    AND json_extract(NEW.body_jcs,'$.observation.receiving_domain_ref.clock_domain_id') IS json_extract(current.body_jcs,'$.clock_domain_descriptor.clock_domain_id')
    AND json_extract(NEW.body_jcs,'$.observation.receiving_domain_ref.descriptor_digest') IS json_extract(current.body_jcs,'$.clock_domain_descriptor.descriptor_digest')
    AND (NEW.wait_until_tick IS NULL OR (json_type(p.body_jcs,'$.authorization.minimum_poll_interval_ns') IS 'text'
      AND (NOT EXISTS (SELECT 1 FROM time_provider_poll_attempt a WHERE a.poll_id=p.poll_id)
        OR EXISTS (SELECT 1 FROM time_provider_capture c WHERE c.poll_id=p.poll_id)
        OR EXISTS (SELECT 1 FROM time_provider_poll_control z WHERE z.poll_id=p.poll_id AND z.next_allowed_tick IS NOT NULL)))))
BEGIN SELECT RAISE(ABORT,'time_provider_source_recovery_parent'); END;

DROP TRIGGER time_provider_poll_runtime;
CREATE TRIGGER time_provider_poll_runtime BEFORE INSERT ON time_provider_poll_reservation
WHEN NOT EXISTS (SELECT 1 FROM time_provider_runtime_binding r JOIN service_boot b USING(service_boot_id)
  JOIN authentication_clock_acquisition a ON a.id=NEW.acquisition_id AND a.service_boot_id=r.service_boot_id
  WHERE r.service_boot_id=NEW.service_boot_id AND b.state='started'
    AND b.rowid=(SELECT max(rowid) FROM service_boot)
    AND a.digest=json_extract(NEW.body_jcs,'$.acquisition_ref.digest')
    AND r.body_digest=json_extract(NEW.body_jcs,'$.runtime_digest'))
 OR json_type(NEW.body_jcs,'$.effective_poll_interval_ns') IS NOT 'text'
 OR substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.effective_poll_interval_ns'),-20)
    <substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.authorization.minimum_poll_interval_ns'),-20)
 OR EXISTS (SELECT 1 FROM time_provider_poll_control c WHERE c.source_digest=NEW.source_digest
    AND (c.next_allowed_tick IS NULL OR substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.effective_poll_interval_ns'),-20)<c.wait_ns))
 OR EXISTS (SELECT 1 FROM time_provider_poll_reservation p JOIN time_provider_runtime_binding r ON r.service_boot_id=NEW.service_boot_id
    WHERE (json_extract(r.body_jcs,'$.format') IS NOT 'leafseamer-time-provider-runtime-binding/2'
          AND p.source_slot=NEW.source_slot AND p.source_digest<>NEW.source_digest)
       OR (json_extract(r.body_jcs,'$.format') IS 'leafseamer-time-provider-runtime-binding/2'
          AND p.source_digest=NEW.source_digest AND p.source_slot<>NEW.source_slot))
 OR EXISTS (SELECT 1 FROM time_provider_poll_reservation p LEFT JOIN time_provider_poll_release x USING(poll_id)
   LEFT JOIN time_provider_control_release z USING(poll_id)
   LEFT JOIN time_provider_source_recovery q ON q.predecessor_poll_id=p.poll_id AND q.receiver_boot_id=NEW.service_boot_id
     AND q.source_digest=NEW.source_digest
   JOIN time_provider_runtime_binding r ON r.service_boot_id=NEW.service_boot_id
   WHERE p.rowid=(SELECT max(last.rowid) FROM time_provider_poll_reservation last WHERE last.source_digest=NEW.source_digest
     OR (json_extract(r.body_jcs,'$.format') IS 'leafseamer-time-provider-runtime-binding/2' AND last.source_slot=NEW.source_slot))
     AND ((p.service_boot_id=NEW.service_boot_id AND (p.source_digest<>NEW.source_digest
        OR coalesce(x.next_allowed_tick,z.next_allowed_tick) IS NULL OR NEW.issued_tick<coalesce(x.next_allowed_tick,z.next_allowed_tick)))
       OR (p.service_boot_id<>NEW.service_boot_id AND (q.wait_until_tick IS NULL OR NEW.issued_tick<q.wait_until_tick
         OR (p.source_digest<>NEW.source_digest AND
           (json_extract(q.body_jcs,'$.transition.authorization') IS NOT json_extract(NEW.body_jcs,'$.authorization')
            OR json_extract(q.body_jcs,'$.transition.source_slot') IS NOT NEW.source_slot))))))
BEGIN SELECT RAISE(ABORT,'time_provider_poll_runtime_or_source'); END;
