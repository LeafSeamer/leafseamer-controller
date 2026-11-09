import fs from 'node:fs';
import canonicalize from 'canonicalize';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import {identityStore} from './identity-store.mjs';
import {authenticationClockStore} from './auth-clock-store.mjs';
import {registerDevice} from './device-registry-store.mjs';
import {sessionStore} from './session-store.mjs';
import {configureVirtualDevice} from './worker-dependencies.mjs';
import {workerLaunchStore} from './worker-launch-store.mjs';
import {extensionInstallationStore} from './extension-installation-store.mjs';
import {initializeLocalPermissions, localPermissionStore} from './local-permission-store.mjs';

const sql = fs.readFileSync(new URL('./storage.sql', import.meta.url), 'utf8');
const scriptDigest = 'sha256:' + crypto.createHash('sha256').update(sql).digest('hex');
const identitySql = fs.readFileSync(new URL('./identity.sql', import.meta.url), 'utf8');
const identityDigest = 'sha256:' + crypto.createHash('sha256').update(identitySql).digest('hex');
const clockSql = fs.readFileSync(new URL('./clock.sql', import.meta.url), 'utf8');
const clockDigest = 'sha256:' + crypto.createHash('sha256').update(clockSql).digest('hex');
const authClockSql = fs.readFileSync(new URL('./auth-clock.sql', import.meta.url), 'utf8');
const authClockDigest = 'sha256:' + crypto.createHash('sha256').update(authClockSql).digest('hex');
const sessionSql = fs.readFileSync(new URL('./session.sql', import.meta.url), 'utf8');
const sessionDigest = 'sha256:' + crypto.createHash('sha256').update(sessionSql).digest('hex');
const tokenSql = fs.readFileSync(new URL('./access-token.sql', import.meta.url), 'utf8');
const tokenDigest = 'sha256:' + crypto.createHash('sha256').update(tokenSql).digest('hex');
const permissionSql = fs.readFileSync(new URL('./local-permission.sql', import.meta.url), 'utf8');
const permissionDigest = 'sha256:' + crypto.createHash('sha256').update(permissionSql).digest('hex');
const contextSql = fs.readFileSync(new URL('./request-context.sql', import.meta.url), 'utf8');
const contextDigest = 'sha256:' + crypto.createHash('sha256').update(contextSql).digest('hex');
const admissionSql = fs.readFileSync(new URL('./command-admission.sql', import.meta.url), 'utf8');
const admissionDigest = 'sha256:' + crypto.createHash('sha256').update(admissionSql).digest('hex');
const deviceSql = fs.readFileSync(new URL('./device-registry.sql', import.meta.url), 'utf8');
const deviceDigest = 'sha256:' + crypto.createHash('sha256').update(deviceSql).digest('hex');
const runtimeSql = fs.readFileSync(new URL('./core-runtime.sql', import.meta.url), 'utf8');
const runtimeDigest = 'sha256:' + crypto.createHash('sha256').update(runtimeSql).digest('hex');
const workerSql = fs.readFileSync(new URL('./worker-launch.sql', import.meta.url), 'utf8');
const workerDigest = 'sha256:' + crypto.createHash('sha256').update(workerSql).digest('hex');
const extensionSql = fs.readFileSync(new URL('./extension-installation.sql', import.meta.url), 'utf8');
const extensionDigest = 'sha256:' + crypto.createHash('sha256').update(extensionSql).digest('hex');
const configurationSql = fs.readFileSync(new URL('./extension-configuration.sql', import.meta.url), 'utf8');
const configurationDigest = 'sha256:' + crypto.createHash('sha256').update(configurationSql).digest('hex');
const roleSql = fs.readFileSync(new URL('./extension-role.sql', import.meta.url), 'utf8');
const roleDigest = 'sha256:' + crypto.createHash('sha256').update(roleSql).digest('hex');
const reviewSql = fs.readFileSync(new URL('./extension-review.sql', import.meta.url), 'utf8');
const reviewDigest = 'sha256:' + crypto.createHash('sha256').update(reviewSql).digest('hex');
const approvalSql = fs.readFileSync(new URL('./extension-approval.sql', import.meta.url), 'utf8');
const approvalDigest = 'sha256:' + crypto.createHash('sha256').update(approvalSql).digest('hex');
const capabilitySql = fs.readFileSync(new URL('./extension-capabilities.sql', import.meta.url), 'utf8');
const capabilityDigest = 'sha256:' + crypto.createHash('sha256').update(capabilitySql).digest('hex');
const workerRuntimeSql=fs.readFileSync(new URL('./worker-runtime.sql',import.meta.url),'utf8');
const workerRuntimeDigest='sha256:'+crypto.createHash('sha256').update(workerRuntimeSql).digest('hex');
const dependencySql=fs.readFileSync(new URL('./worker-dependencies.sql',import.meta.url),'utf8');
const dependencyDigest='sha256:'+crypto.createHash('sha256').update(dependencySql).digest('hex');
const planSql=fs.readFileSync(new URL('./extension-plan.sql',import.meta.url),'utf8');
const planDigest='sha256:'+crypto.createHash('sha256').update(planSql).digest('hex');
const activationSql=fs.readFileSync(new URL('./extension-activation.sql',import.meta.url),'utf8');
const activationDigest='sha256:'+crypto.createHash('sha256').update(activationSql).digest('hex');
const authorizationSql=fs.readFileSync(new URL('./worker-authorization.sql',import.meta.url),'utf8');
const authorizationDigest='sha256:'+crypto.createHash('sha256').update(authorizationSql).digest('hex');
const moduleSql=fs.readFileSync(new URL('./device-module.sql',import.meta.url),'utf8');
const moduleDigest='sha256:'+crypto.createHash('sha256').update(moduleSql).digest('hex');
const catalogSql=fs.readFileSync(new URL('./device-catalog.sql',import.meta.url),'utf8');
const catalogDigest='sha256:'+crypto.createHash('sha256').update(catalogSql).digest('hex');
const controlSql=fs.readFileSync(new URL('./device-control.sql',import.meta.url),'utf8');
const controlDigest='sha256:'+crypto.createHash('sha256').update(controlSql).digest('hex');
const executionSql=fs.readFileSync(new URL('./device-execution.sql',import.meta.url),'utf8');
const executionDigest='sha256:'+crypto.createHash('sha256').update(executionSql).digest('hex');
const executionFramesSql=fs.readFileSync(new URL('./device-execution-frames.sql',import.meta.url),'utf8');
const executionFramesDigest='sha256:'+crypto.createHash('sha256').update(executionFramesSql).digest('hex');
const executionBindingSql=fs.readFileSync(new URL('./device-execution-binding.sql',import.meta.url),'utf8');
const executionBindingDigest='sha256:'+crypto.createHash('sha256').update(executionBindingSql).digest('hex');
const executionHandshakeSql=fs.readFileSync(new URL('./device-execution-handshake.sql',import.meta.url),'utf8');
const executionHandshakeDigest='sha256:'+crypto.createHash('sha256').update(executionHandshakeSql).digest('hex');
const executionControlSql=fs.readFileSync(new URL('./device-execution-control.sql',import.meta.url),'utf8');
const executionControlDigest='sha256:'+crypto.createHash('sha256').update(executionControlSql).digest('hex');
const controlSourceSql=fs.readFileSync(new URL('./device-control-source.sql',import.meta.url),'utf8');
const controlSourceDigest='sha256:'+crypto.createHash('sha256').update(controlSourceSql).digest('hex');
const manualAuthoritySql=fs.readFileSync(new URL('./device-manual-authority.sql',import.meta.url),'utf8');
const manualAuthorityDigest='sha256:'+crypto.createHash('sha256').update(manualAuthoritySql).digest('hex');
const deviceAuthorizationSql=fs.readFileSync(new URL('./device-authorization-state.sql',import.meta.url),'utf8');
const deviceAuthorizationDigest='sha256:'+crypto.createHash('sha256').update(deviceAuthorizationSql).digest('hex');
const coreSourceSql=fs.readFileSync(new URL('./core-runtime-source.sql',import.meta.url),'utf8');
const coreSourceDigest='sha256:'+crypto.createHash('sha256').update(coreSourceSql).digest('hex');
const serviceIdentitySql=fs.readFileSync(new URL('./service-identity.sql',import.meta.url),'utf8');
const serviceIdentityDigest='sha256:'+crypto.createHash('sha256').update(serviceIdentitySql).digest('hex');
const serviceAccessTokenSql=fs.readFileSync(new URL('./service-access-token.sql',import.meta.url),'utf8');
const serviceAccessTokenDigest='sha256:'+crypto.createHash('sha256').update(serviceAccessTokenSql).digest('hex');
const evaluatorSourceSql=fs.readFileSync(new URL('./device-evaluator-source.sql',import.meta.url),'utf8');
const evaluatorSourceDigest='sha256:'+crypto.createHash('sha256').update(evaluatorSourceSql).digest('hex');
const principalRevocationSql=fs.readFileSync(new URL('./service-principal-revocation.sql',import.meta.url),'utf8');
const principalRevocationDigest='sha256:'+crypto.createHash('sha256').update(principalRevocationSql).digest('hex');
const deviceRecoverySql=fs.readFileSync(new URL('./device-authorization-recovery.sql',import.meta.url),'utf8');
const deviceRecoveryDigest='sha256:'+crypto.createHash('sha256').update(deviceRecoverySql).digest('hex');
const deviceConsumptionSql=fs.readFileSync(new URL('./device-authorization-consumption.sql',import.meta.url),'utf8');
const deviceConsumptionDigest='sha256:'+crypto.createHash('sha256').update(deviceConsumptionSql).digest('hex');
const manualChallengeSql=fs.readFileSync(new URL('./device-manual-challenge.sql',import.meta.url),'utf8');
const manualChallengeDigest='sha256:'+crypto.createHash('sha256').update(manualChallengeSql).digest('hex');
const deviceEvidenceSql=fs.readFileSync(new URL('./device-authorization-evidence.sql',import.meta.url),'utf8');
const deviceEvidenceDigest='sha256:'+crypto.createHash('sha256').update(deviceEvidenceSql).digest('hex');
const initialResourceSql=fs.readFileSync(new URL('./device-initial-resource.sql',import.meta.url),'utf8');
const initialResourceDigest='sha256:'+crypto.createHash('sha256').update(initialResourceSql).digest('hex');
const initialOpenSql=fs.readFileSync(new URL('./device-initial-open.sql',import.meta.url),'utf8');
const initialOpenDigest='sha256:'+crypto.createHash('sha256').update(initialOpenSql).digest('hex');
const workerBindingSql=fs.readFileSync(new URL('./device-worker-binding.sql',import.meta.url),'utf8');
const workerBindingDigest='sha256:'+crypto.createHash('sha256').update(workerBindingSql).digest('hex');
const executionOpenSql=fs.readFileSync(new URL('./device-execution-open.sql',import.meta.url),'utf8');
const executionOpenDigest='sha256:'+crypto.createHash('sha256').update(executionOpenSql).digest('hex');
const initialReadySql=fs.readFileSync(new URL('./device-initial-ready.sql',import.meta.url),'utf8');
const initialReadyDigest='sha256:'+crypto.createHash('sha256').update(initialReadySql).digest('hex');
const commandRecordSql=fs.readFileSync(new URL('./command-record.sql',import.meta.url),'utf8');
const commandLifecycleSql=fs.readFileSync(new URL('./command-lifecycle.sql',import.meta.url),'utf8');
const commandLifecycleDigest='sha256:'+crypto.createHash('sha256').update(commandLifecycleSql).digest('hex');
const commandEncodingSql=fs.readFileSync(new URL('./command-encoding.sql',import.meta.url),'utf8');
const commandDispatchSql=fs.readFileSync(new URL('./command-dispatch.sql',import.meta.url),'utf8');
const commandSettlementSql=fs.readFileSync(new URL('./command-settlement.sql',import.meta.url),'utf8');
const commandPreparationCleanupSql=fs.readFileSync(new URL('./command-preparation-cleanup.sql',import.meta.url),'utf8');
const resourceSuccessorSql=fs.readFileSync(new URL('./device-resource-successor.sql',import.meta.url),'utf8');
const resourceSuccessorDigest='sha256:'+crypto.createHash('sha256').update(resourceSuccessorSql).digest('hex');
const commandPreparationCleanupDigest='sha256:'+crypto.createHash('sha256').update(commandPreparationCleanupSql).digest('hex');
const commandSettlementDigest='sha256:'+crypto.createHash('sha256').update(commandSettlementSql).digest('hex');
const commandDispatchDigest='sha256:'+crypto.createHash('sha256').update(commandDispatchSql).digest('hex');
const commandGuardSql=fs.readFileSync(new URL('./command-guard.sql',import.meta.url),'utf8');
const commandGuardDigest='sha256:'+crypto.createHash('sha256').update(commandGuardSql).digest('hex');
const commandFinalAdmissionSql=fs.readFileSync(new URL('./command-final-admission.sql',import.meta.url),'utf8');
const commandFinalAdmissionDigest='sha256:'+crypto.createHash('sha256').update(commandFinalAdmissionSql).digest('hex');
const commandEncodingDigest='sha256:'+crypto.createHash('sha256').update(commandEncodingSql).digest('hex');
const commandRecordDigest='sha256:'+crypto.createHash('sha256').update(commandRecordSql).digest('hex');
const applicationId = 0x4c53434c;
const engine = Object.freeze({version: '3.53.4', source: '2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc'});
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export class StorageError extends Error {
  constructor(code) { super(code); this.name = 'StorageError'; this.code = code; }
}
function require(ok, code) { if (!ok) throw new StorageError(code); }
function rows(db, sqlText) {
  const stmt = db.prepare(sqlText), names = stmt.columns().map(column => column.name);
  return stmt.raw().all().map(values => Object.fromEntries(names.map((name, index) => [name, values[index]])));
}
function pragma(db, source) {
  const stmt = db.prepare('PRAGMA ' + source);
  if (stmt.reader) return stmt.raw().get()?.[0];
  stmt.run();
}
function filename(dataDir) {
  require(typeof dataDir === 'string' && path.isAbsolute(dataDir), 'absolute_data_directory_required');
  return path.join(path.resolve(dataDir), 'controller.sqlite');
}
function open(file) {
  const db = new Database(file, {fileMustExist: true, timeout: 0});
  try {
    const actual = rows(db, 'SELECT sqlite_version() AS version, sqlite_source_id() AS source')[0];
    require(actual.version === engine.version && actual.source === engine.source, 'sqlite_engine_mismatch');
    pragma(db, 'foreign_keys = ON'); pragma(db, 'trusted_schema = OFF');
    pragma(db, 'recursive_triggers = ON');
    pragma(db, 'locking_mode = EXCLUSIVE');
    pragma(db, 'wal_autocheckpoint = 0');
    require(pragma(db, 'foreign_keys') === 1, 'foreign_keys_unavailable');
    require(pragma(db, 'recursive_triggers') === 1, 'recursive_triggers_unavailable');
    require(pragma(db, 'locking_mode') === 'exclusive', 'exclusive_mode_unavailable');
    require(pragma(db, 'wal_autocheckpoint') === 0, 'checkpoint_mode_unavailable');
    return db;
  } catch (error) { db.close(); throw error; }
}
function identity(db, revision = '1') {
  const records = rows(db, 'SELECT * FROM service_state');
  require(records.length === 1 && records[0].singleton === 1 && records[0].authority === 'controller', 'service_identity_invalid');
  const row = records[0];
  for (const field of ['service_id', 'database_instance_id', 'control_epoch', 'request_epoch']) require(uuid.test(row[field]), 'service_identity_invalid');
  require(row.schema_revision === revision && row.maintenance_state === 'protected' && row.state_revision === '0', 'service_state_invalid');
  return Object.freeze({...row});
}
export function initializeStorage(dataDir) {
  const file = filename(dataDir);
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
  let handle;
  try { handle = fs.openSync(file, 'wx', 0o600); }
  catch (error) { throw new StorageError(error.code === 'EEXIST' ? 'database_already_exists' : 'database_create_failed'); }
  fs.closeSync(handle);
  let db;
  try {
    db = open(file);
    require(pragma(db, 'journal_mode = WAL') === 'wal', 'wal_unavailable');
    pragma(db, 'synchronous = FULL');
    db.transaction(() => {
      db.exec(sql);
      pragma(db, 'application_id = ' + applicationId); pragma(db, 'user_version = 1');
      db.prepare("INSERT INTO service_state VALUES (1, 'controller', ?, ?, ?, ?, '1', 'protected', '0')")
        .run(crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID());
      db.prepare("INSERT INTO schema_migration VALUES (?, '0', '1', ?, NULL, 'committed', ?)")
        .run(crypto.randomUUID(), scriptDigest, crypto.randomUUID());
    }).immediate();
    return identity(db);
  } finally { db?.close(); }
}
function validateStorage(db) {
  const revision = pragma(db, 'user_version');
  require(pragma(db, 'application_id') === applicationId && [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57].includes(revision), 'database_version_mismatch');
  require(pragma(db, 'journal_mode') === 'wal', 'journal_mode_mismatch');
  pragma(db, 'synchronous = FULL');
  require(pragma(db, 'synchronous') === 2, 'synchronous_mismatch');
  require(pragma(db, 'quick_check') === 'ok' && rows(db, 'PRAGMA foreign_key_check').length === 0, 'database_integrity');
  const migrations = rows(db, 'SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)');
  require(migrations.length === revision && migrations[0].from_revision === '0' && migrations[0].to_revision === '1' && migrations[0].state === 'committed' && migrations[0].script_digest === scriptDigest, 'migration_mismatch');
  for (let i = 1; i < revision; i++) require(migrations[i].from_revision === String(i) && migrations[i].to_revision === String(i + 1) && migrations[i].state === 'committed' && migrations[i].script_digest === [scriptDigest, identityDigest, clockDigest, authClockDigest, sessionDigest, tokenDigest, permissionDigest, contextDigest, admissionDigest, deviceDigest, runtimeDigest, workerDigest, extensionDigest, configurationDigest, roleDigest, reviewDigest, approvalDigest, capabilityDigest, workerRuntimeDigest, dependencyDigest, planDigest, activationDigest, authorizationDigest, moduleDigest, catalogDigest, controlDigest, executionDigest, executionFramesDigest, executionBindingDigest, executionHandshakeDigest, executionControlDigest, controlSourceDigest, manualAuthorityDigest, deviceAuthorizationDigest, coreSourceDigest, serviceIdentityDigest, serviceAccessTokenDigest, evaluatorSourceDigest, principalRevocationDigest, deviceRecoveryDigest, deviceConsumptionDigest, manualChallengeDigest, deviceEvidenceDigest, initialResourceDigest, initialOpenDigest, workerBindingDigest, executionOpenDigest, initialReadyDigest, commandRecordDigest, commandLifecycleDigest, commandEncodingDigest, commandFinalAdmissionDigest, commandGuardDigest, commandDispatchDigest, commandSettlementDigest, commandPreparationCleanupDigest, resourceSuccessorDigest][i] && /^sha256:[0-9a-f]{64}$/.test(migrations[i].backup_ref), 'migration_mismatch');
  return identity(db, String(revision));
}
export async function migrateStorage(dataDir, targetRevision = 57) {
  require([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57].includes(targetRevision), 'migration_target');
  const file = filename(dataDir);
  let db;
  try {
    db = open(file);
    const state = validateStorage(db);
    const current = Number(state.schema_revision);
    require(targetRevision >= current, 'migration_downgrade');
    if (current === targetRevision) return {schema_revision: String(current), changed: false};
    const steps = [];
    for (let next = current + 1; next <= targetRevision; next++) {
      const backupName = 'controller-before-v' + next + '-' + crypto.randomUUID() + '.sqlite';
      const backupPath = path.join(path.dirname(file), backupName);
      const fd = fs.openSync(backupPath, 'wx', 0o600); fs.closeSync(fd);
      await db.backup(backupPath);
      const backupRef = 'sha256:' + crypto.createHash('sha256').update(fs.readFileSync(backupPath)).digest('hex');
      pragma(db, 'foreign_keys = OFF');
      require(pragma(db, 'foreign_keys') === 0, 'migration_setup_failed');
      db.transaction(() => {
        db.exec([identitySql, clockSql, authClockSql, sessionSql, tokenSql, permissionSql, contextSql, admissionSql, deviceSql, runtimeSql, workerSql, extensionSql, configurationSql, roleSql, reviewSql, approvalSql, capabilitySql, workerRuntimeSql, dependencySql, planSql, activationSql, authorizationSql, moduleSql, catalogSql, controlSql, executionSql, executionFramesSql, executionBindingSql, executionHandshakeSql, executionControlSql, controlSourceSql, manualAuthoritySql, deviceAuthorizationSql, coreSourceSql, serviceIdentitySql, serviceAccessTokenSql, evaluatorSourceSql, principalRevocationSql, deviceRecoverySql, deviceConsumptionSql, manualChallengeSql, deviceEvidenceSql, initialResourceSql, initialOpenSql, workerBindingSql, executionOpenSql, initialReadySql, commandRecordSql, commandLifecycleSql, commandEncodingSql, commandFinalAdmissionSql, commandGuardSql, commandDispatchSql, commandSettlementSql, commandPreparationCleanupSql, resourceSuccessorSql][next - 2]);
        if (next === 7) initializeLocalPermissions(db, state);
        db.prepare("INSERT INTO schema_migration VALUES (?, ?, ?, ?, ?, 'committed', ?)")
          .run(crypto.randomUUID(), String(next - 1), String(next), [identityDigest, clockDigest, authClockDigest, sessionDigest, tokenDigest, permissionDigest, contextDigest, admissionDigest, deviceDigest, runtimeDigest, workerDigest, extensionDigest, configurationDigest, roleDigest, reviewDigest, approvalDigest, capabilityDigest, workerRuntimeDigest, dependencyDigest, planDigest, activationDigest, authorizationDigest, moduleDigest, catalogDigest, controlDigest, executionDigest, executionFramesDigest, executionBindingDigest, executionHandshakeDigest, executionControlDigest, controlSourceDigest, manualAuthorityDigest, deviceAuthorizationDigest, coreSourceDigest, serviceIdentityDigest, serviceAccessTokenDigest, evaluatorSourceDigest, principalRevocationDigest, deviceRecoveryDigest, deviceConsumptionDigest, manualChallengeDigest, deviceEvidenceDigest, initialResourceDigest, initialOpenDigest, workerBindingDigest, executionOpenDigest, initialReadyDigest, commandRecordDigest, commandLifecycleDigest, commandEncodingDigest, commandFinalAdmissionDigest, commandGuardDigest, commandDispatchDigest, commandSettlementDigest, commandPreparationCleanupDigest, resourceSuccessorDigest][next - 2], backupRef, crypto.randomUUID());
        pragma(db, 'user_version = ' + next);
        require(rows(db, 'PRAGMA foreign_key_check').length === 0, 'migration_integrity');
      }).immediate();
      pragma(db, 'foreign_keys = ON');
      require(pragma(db, 'foreign_keys') === 1, 'foreign_keys_unavailable');
      validateStorage(db);
      steps.push({schema_revision: String(next), backup_file: backupName, backup_ref: backupRef});
    }
    return {...steps.at(-1), changed: true, steps};
  } catch (error) {
    if (error instanceof StorageError) throw error;
    throw new StorageError(error.code === 'SQLITE_BUSY' ? 'database_in_use' : 'migration_failed');
  } finally { db?.close(); }
}
function clockJournal(db, bootId) {
  let samples = 0;
  return Object.freeze({
    current() {
      const row = db.prepare('SELECT state, reason FROM authentication_clock_diagnostic WHERE service_boot_id = ?').raw().get(bootId);
      require(row !== undefined, 'clock_journal_missing'); return {state: row[0], reason: row[1]};
    },
    sample(capture, artifactDigest) {
      const body = Buffer.from(JSON.stringify(capture));
      require(body.length <= 8192 && /^sha256:[0-9a-f]{64}$/.test(artifactDigest), 'clock_journal_input');
      db.transaction(() => {
        const result = db.prepare("UPDATE authentication_clock_diagnostic SET sequence = sequence + 1, last_capture = ?, native_artifact_digest = ?, reason = 'clock_approval_missing' WHERE service_boot_id = ? AND state = 'unqualified' AND sequence < 9007199254740991")
          .run(body, artifactDigest, bootId);
        require(result.changes === 1, 'clock_journal_closed');
      }).immediate();
      // 当前只有保护态诊断写入；不把此小范围checkpoint当完整业务容量调度。
      if (++samples % 32 === 0) {
        const [busy, log, checkpointed] = db.prepare('PRAGMA wal_checkpoint(PASSIVE)').raw().get();
        require(busy === 0 && log === checkpointed, 'clock_checkpoint_incomplete');
      }
    },
    fault(reason) {
      require(typeof reason === 'string' && /^[a-z_]{1,80}$/.test(reason), 'clock_fault_reason');
      db.transaction(() => {
        db.prepare("UPDATE authentication_clock_diagnostic SET state = 'faulted', reason = ? WHERE service_boot_id = ? AND state = 'unqualified'").run(reason, bootId);
      }).immediate();
    }
  });
}
export function openStorage(dataDir) {
  let db;
  try {
    db = open(filename(dataDir));
    const state = validateStorage(db), bootId = crypto.randomUUID();
    db.transaction(() => {
      db.prepare("INSERT INTO service_boot VALUES (?, ?, ?, ?, NULL, 'started')")
        .run(state.service_id, state.database_instance_id, bootId, new Date().toISOString());
      if (state.schema_revision !== '1') db.prepare("UPDATE first_admin_challenge SET state = 'invalidated' WHERE state = 'pending'").run();
      if (Number(state.schema_revision) >= 3) db.prepare("INSERT INTO authentication_clock_diagnostic VALUES (?, 'unqualified', 'clock_not_sampled', 0, NULL, NULL)").run(bootId);
      if (Number(state.schema_revision) >= 8) db.prepare("UPDATE request_context SET state = 'closed', closed_reason = 'restarted' WHERE state = 'active'").run();
    }).immediate();
    if(Number(state.schema_revision)>=27)db.transaction(()=>{
      for(const row of db.prepare('SELECT s.ipc_session_id FROM execution_session s LEFT JOIN execution_session_end e USING(ipc_session_id) WHERE e.ipc_session_id IS NULL').raw().all())
        db.prepare("INSERT INTO execution_session_end VALUES(?,?,'restarted')").run(row[0],crypto.randomUUID());
    }).immediate();
    let closed = false, sessions = null, sessionClock = null, sessionAuthority = null;
    const localAuthority = Number(state.schema_revision) >= 7 ? localPermissionStore(db, state) : null;
    let createExtensionManagement,workerExtensionSource,stopWorkerContent,initialOpeningSource,commandEncodingProvider;
    const extensionInstallations=Number(state.schema_revision)>=13?extensionInstallationStore(db,state,()=>!closed,create=>{createExtensionManagement=create;},source=>{workerExtensionSource=source;},bootId):null;
    const workerLaunches=Number(state.schema_revision)>=12?workerLaunchStore(db,state,bootId,()=>!closed,workerExtensionSource,stop=>{stopWorkerContent=stop;},()=>initialOpeningSource,()=>commandEncodingProvider):null;
    return Object.freeze({identity: state, serviceBootId: bootId, engine,
      configureVirtualDevice(input){require(!closed,'storage_closed');return configureVirtualDevice(db,state,input);},
      bindCoreRuntime(binding, policy) {
        require(!closed && Number(state.schema_revision) >= 11, 'core_runtime_migration_required');
        require(binding.intent.service_id === state.service_id && policy.service_id === state.service_id &&
          policy.database_instance_id === state.database_instance_id && binding.receipt.gate_state === 'closed', 'core_runtime_scope');
        const bodies = [binding.intent, binding.descriptor, binding.receipt, policy].map(canonicalize);
        require(bodies.every(b => Buffer.byteLength(b) <= 8192), 'core_runtime_capacity');
        db.transaction(() => {
          db.prepare('INSERT INTO core_runtime_binding VALUES(?,?,?,?,?,?,?,?)').run(bootId, binding.receipt.receipt_id,
            binding.receipt.bootstrap_id, binding.receipt.member_boot_id, ...bodies);
        }).immediate();
      },
      registerDevice(input) { require(!closed && Number(state.schema_revision) >= 10, 'device_migration_required'); return registerDevice(db, state, input); },
      workerLaunches,
      extensionInstallations,
      enrollment: state.schema_revision !== '1' ? identityStore(db, bootId, localAuthority ? state : null) : null,
      clockJournal: Number(state.schema_revision) >= 3 ? clockJournal(db, bootId) : null,
      authenticationClock: Number(state.schema_revision) >= 4 ? authenticationClockStore(db, {service_id: state.service_id, service_boot_id: bootId}) : null,
      sessions(clock, authority = localAuthority) {
        require(Number(state.schema_revision) >= 5 && !closed, 'session_migration_required');
        require(clock && typeof clock.current === 'function' && (!sessionClock || sessionClock === clock), 'session_clock_binding');
        require(!sessions || sessionAuthority === authority, 'session_authority_binding');
        sessionClock = clock; sessionAuthority = authority;
        sessions ??= sessionStore(db, state.service_id, clock, authority, Number(state.schema_revision) >= 6,
          Number(state.schema_revision) >= 8 ? {service: state, bootId} : null,authority===localAuthority?createExtensionManagement:null,authority===localAuthority?workerLaunches?.controlBarrier:null,
          authority===localAuthority?workerLaunches?.commandExecutionCurrent:null,authority===localAuthority?value=>{initialOpeningSource=value;}:null,
          authority===localAuthority?value=>{commandEncodingProvider=value;}:null,authority===localAuthority?workerLaunches?.queueCommandEncoding:null); return sessions;
      },
      close() {
        if (closed) return; closed = true; stopWorkerContent?.(); sessions?.stop();
        try {
          db.transaction(() => {
            if (state.schema_revision !== '1') db.prepare("UPDATE first_admin_challenge SET state = 'invalidated' WHERE service_boot_id = ? AND state = 'pending'").run(bootId);
            db.prepare("UPDATE service_boot SET state = 'stopped', stopped_utc = ? WHERE service_boot_id = ? AND state = 'started'")
            .run(new Date().toISOString(), bootId); }).immediate();
        } finally { db.close(); }
      }});
  } catch (error) {
    if (db?.open) db.close();
    if (error instanceof StorageError) throw error;
    throw new StorageError(error.code === 'SQLITE_BUSY' ? 'database_in_use' : 'database_unavailable');
  }
}
