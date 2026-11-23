import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {canonical, digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {obsDeviceCatalog, obsDeviceIdentity} from './obs-device-module.mjs';
import {readRegisteredObsResource} from './obs-resource.mjs';

const bytes = name => readFileSync(new URL('./' + name, import.meta.url));
const hash = name => 'sha256:' + createHash('sha256').update(bytes(name)).digest('hex');
const same = (left, right) => canonical(left) === canonical(right);
const need = (ok, reason) => { if (!ok) throw new IdentityError('obs_worker_' + reason); };
const template = JSON.parse(bytes('obs-module-capability.json'));
const templateDigest = hash('obs-module-capability.json');
const catalog = obsDeviceCatalog();
need(same(template.state_schema, catalog.state_schema) && template.actions.length === 0 && template.triggers.length === 0, 'capability');

export const obsModuleDefinition = Object.freeze({
  module: hash('obs-device-module.mjs'), policy: hash('obs-module-policy.json'),
  identity: obsDeviceIdentity, catalog, template, qualification: 'fixed_obs_read_only/1'
});

export function isObsModuleEntry(content, entry) {
  const definition = obsModuleDefinition;
  const files = content?.inventory?.files ?? [];
  return entry?.kind === 'worker' && entry.loader === 'node_module' &&
    files.some(file => file.file_id === entry.file_id && file.role === 'module' && file.digest === definition.module) &&
    files.some(file => file.file_id === entry.io_policy_file_id && file.role === 'policy' && file.digest === definition.policy);
}

export function isObsReadOnlyRole(manifest, inventory, role, device) {
  return role?.kind === 'device' && role.minimum === 1 && role.maximum === 1 &&
    role.role_id === template.device_role && device?.device_kind === template.device_kind &&
    manifest.roles.length === 1 && manifest.permission_templates.length === 0 && manifest.entrypoints.length === 1 &&
    isObsModuleEntry({inventory}, manifest.entrypoints[0]) &&
    manifest.api_versions.length === 1 && manifest.api_versions[0] === 'leafseamer-device-module/2' &&
    manifest.ipc_versions.length === 1 && manifest.ipc_versions[0] === 'device-module/3' &&
    manifest.capability_template_file_ids.length === 1 && inventory.files.some(file =>
      file.file_id === manifest.capability_template_file_ids[0] && file.role === 'schema' && file.digest === templateDigest);
}

export function selectObsWorkerResource(db, service, selected, device, template) {
  const entries = selected.content.manifest.entrypoints.filter(entry => isObsModuleEntry(selected.content, entry));
  need(entries.length === 1 && (!selected.entry || same(entries[0], selected.entry)) &&
    selected.content.manifest.api_versions.includes('leafseamer-device-module/2') &&
    !selected.content.manifest.api_versions.includes('leafseamer-device-primitives/1') &&
    !selected.content.manifest.api_versions.includes('leafseamer-device-event-capture/1') &&
    same(template, obsModuleDefinition.template), 'profile');
  const resource = readRegisteredObsResource(db, service, device.object_id);
  need(same(resource.record.device_ref, device), 'device_binding');
  const reference = selected.approval.configuration_ref;
  need(reference?.kind === 'configuration' && reference.authority_service_id === service.service_id &&
    reference.database_instance_id === service.database_instance_id, 'configuration_binding');
  const row = db.prepare('SELECT body_jcs,body_digest FROM extension_configuration WHERE configuration_id=? AND revision=?')
    .raw().get(reference.object_id, Number(reference.revision));
  need(row && row[1] === reference.digest, 'configuration_binding');
  const body = JSON.parse(row[0]), config = body.configuration, secret = config?.secret_ref;
  need(canonical(body) === row[0] && digest(body) === row[1] &&
    config && Object.keys(config).sort().join(',') === 'resource_ref,secret_ref' &&
    same(config.resource_ref, resource.resource_ref) && secret &&
    Object.keys(secret).sort().join(',') === 'owner_service_id,purpose,secret_id,version' &&
    secret.owner_service_id === service.service_id && secret.purpose === 'obs_websocket' &&
    secret.secret_id === resource.resource_ref.object_id && typeof secret.version === 'string' &&
    /^[1-9][0-9]{0,8}(?![\s\S])/.test(secret.version), 'configuration_binding');
  return {resource_ref: resource.resource_ref, secret_ref: secret, scene_uuids: resource.record.scene_uuids};
}
