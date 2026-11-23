import {canonical, digest} from './auth-clock-value.mjs';
import {ObsDiscoveryError, openObsCutSession} from './obs-discovery.mjs';

export const obsDeviceIdentity = Object.freeze({kind: 'physical', model: 'obs.studio', revision: '1'});
const document = {
  type: 'object', additionalProperties: false, required: ['sample_sequence', 'program_scene_uuid'],
  properties: {
    sample_sequence: {type: 'string', pattern: '^[1-9][0-9]{0,19}(?![\\s\\S])'},
    program_scene_uuid: {type: 'string', pattern: '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\\s\\S])'}
  }
};
const catalog = {
  catalog_revision: '1', action_ids: [], trigger_ids: [],
  state_schema: {schema_id: 'leafseamer.obs.program-scene.1', dialect: 'https://json-schema.org/draft/2020-12/schema',
    document, digest: digest(document)}
};
export const obsDeviceCatalog = () => structuredClone(catalog);
const need = (ok, code) => { if (!ok) throw new ObsDiscoveryError(code); };

// 凭据由固定装配在内存中提供；只读模块接口不包含任意 RPC 或发送出口。
export function createObsDeviceModule({resource, password, signal}) {
  need(resource?.format === 'leafseamer-obs-local-resource/1' && resource.endpoint?.address === '127.0.0.1' &&
    resource.profile === 'obs_isolated_empty_cut/1' && signal instanceof AbortSignal && !signal.aborted, 'resource_binding');
  const selected = structuredClone(resource), device = selected.device_ref.object_id;
  let connection = null, session = null, ordinal = 0n, opening = false, retired = false;
  const retire = () => {
    retired = true;
    password = null;
    connection?.close();
  };
  function current(input) {
    need(!retired && !signal.aborted && input.signal === signal &&
      input.device_id === device && connection && input.device_session_id === session, 'device_session');
    connection.assertCurrent();
    return connection;
  }
  function matches(sample) {
    need(sample.profile === selected.profile && sample.obs_version === selected.obs_version &&
      sample.websocket_version === selected.websocket_version && sample.rpc_version === selected.rpc_version &&
      sample.available_requests_digest === selected.available_requests_digest && sample.collection_name === selected.collection_name &&
      canonical(sample.scenes.map(scene => scene.obs_scene_uuid).sort()) === canonical(selected.scene_uuids), 'resource_catalog_changed');
  }
  return Object.freeze({
    api_version: 'leafseamer-device-module/2',
    async connectReadOnly(input) {
      need(!retired && !opening && !connection && !signal.aborted && input.signal === signal && input.device_id === device &&
        typeof input.device_session_id === 'string' && /^[A-Za-z0-9_-]{1,128}(?![\s\S])/.test(input.device_session_id), 'device_session');
      opening = true;
      try {
        connection = await openObsCutSession({port: selected.endpoint.port, password}, signal);
        connection.assertCurrent();
        matches(connection.initial);
        session = input.device_session_id;
        return {...obsDeviceIdentity};
      } catch (error) {
        retire();
        throw error;
      } finally { password = null; opening = false; }
    },
    async proposeCatalog(input) {
      current(input);
      need(canonical(input.identity) === canonical(obsDeviceIdentity), 'device_identity');
      return obsDeviceCatalog();
    },
    async captureBaseline(input) {
      const active = current(input);
      need(ordinal < 99999999999999999999n, 'sample_capacity');
      try {
        const sample = await active.sample();
        current(input);
        matches(sample);
        return {sample_sequence: String(++ordinal), program_scene_uuid: sample.program_scene_uuid};
      } catch (error) {
        if (error.code !== 'obs_session_busy') retire();
        throw error;
      }
    },
    async stopReadOnly(input) {
      need(!retired && input.signal === signal && input.device_id === device && connection &&
        input.device_session_id === session, 'device_session');
      retire();
    }
  });
}
