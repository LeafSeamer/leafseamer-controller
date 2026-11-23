import {obsDeviceCatalog,obsDeviceIdentity} from './obs-device-module.mjs';
import {ObsCutEntryRejected,ObsDiscoveryError,openObsCutWriterSession} from './obs-discovery.mjs';
import {encodeObsCutPacket,obsCutDirectoryMatches,obsCutPrimitive} from './obs-cut-packet.mjs';
import {canonical} from './auth-clock-value.mjs';

export const obsCutAction = 'obs.program_scene.set';
export function obsCutDeviceCatalog(){
  return {...obsDeviceCatalog(),action_ids:[obsCutAction]};
}

const need=(ok,code)=>{if(!ok)throw new ObsDiscoveryError(code);};

// 由受监督 host 核准固定内容与凭据后调用。读、编码与 Cut 使用同一条 OBS 连接。
export function createObsCutDeviceModule({resource,resourceRef,password,signal,onInvalidated,tick}){
  need(resource?.format==='leafseamer-obs-local-resource/1'&&resource.endpoint?.address==='127.0.0.1'&&
    resource.profile==='obs_isolated_empty_cut/1'&&signal instanceof AbortSignal&&!signal.aborted&&typeof tick==='function','resource_binding');
  const resourceCopy=structuredClone(resource),reference=canonical(resourceRef),device=resourceCopy.device_ref.object_id;
  let connection,session,confirmation,opening=false,retired=false,ordinal=0n;
  const retire=()=>{
    retired=true;
    password=null;
    connection?.close();
    signal.removeEventListener('abort',retire);
  };
  signal.addEventListener('abort',retire,{once:true});
  function current(input){
    need(!retired&&!signal.aborted&&input.device_id===device&&session&&input.device_session_id===session&&
      input.signal instanceof AbortSignal&&!input.signal.aborted,'device_session');
    connection.assertCurrent();
  }
  function match(resourceSample){
    const ids=resourceSample.scenes.map(scene=>scene.obs_scene_uuid).sort();
    for(const field of ['profile','obs_version','websocket_version','rpc_version','available_requests_digest','collection_name'])
      need(resourceSample[field]===resourceCopy[field],'resource_catalog_changed');
    need(ids.length===resourceCopy.scene_uuids.length&&ids.every((id,index)=>id===resourceCopy.scene_uuids[index]),'resource_catalog_changed');
  }
  return Object.freeze({
    api_version:'leafseamer-device-module/2',
    async connectReadOnly(input){
      need(!retired&&!opening&&!connection&&!signal.aborted&&input.signal===signal&&input.device_id===device&&
        typeof input.device_session_id==='string'&&/^[A-Za-z0-9_-]{1,128}(?![\s\S])/.test(input.device_session_id),'device_session');
      opening=true;
      try{
        connection=await openObsCutWriterSession({port:resourceCopy.endpoint.port,password},signal,onInvalidated);
        connection.assertCurrent();
        match(connection.initial);
        session=input.device_session_id;
        return {...obsDeviceIdentity};
      }catch(error){retire();throw error;}
      finally{password=null;opening=false;}
    },
    async proposeCatalog(input){
      current(input);
      need(canonical(input.identity)===canonical(obsDeviceIdentity),'device_identity');
      return obsCutDeviceCatalog();
    },
    async captureBaseline(input){
      current(input);
      need(ordinal<99999999999999999999n,'sample_capacity');
      const sample=await connection.sample();
      current(input);
      match(sample);
      const scenes=[...sample.scenes].sort((a,b)=>a.obs_scene_uuid<b.obs_scene_uuid?-1:1);
      return {sample_sequence:String(++ordinal),program_scene_uuid:sample.program_scene_uuid,scenes};
    },
    async stopReadOnly(input){current(input);retire();},
    execution:Object.freeze({
      api_version:'leafseamer-device-primitives/1',
      bindSceneCatalog(catalog,boundResource){
        current({...catalog,signal});
        need(!confirmation&&canonical(boundResource)===reference&&
          obsCutDirectoryMatches(catalog,connection.initial.scenes),'resource_catalog_changed');
        confirmation=structuredClone(catalog);
      },
      async encodePrimitive(input){
        current(input);
        need(confirmation&&input.primitive_id===obsCutPrimitive,'cut_primitive');
        return encodeObsCutPacket(confirmation,input,input.parameters);
      },
      async writePrimitive(input){
        current(input);
        need(confirmation&&typeof input.enterTransmission==='function','cut_dispatch');
        return connection.writePreparedCut({...input,catalog:confirmation,tick,
          enterTransmission(){
            try{return input.enterTransmission();}
            catch{throw new ObsCutEntryRejected();}
          }
        });
      }
    })
  });
}
