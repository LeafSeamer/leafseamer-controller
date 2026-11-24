import {localEventOperations,manageLocalEvents} from './local-event-management.mjs';
import {pairingFields} from './peer-pairing-value.mjs';

export function createLocalPairingManagement({sessions,transport,assertCurrent}){
  return async (auth,operation,input)=>{
    assertCurrent();
    const peer=transport();
    if(!peer)throw new Error('pairing_runtime_unavailable');
    const api=sessions.peerPairings;
    let result;
    switch(operation){
      case 'stage': result=api.stage(auth,input);break;
      case 'export': result=api.exportFirstPairingAuthorization(auth,input);break;
      case 'activate': result=api.activate(auth,input);break;
      case 'read-audience':
        pairingFields(input,'principal_id,audience');
        result=sessions.remotePermissions.get(auth,input.principal_id,input.audience);
        break;
      case 'grant-audience':
        result=sessions.remotePermissions.replace(auth,input);
        break;
      case 'inspect':
        pairingFields(input,'binding_id');
        result=api.get(auth,input.binding_id);
        break;
      case 'prove':
        pairingFields(input,'binding_id');
        api.get(auth,input.binding_id);
        assertCurrent();
        await peer.prove(input.binding_id);
        assertCurrent();
        result=api.get(auth,input.binding_id);
        break;
      default:
        if(!localEventOperations.includes(operation))throw new Error('pairing_operation');
        result=manageLocalEvents(sessions,auth,operation,input);
    }
    assertCurrent();
    return result;
  };
}
