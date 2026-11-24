import crypto from 'node:crypto';
import {IdentityError} from './identity-error.mjs';
import {localEventOperations,manageLocalEvents} from './local-event-management.mjs';
import {pairingFields} from './peer-pairing-value.mjs';

export const localRunEndorsementOperations=Object.freeze(['create-automation-principal','approve-automation-principal',
  'replace-run-endorsement-policy','endorse-run']);

export function createLocalPairingManagement({sessions,serviceId,transport,assertCurrent}){
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
      case 'create-automation-principal':
        pairingFields(input,'display_name,request_id');
        result=sessions.createServicePrincipal(auth,{...input,purpose:'automation'});
        break;
      case 'approve-automation-principal':
        result=sessions.approveAutomationServicePrincipal(auth,input);
        break;
      case 'replace-run-endorsement-policy':
        if(!sessions.runEndorsementPolicies)throw new IdentityError('run_endorsement_policy_unavailable');
        result=sessions.runEndorsementPolicies.replace(auth,input);
        break;
      case 'endorse-run': {
        pairingFields(input,'binding_id,idempotency_key,proposal_ref');
        if(!sessions.runApprovalEndorsements)throw new IdentityError('run_endorsement_unavailable');
        const issued=sessions.issueToken(auth,{request_id:crypto.randomUUID(),audience:serviceId,
          requested_scopes:['grant.manage','grant.read','request.create']});
        const token={token_id:issued.token.token_id,secret:issued.secret};
        const context=sessions.createEndorsementContext(token,{ttl_ms:30000,max_unique_requests:1});
        result=await sessions.runApprovalEndorsements.endorse(token,{...input,context_id:context.context_id});
        break;
      }
      default:
        if(!localEventOperations.includes(operation))throw new Error('pairing_operation');
        result=manageLocalEvents(sessions,auth,operation,input);
    }
    assertCurrent();
    return result;
  };
}
