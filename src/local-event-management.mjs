import {IdentityError} from './identity-error.mjs';
import {pairingFields} from './peer-pairing-value.mjs';

export const localEventOperations=Object.freeze(['register-event-scope','register-status-scope','revoke-event-scope','create-event-consumer','approve-event-consumer','approve-event-policy']);

export function manageLocalEvents(sessions,auth,operation,request){
  if(!sessions.registerEventScope||!sessions.serviceSubscriptions)throw new IdentityError('event_scope_unavailable');
  switch(operation){
    case 'register-event-scope':return sessions.registerEventScope(auth,request);
    case 'register-status-scope':return sessions.registerEventScope(auth,request,'status_projection');
    case 'revoke-event-scope':return sessions.revokeEventScope(auth,request);
    case 'create-event-consumer':
      pairingFields(request,'display_name,request_id');
      return sessions.createServicePrincipal(auth,{...request,purpose:'event_consumer'});
    case 'approve-event-consumer':
    case 'approve-event-policy': {
      const permissions=request?.permissions;
      if(!Array.isArray(permissions)||permissions.length!==2||
        !permissions.includes('event.internal.subscribe')||!permissions.includes('status.read'))throw new IdentityError('service_identity_input');
      return operation==='approve-event-consumer'?sessions.approveSubscriptionServicePrincipal(auth,request):
        sessions.approveLocalSubscriptionPolicy(auth,request);
    }
    default:throw new IdentityError('event_scope_input');
  }
}
