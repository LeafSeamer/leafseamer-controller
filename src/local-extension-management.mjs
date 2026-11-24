import {IdentityError} from './identity-crypto.mjs';

export const localExtensionPath='/auth/local-extension/v1';
export const localExtensionOperations=Object.freeze(['approve','plan','activate','enable','lookup-plan','lookup-activation','start']);

export function createLocalExtensionManagement({sessions,workerLaunches,assertCurrent}){
  const management=sessions.localExtensionManagement;
  const actions={approve:management.approve,plan:management.plan,activate:management.activate,enable:management.enable,
    'lookup-plan':(auth,request)=>lookup(management.lookupPlan,auth,request),
    'lookup-activation':(auth,request)=>lookup(management.lookupActivation,auth,request)};
  function lookup(query,auth,request){
    if(!request||Object.keys(request).join(',')!=='request_id')throw new IdentityError('extension_management_input');
    const result=query(auth,request.request_id);
    if(!result)throw new IdentityError('extension_management_not_found');
    return result;
  }
  return async (auth,operation,request)=>{
    assertCurrent();
    if(operation==='start'){
      const proof=management.assertStart(auth);
      return workerLaunches.startLinux(request,()=>{
        assertCurrent();
        const current=management.assertStart(auth);
        if(current.authorization_digest!==proof.authorization_digest)
          throw new IdentityError('extension_management_denied');
      });
    }
    if(!Object.hasOwn(actions,operation))throw new IdentityError('extension_management_input');
    const result=await actions[operation](auth,request);
    assertCurrent();
    return result;
  };
}
