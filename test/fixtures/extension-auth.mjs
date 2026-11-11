import crypto from 'node:crypto';
import {startAuthenticationClock} from '../../dist/auth-clock.mjs';
import {localIdentityPermissions} from '../../dist/local-permission-store.mjs';
import {fixture as clockFixture} from '../auth-clock-fixture.mjs';
const login={login:'role.test',password:'Synthetic-role-password-123'};
const sessionInput=value=>({credential_id:value.credential_id,secret:value.secret,csrf:value.csrf});
export async function authenticated(t,f,{grant=true,native=null,sampleWindowPolicy=null}={}){
 const c=clockFixture(f.store.authenticationClock.scope,native,{sampleWindowPolicy}),real=startAuthenticationClock(c.source,f.store.authenticationClock,c.provider,{schedule:native!==null}),state={offset:0n};
 t.after(()=>real.stop());const shifted=value=>({...value,lower_ns:String(BigInt(value.lower_ns)+state.offset),upper_ns:String(BigInt(value.upper_ns)+state.offset)});
 const clock={current(){const value=real.current();state.onRead?.();return shifted(value);},pairingSample(){const value=real.pairingSample();state.onPairingRead?.();return shifted(value);}};
 const sessions=f.store.sessions(clock),logged=await sessions.login(login),auth=sessionInput(logged);
 if(grant){const current=sessions.localPermissions(auth);if(!current.permissions.includes('extension.manage'))sessions.replaceLocalPermissions(auth,{request_id:crypto.randomUUID(),principal_id:logged.session.principal_id,
  expected_revision:current.revision,permissions:[...localIdentityPermissions,'extension.read','extension.manage']});}
 const token=(scopes=['extension.manage','extension.read'])=>{const value=sessions.issueToken(auth,{request_id:crypto.randomUUID(),audience:f.store.identity.service_id,requested_scopes:scopes});return {token_id:value.token.token_id,secret:value.secret};};
 return {sessions,logged,auth,token,state,real};
}
