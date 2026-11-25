import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {timeProviderCaptureStore} from '../dist/time-provider-capture.mjs';

function extension(type,payload){
  const field=Buffer.alloc(4+payload.length);
  field.writeUInt16BE(type);
  field.writeUInt16BE(field.length,2);
  payload.copy(field,4);
  return field;
}

function packet(response,extensionFields){
  const header=Buffer.alloc(48);
  header[0]=response?36:35;
  if(response){
    header[1]=1;
    for(const offset of [16,24,32,40])header[offset]=1;
  }else header[40]=1;
  return Buffer.concat([header,...extensionFields]).toString('base64url');
}

test('NTS 归档前核对请求与应答的唯一标识和末尾认证字段',()=>{
  const readKey=()=>{throw new Error('fixture_reached_key_reader');};
  const archive=timeProviderCaptureStore({inTransaction:false},{},{currentKey:readKey,readKey});
  const uid=extension(0x0104,Buffer.alloc(32,1)),different=extension(0x0104,Buffer.alloc(32,2));
  const auth=extension(0x0404,Buffer.alloc(32));
  const rawKE=Buffer.from([128,0,0,0]);
  const candidate={m1_tick_ns:'10',m4_tick_ns:'11',request:packet(false,[uid,auth]),
    key_reply:rawKE.toString('base64url'),key_reply_digest:'sha256:'+createHash('sha256').update(rawKE).digest('hex')};
  function store(fields){
    return archive.store({attempt:{attempted_tick_ns:'9',valid_before_tick_ns:'12'},
      authorize(){},candidate:{...candidate,response:packet(true,fields)}});
  }
  assert.throws(()=>store([uid,auth]),/fixture_reached_key_reader/);
  assert.throws(()=>store([different,auth]),/time_provider_capture_nts_identifier/);
  assert.throws(()=>store([uid,uid,auth]),/time_provider_capture_nts_identifier/);
  assert.throws(()=>store([uid]),/time_provider_capture_nts_authenticator/);
  assert.throws(()=>store([uid,auth,extension(0xabcd,Buffer.alloc(4))]),/time_provider_capture_nts_authenticator/);
});
