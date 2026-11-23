import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingCertificate,pairingFields as fields,pairingInteger as integer,pairingNeed as need,pairingTranscript,pairingUuid as uuid} from './peer-pairing-value.mjs';

export const firstPairingFormat='leafseamer.first-pairing-authorization/1';
const hash=value=>typeof value==='string'&&/^sha256:[0-9a-f]{64}$/.test(value);
const signingBytes=authorization=>Buffer.from(firstPairingFormat+'\0'+canonical(authorization));

function checked(body,certificate){
 fields(body,'format,authorization_id,transcript,transcript_digest,controller_stage_ref,administrator,not_before_ns,expires_ns');
 need(body.format===firstPairingFormat,'first_authorization_format');uuid(body.authorization_id);
 const transcript=pairingTranscript(body.transcript);
 need(same(transcript,body.transcript)&&body.transcript_digest===digest(transcript),'first_authorization_transcript');
 const controller=transcript.parties.find(party=>party.service_kind==='controller');
 const seamer=transcript.parties.find(party=>party.service_kind==='seamer');
 need(controller&&seamer&&controller.issuer_id===seamer.issuer_id&&controller.issuer_epoch===seamer.issuer_epoch&&
  seamer.permissions.includes('auth.introspect'),'first_authorization_parties');
 const pin=pairingCertificate(certificate.raw);
 need(certificate.publicKey.asymmetricKeyType==='ec'&&certificate.publicKey.asymmetricKeyDetails?.namedCurve==='prime256v1'&&
  pin.certificate_der_sha256===controller.certificate_der_sha256&&pin.spki_sha256===controller.spki_sha256,'first_authorization_certificate');
 const stage=body.controller_stage_ref,actor=body.administrator;
 fields(stage,'id,revision,digest');
 need(stage.id===controller.binding_id&&stage.revision==='1'&&hash(stage.digest),'first_authorization_stage');
 fields(actor,'principal_kind,principal_id,issuer_id,issuer_epoch');uuid(actor.principal_id);
 need(actor.principal_kind==='human'&&actor.issuer_id===controller.issuer_id&&actor.issuer_epoch===controller.issuer_epoch,'first_authorization_administrator');
 const begin=integer(body.not_before_ns),end=integer(body.expires_ns);
 need(begin<end&&end-begin<=600000000000n&&transcript.parties.every(party=>begin>=integer(party.not_before_ns)&&end<=integer(party.expires_ns)),
  'first_authorization_validity');
 return body;
}

export function signFirstPairingAuthorization(body,certificate,privateKey){
 const authorization=checked(body,certificate);
 need(certificate.checkPrivateKey(privateKey),'first_authorization_certificate');
 const signature=crypto.sign('sha256',signingBytes(authorization),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
 return {authorization,signature};
}

export function verifyFirstPairingAuthorization(bytes,pinnedCertificate){
 need(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=32768,'first_authorization_capacity');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),value=JSON.parse(text);
 fields(value,'authorization,signature');
 const certificate=pinnedCertificate instanceof crypto.X509Certificate?pinnedCertificate:new crypto.X509Certificate(pinnedCertificate);
 const {authorization,signature}=value;
 need(canonical(value)===text&&typeof signature==='string'&&/^[A-Za-z0-9_-]{86}$/.test(signature),'first_authorization_encoding');
 const signed=Buffer.from(signature,'base64url');
 need(signed.length===64&&signed.toString('base64url')===signature,'first_authorization_encoding');
 checked(authorization,certificate);
 need(crypto.verify('sha256',signingBytes(authorization),{key:certificate.publicKey,dsaEncoding:'ieee-p1363'},signed),'first_authorization_signature');
 return value;
}
