#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {canonical,context,fields} from './auth-clock-value.mjs';
import {clockInteger,openNativeClock} from './native-clock.mjs';
import {pairingUuid} from './peer-pairing-value.mjs';

const evidenceFormat='leafseamer.authentication-clock-evidence/1';
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const hash=value=>typeof value==='string'&&/^sha256:[0-9a-f]{64}$/.test(value);

function readFile(file,limit){
 need(typeof file==='string'&&path.isAbsolute(file)&&fs.lstatSync(file).isFile(),'clock_evidence_file');
 const fd=fs.openSync(file,'r');
 try{
  const stat=fs.fstatSync(fd);
  need(stat.isFile()&&stat.size>0&&stat.size<=limit,'clock_evidence_size');
  const bytes=Buffer.alloc(stat.size+1);
  let offset=0,count;
  while(offset<bytes.length&&(count=fs.readSync(fd,bytes,offset,bytes.length-offset,null))>0)offset+=count;
  need(offset===stat.size,'clock_evidence_size');
  return bytes.subarray(0,offset);
 }finally{fs.closeSync(fd);}
}
function readJson(file){
 const text=new TextDecoder('utf-8',{fatal:true}).decode(readFile(file,65536));
 const value=JSON.parse(text);
 need(canonical(value)===text,'clock_evidence_encoding');
 return value;
}
function signingProfile(file){
 const profile=readJson(file);
 fields(profile,['format','service_id','database_instance_id','policy_digest','native_binary_digest','private_key_file','evidence_file']);
 need(profile.format==='leafseamer.authentication-clock-signing-profile/1'&&hash(profile.policy_digest)&&hash(profile.native_binary_digest)&&
  typeof profile.private_key_file==='string'&&path.isAbsolute(profile.private_key_file)&&
  typeof profile.evidence_file==='string'&&path.isAbsolute(profile.evidence_file),'clock_evidence_profile');
 pairingUuid(profile.service_id);pairingUuid(profile.database_instance_id);
 return profile;
}
function checkStatement(statement,profile,now){
 fields(statement,['challenge','evidence']);
 const {challenge,evidence}=statement;
 const supervised=Object.hasOwn(challenge??{},'clock_domain_id');
 fields(challenge,['event','service_id','service_boot_id','database_instance_id','native_binary_digest','continuity','tick_ns',
  ...(supervised?['clock_domain_id','descriptor_digest']:[])]);
 pairingUuid(challenge.service_boot_id);
 need(challenge.event==='authentication_clock_challenge'&&challenge.service_id===profile.service_id&&
  challenge.database_instance_id===profile.database_instance_id&&challenge.native_binary_digest===profile.native_binary_digest&&
  clockInteger(challenge.tick_ns)<=now,'clock_evidence_challenge');
 context(evidence,{service_id:profile.service_id,service_boot_id:challenge.service_boot_id},profile.native_binary_digest,now);
 need(evidence.policy.digest===profile.policy_digest,'clock_evidence_policy');
 const runtime=evidence.runtime;
 need(runtime.continuity===challenge.continuity&&(!supervised||runtime.clock_domain_id===challenge.clock_domain_id&&
  runtime.descriptor_digest===challenge.descriptor_digest),'clock_evidence_runtime');
}
function replaceFile(file,bytes){
 const prior=fs.lstatSync(file,{throwIfNoEntry:false});
 need(!prior||prior.isFile(),'clock_evidence_file');
 const temporary=path.join(path.dirname(file),'.clock-evidence-'+crypto.randomUUID()+'.tmp');
 const fd=fs.openSync(temporary,'wx',0o600);
 try{
  try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.renameSync(temporary,file);
 }finally{if(fs.existsSync(temporary))fs.unlinkSync(temporary);}
}

try{
 const args=process.argv.slice(2),options=new Map();
 for(let i=0;i<args.length;i+=2){
  need(['--profile','--statement'].includes(args[i])&&!options.has(args[i])&&typeof args[i+1]==='string','clock_evidence_arguments');
  options.set(args[i],args[i+1]);
 }
 need(options.size===2,'clock_evidence_arguments');
 const profileFile=options.get('--profile'),statementFile=options.get('--statement');
 const profile=signingProfile(profileFile),statement=readJson(statementFile),clock=openNativeClock();
 const inputs=[profileFile,statementFile,profile.private_key_file].map(file=>fs.realpathSync.native(file));
 const output=path.join(fs.realpathSync.native(path.dirname(profile.evidence_file)),path.basename(profile.evidence_file));
 const matchPath=process.platform==='win32'?value=>value.toLowerCase():value=>value;
 need(!inputs.map(matchPath).includes(matchPath(output)),'clock_evidence_output');
 checkStatement(statement,profile,clock.tick());
 const keyBytes=readFile(profile.private_key_file,16384);
 let key;
 try{key=crypto.createPrivateKey(keyBytes);}finally{keyBytes.fill(0);}
 need(key.asymmetricKeyType==='ed25519','clock_evidence_signer');
 const {evidence}=statement;
 const signature=crypto.sign(null,Buffer.from(evidenceFormat+'\0'+canonical(evidence)),key).toString('base64url');
 checkStatement(statement,profile,clock.tick());
 replaceFile(output,canonical({format:evidenceFormat,evidence,signature}));
 process.stdout.write(canonical({state:'published',service_id:profile.service_id,service_boot_id:evidence.runtime.service_boot_id})+'\n');
}catch(error){
 const code=/^(clock_evidence_|auth_clock_)[a-z_]+$/.test(error.code??'')?error.code:'clock_evidence_failed';
 process.stderr.write(JSON.stringify({error:code})+'\n');
 process.exitCode=1;
}
