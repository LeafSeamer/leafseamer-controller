import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {isIP} from 'node:net';
import {spawnSync} from 'node:child_process';
import {fields} from './auth-clock-value.mjs';

const flags=fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK;
const hash=/^sha256:[0-9a-f]{64}$(?![\s\S])/;
const decimal=/^-?[0-9]{1,16}(?:\.[0-9]{1,9})?$(?![\s\S])/;
const integer=/^(0|[1-9][0-9]*)$(?![\s\S])/;
const env=Object.freeze({LC_ALL:'C',LANG:'C',PATH:'/usr/bin:/usr/sbin'});
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};
const digest=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const absolute=file=>typeof file==='string'&&file.length<=512&&/^\/[A-Za-z0-9_.\/-]+$(?![\s\S])/.test(file)&&
  path.posix.normalize(file)===file&&file!=='/'&&!file.endsWith('/');
const addresses=value=>Array.isArray(value)&&value.length>=1&&value.length<=16&&new Set(value).size===value.length&&
  value.every(address=>typeof address==='string'&&isIP(address)!==0);
const sameList=(left,right)=>[...left].sort().join(',')===[...right].sort().join(',');

function trustedParents(file,owner=0n){
  for(let directory=path.posix.dirname(file);directory!=='/';directory=path.posix.dirname(directory)){
    const stat=fs.lstatSync(directory,{bigint:true});
    const sticky=(directory==='/tmp'||directory==='/var/tmp')&&stat.uid===0n&&(stat.mode&0o1000n)!==0n;
    need(stat.isDirectory()&&(stat.uid===0n||stat.uid===owner)&&((stat.mode&0o022n)===0n||sticky),
      'clock_evidence_chrony_directory');
  }
}

function read(file,limit,{owner,symlink=false}={}){
  if(owner!==undefined)trustedParents(file,owner);
  const fd=fs.openSync(file,symlink?fs.constants.O_RDONLY|fs.constants.O_NONBLOCK:flags);
  try{
    const stat=fs.fstatSync(fd,{bigint:true});
    need(stat.isFile()&&stat.size<=BigInt(limit)&&(owner===undefined||
      (stat.uid===0n||stat.uid===owner)&&(stat.mode&0o022n)===0n),'clock_evidence_chrony_file');
    const bytes=Buffer.alloc(limit+1);
    let length=0,count;
    while(length<bytes.length&&(count=fs.readSync(fd,bytes,length,bytes.length-length,null))>0)length+=count;
    need(length>0&&length<=limit,'clock_evidence_chrony_file');
    return bytes.subarray(0,length);
  }finally{fs.closeSync(fd);}
}
const text=(file,limit)=>new TextDecoder('utf-8',{fatal:true}).decode(read(file,limit));

function configSources(bytes,settings){
  const lines=new TextDecoder('utf-8',{fatal:true}).decode(bytes).split('\n')
    .map(line=>line.trim()).filter(line=>line&&!/^[!;#%]/.test(line)).map(line=>line.split(/\s+/));
  const prohibited=new Set(['include','confdir','sourcedir','pool','peer','refclock','local','manual']);
  need(lines.every(([name])=>!prohibited.has(name.toLowerCase())),'clock_evidence_chrony_configuration');
  const sources=lines.filter(([name])=>name.toLowerCase()==='server').map(([,value])=>value);
  const pidFiles=lines.filter(([name])=>name.toLowerCase()==='pidfile');
  const sockets=lines.filter(([name,address])=>name.toLowerCase()==='bindcmdaddress'&&address?.startsWith('/'));
  need(addresses(sources)&&sameList(sources,settings.source_addresses)&&pidFiles.length===1&&pidFiles[0].length===2&&
    pidFiles[0][1]===settings.pid_file&&sockets.length===1&&sockets[0].length===2&&sockets[0][1]===settings.socket_file,
  'clock_evidence_chrony_configuration');
}

function fixedArguments(raw,configuration){
  need(raw.at(-1)===0,'clock_evidence_chrony_daemon');
  const [binary,...args]=raw.subarray(0,-1).toString('utf8').split('\0');
  need(path.posix.basename(binary)==='chronyd','clock_evidence_chrony_daemon');
  const seen=new Set();let selected=null;
  for(let i=0;i<args.length;i++){
    const option=args[i];
    need(!seen.has(option)&&['-n','-d','-x','-f','-F'].includes(option),'clock_evidence_chrony_daemon');
    seen.add(option);
    if(option==='-f')selected=args[++i];
    if(option==='-F')need(/^-?[012]$/.test(args[++i]??''),'clock_evidence_chrony_daemon');
  }
  need(selected===configuration,'clock_evidence_chrony_daemon');
  return seen.has('-x');
}

function socketInode(filename){
  const matches=text('/proc/net/unix',1048576).split('\n').slice(1).flatMap(line=>{
    const fields=line.trim().split(/\s+/);
    return fields.length===8&&fields[4]==='0002'&&fields[7]===filename?[fields[6]]:[];
  });
  need(matches.length===1&&integer.test(matches[0]),'clock_evidence_chrony_socket');
  return matches[0];
}

function daemon(settings){
  const socket=fs.lstatSync(settings.socket_file,{bigint:true});
  need(socket.isSocket(),'clock_evidence_chrony_socket');
  trustedParents(settings.socket_file,socket.uid);
  const pid=read(settings.pid_file,48,{owner:socket.uid}).toString('utf8').trim();
  need(/^[1-9][0-9]{0,9}$/.test(pid)&&BigInt(pid)>1n,'clock_evidence_chrony_daemon');
  const directory='/proc/'+pid;
  const stat=text(directory+'/stat',4096),end=stat.lastIndexOf(') '),columns=stat.slice(end+2).trimEnd().split(' ');
  need(stat.startsWith(pid+' (')&&end>0&&/^[A-Za-z]$/.test(columns[0]??'')&&
    !['Z','X','x'].includes(columns[0])&&integer.test(columns[19]??''),'clock_evidence_chrony_daemon');
  const proc=fs.statSync(directory,{bigint:true});
  const inode=socketInode(settings.socket_file),descriptors=fs.readdirSync(directory+'/fd');
  need(descriptors.length<=65536&&descriptors.some(fd=>{
    try{return fs.readlinkSync(directory+'/fd/'+fd)==='socket:['+inode+']';}
    catch(error){if(error.code==='ENOENT')return false;throw error;}
  }),'clock_evidence_chrony_socket');
  const namespace=fs.statSync(directory+'/ns/time',{bigint:true}),local=fs.statSync('/proc/self/ns/time',{bigint:true});
  need(namespace.dev===local.dev&&namespace.ino===local.ino,'clock_evidence_chrony_namespace');
  need(digest(read(directory+'/exe',4194304,{symlink:true}))===settings.chronyd_sha256,'clock_evidence_chrony_daemon');
  const trackingOnly=fixedArguments(read(directory+'/cmdline',8192),settings.configuration_file);
  return {pid,start_ticks:columns[19],process:String(proc.dev)+':'+proc.ino,socket:String(socket.dev)+':'+socket.ino,
    inode,time_namespace:String(namespace.dev)+':'+namespace.ino,trackingOnly};
}

function tracking(raw){
  const columns=raw.trimEnd().split(',');
  need(columns.length===14&&/^[0-9A-F]{8}$/.test(columns[0])&&!['00000000','7F7F0101'].includes(columns[0])&&
    isIP(columns[1])!==0&&/^(?:[1-9]|1[0-5])$/.test(columns[2])&&decimal.test(columns[3])&&Number(columns[3])>0&&
    columns[13]==='Normal','clock_evidence_chrony_unsynchronized');
  function nanoseconds(value){
    need(decimal.test(value),'clock_evidence_chrony_error');
    const [seconds,fraction='']=value.replace(/^-/,'').split('.');
    const absolute=BigInt(seconds)*1000000000n+BigInt(fraction.padEnd(9,'0'));
    return value.startsWith('-')?-absolute:absolute;
  }
  const offset=nanoseconds(columns[4]),delay=nanoseconds(columns[10]),dispersion=nanoseconds(columns[11]);
  need(delay>=0n&&dispersion>=0n,'clock_evidence_chrony_error');
  // Allow for rounding in the three decimal fields printed by chronyc.
  return {source:columns[1],reportedErrorNs:(offset<0n?-offset:offset)+dispersion+(delay+1n)/2n+2n};
}

function selectedSource(raw,settings){
  const rows=raw.trimEnd().split('\n').map(line=>line.split(','));
  need(rows.length<=16&&rows.every(row=>row.length===10&&row[0]==='^'&&/^[*+?x~-]$/.test(row[1])),
    'clock_evidence_chrony_sources');
  const reported=rows.map(row=>row[2]);
  const selected=rows.filter(row=>row[1]==='*');
  need(addresses(reported)&&sameList(reported,settings.source_addresses)&&selected.length===1,'clock_evidence_chrony_sources');
  const row=selected[0];
  need(/^(?:[1-9]|1[0-5])$/.test(row[3])&&/^[0-3]?[0-7]{1,2}$/.test(row[5])&&
    (Number.parseInt(row[5],8)&1)===1&&integer.test(row[6])&&Number(row[6])<settings.max_source_age_s,
    'clock_evidence_chrony_stale');
  return row[2];
}

export function observeLinuxChronyHealth(settings){
  try{
    need(process.platform==='linux','clock_evidence_chrony_platform');
    fields(settings,['format','chronyc_file','chronyc_sha256','chronyd_sha256','configuration_file','configuration_sha256',
      'pid_file','socket_file','source_addresses','max_source_age_s']);
    need(settings.format==='leafseamer.linux-chrony-health/1'&&[settings.chronyc_sha256,settings.chronyd_sha256,settings.configuration_sha256].every(value=>
      typeof value==='string'&&hash.test(value))&&[settings.chronyc_file,settings.configuration_file,settings.pid_file,settings.socket_file].every(absolute)&&
      settings.socket_file.length<=100&&addresses(settings.source_addresses)&&Number.isInteger(settings.max_source_age_s)&&
      settings.max_source_age_s>=1&&settings.max_source_age_s<=3600,'clock_evidence_chrony_profile');
    const verify=()=>{
      need(digest(read(settings.chronyc_file,4194304,{owner:0n}))===settings.chronyc_sha256,'clock_evidence_chrony_client');
      const bytes=read(settings.configuration_file,65536,{owner:0n});
      need(digest(bytes)===settings.configuration_sha256,'clock_evidence_chrony_configuration');
      configSources(bytes,settings);
      return daemon(settings);
    };
    const identity=verify();
    const deadline=performance.now()+750;
    function query(command){
      const remaining=Math.floor(deadline-performance.now());
      need(remaining>0,'clock_evidence_chrony_timeout');
      // Keep the signer's local identity when the packaged client has a default drop user.
      const result=spawnSync(settings.chronyc_file,['-u','root','-n','-c','-h',settings.socket_file,command],{
        env,encoding:'utf8',timeout:remaining,maxBuffer:16384
      });
      need(result.status===0,'clock_evidence_chrony_query');
      return result.stdout;
    }
    const before=tracking(query('tracking'));
    const selected=selectedSource(query('sources'),settings);
    const after=tracking(query('tracking'));
    need(before.source===selected&&after.source===selected,'clock_evidence_chrony_source_changed');
    need(JSON.stringify(verify())===JSON.stringify(identity)&&performance.now()<deadline,'clock_evidence_chrony_changed');
    const reportedErrorNs=before.reportedErrorNs>after.reportedErrorNs?before.reportedErrorNs:after.reportedErrorNs;
    return Object.freeze({state:identity.trackingOnly?'tracking_only':'synchronized',source:selected,reportedErrorNs,identity:Object.freeze(identity)});
  }catch(error){
    if(/^clock_evidence_chrony_[a-z_]+$/.test(error.code??''))throw error;
    throw Object.assign(new Error('clock_evidence_chrony_unavailable',{cause:error}),{code:'clock_evidence_chrony_unavailable'});
  }
}
