import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function linuxPeerCertificates(){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-peer-certificates-'));
 try{
  const config=path.join(directory,'openssl.cnf');
  fs.writeFileSync(config,'[req]\ndistinguished_name=subject\n[subject]\n');
  fs.writeFileSync(path.join(directory,'leaf.ext'),[
   'basicConstraints=critical,CA:FALSE','keyUsage=critical,digitalSignature',
   'extendedKeyUsage=serverAuth,clientAuth','subjectAltName=DNS:localhost,IP:127.0.0.1',''
  ].join('\n'));
  function openssl(...args){
   const result=spawnSync('openssl',args,{cwd:directory,encoding:'utf8',timeout:5000,env:{...process.env,OPENSSL_CONF:config}});
   if(result.status!==0)throw new Error('pairing_test_certificate_generation',{cause:result.error??result.stderr});
  }
  function key(file){openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',file);}
  key('ca.key');
  openssl('req','-new','-x509','-key','ca.key','-subj','/CN=Pairing test CA','-days','2',
   '-addext','basicConstraints=critical,CA:TRUE,pathlen:0','-addext','keyUsage=critical,keyCertSign','-out','ca.pem');
  const read=file=>fs.readFileSync(path.join(directory,file),'utf8');
  const leaves=[];
  for(let index=1;index<=3;index++){
   key('leaf.key');
   openssl('req','-new','-key','leaf.key','-subj','/CN=localhost','-out','leaf.csr');
   openssl('x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-set_serial',String(index),
    '-days','1','-extfile','leaf.ext','-out','leaf.pem');
   leaves.push({cert:read('leaf.pem'),key:read('leaf.key')});
  }
  return {ca:read('ca.pem'),leaves};
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
}

// 仅生成测试证书，不使用系统信任库或服务密钥目录。
export function peerCertificates(){
 if(process.platform==='linux')return linuxPeerCertificates();
 const script=`$ErrorActionPreference='Stop'
 $curve=[System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
 $caKey=[System.Security.Cryptography.ECDsa]::Create($curve)
 $request=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Pairing test CA',$caKey,[System.Security.Cryptography.HashAlgorithmName]::SHA256)
 $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$true,0,$true))
 $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign,$true))
 $start=[DateTimeOffset]::UtcNow.AddMinutes(-2)
 $ca=$request.CreateSelfSigned($start,$start.AddDays(2))
 $leaves=@()
 for($index=0;$index -lt 3;$index++){
  $key=[System.Security.Cryptography.ECDsa]::Create($curve)
  $r=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost',$key,[System.Security.Cryptography.HashAlgorithmName]::SHA256)
  $r.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
  $r.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,$true))
  $oids=[System.Security.Cryptography.OidCollection]::new()
  $null=$oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'));$null=$oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2'))
  $r.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false))
  $san=[System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new();$san.AddDnsName('localhost');$san.AddIpAddress([System.Net.IPAddress]::Loopback)
  $r.CertificateExtensions.Add($san.Build());$serial=[System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
  $leaf=$r.Create($ca,$start,$start.AddDays(1),$serial)
  $leaves+=@{key=$key.ExportPkcs8PrivateKeyPem();cert=$leaf.ExportCertificatePem()};$leaf.Dispose();$key.Dispose()
 }
 @{ca=$ca.ExportCertificatePem();leaves=$leaves}|ConvertTo-Json -Depth 4 -Compress
 $ca.Dispose();$caKey.Dispose()`;
 const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8',windowsHide:true});
 if(result.status!==0)throw new Error('pairing_test_certificate_generation',{cause:result.stderr});return JSON.parse(result.stdout);
}
