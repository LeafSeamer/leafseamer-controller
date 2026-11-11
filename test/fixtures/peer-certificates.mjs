import {spawnSync} from 'node:child_process';
// 仅测试内存材料；不写系统信任库、服务秘密目录或正式发行配置。
export function peerCertificates(){
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
