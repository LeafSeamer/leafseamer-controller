import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {IdentityError} from './identity-error.mjs';

const powershell = 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe';
const masterFile = 'leafseamer-master-key.dpapi';
const utf8 = new TextEncoder();
const helper = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false,$true)
$json = [Console]::In.ReadToEnd() | ConvertFrom-Json
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
function Check-SecretPath([string]$p, [bool]$directory) {
  $attr = [System.IO.File]::GetAttributes($p)
  if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -or
      ([bool]($attr -band [System.IO.FileAttributes]::Directory) -ne $directory)) { throw 'path' }
  if ($directory) { $acl = [System.IO.Directory]::GetAccessControl($p) }
  else { $acl = [System.IO.File]::GetAccessControl($p) }
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($owner -ne $sid -and $owner -ne $system) { throw 'owner' }
  if ($directory -and !$acl.AreAccessRulesProtected) { throw 'inheritance' }
  foreach ($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference -ne $sid -and $rule.IdentityReference -ne $system) { throw 'acl' }
  }
}
if ($json.operation -eq 'initialize') {
  $attr = [System.IO.File]::GetAttributes($json.path)
  if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -or !$([bool]($attr -band [System.IO.FileAttributes]::Directory))) { throw 'path' }
  $oldOwner = [System.IO.Directory]::GetAccessControl($json.path).GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($oldOwner -ne $sid -and $oldOwner -ne $system) { throw 'owner' }
  if ([System.IO.Directory]::EnumerateFileSystemEntries($json.path).GetEnumerator().MoveNext()) { throw 'existing' }
  $acl = [System.Security.AccessControl.DirectorySecurity]::new()
  $acl.SetAccessRuleProtection($true,$false)
  foreach ($principal in @($sid,$system)) {
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
  }
  [System.IO.Directory]::SetAccessControl($json.path,$acl)
}
Check-SecretPath $json.path $true
if ($json.operation -eq 'initialize' -or $json.operation -eq 'unprotect') {
  Add-Type -AssemblyName System.Security
  $entropy = [System.Text.Encoding]::UTF8.GetBytes('LeafSeamer/SecretStore/Windows/v1/' + $json.owner)
  $master = [System.IO.Path]::Combine($json.path,'leafseamer-master-key.dpapi')
  $inputBytes = $null
  $outputBytes = $null
  try {
    if ($json.operation -eq 'initialize') {
      $inputBytes = [Convert]::FromBase64String($json.payload)
      if ($inputBytes.Length -ne 32) { throw 'key length' }
      $outputBytes = [System.Security.Cryptography.ProtectedData]::Protect($inputBytes,$entropy,'CurrentUser')
    } else {
      $files = [System.IO.Directory]::GetFileSystemEntries($json.path)
      if ($files.Count -gt 4096) { throw 'store capacity' }
      foreach ($file in $files) { Check-SecretPath $file $false }
      if ([System.IO.FileInfo]::new($master).Length -gt 4096) { throw 'envelope size' }
      $inputBytes = [System.IO.File]::ReadAllBytes($master)
      $outputBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($inputBytes,$entropy,'CurrentUser')
      if ($outputBytes.Length -ne 32) { throw 'key length' }
    }
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($outputBytes,0,$outputBytes.Length)
    $stdout.Flush()
  } finally {
    if ($null -ne $inputBytes) { [Array]::Clear($inputBytes,0,$inputBytes.Length) }
    if ($null -ne $outputBytes) { [Array]::Clear($outputBytes,0,$outputBytes.Length) }
  }
} else { throw 'operation' }
`;
const command = Buffer.from(helper, 'utf16le').toString('base64');

export function windowsSecretDirectory(dataDirectory) {
  const absolute = path.win32.resolve(dataDirectory);
  return path.win32.join(path.win32.dirname(absolute), path.win32.basename(absolute) + '.obs-secrets');
}

function invoke(operation, directory, owner, key) {
  const location = directory.replace(/^\\\\\?\\(?=[A-Za-z]:\\)/, '');
  if (process.platform !== 'win32' || !/^[A-Za-z]:\\/.test(location)) throw new IdentityError('secret_store_profile');
  const input = Buffer.from(utf8.encode(JSON.stringify({operation, path: location, owner, ...(key&&{payload:key.toString('base64')})})));
  try {
    return execFileSync(powershell, ['-NoProfile','-NonInteractive','-EncodedCommand',command], {
      input, stdio: ['pipe','pipe','pipe'], windowsHide: true, timeout: 5000, maxBuffer: 8192
    });
  } catch { throw new IdentityError(operation === 'unprotect' ? 'secret_store_dpapi' : 'secret_store_directory_permissions'); }
  finally { input.fill(0); }
}

export function initializeWindowsSecretDirectory(directory, owner, key) {
  const protectedKey = invoke('initialize', directory, owner, key);
  if (protectedKey.length < 32 || protectedKey.length > 4096) throw new IdentityError('secret_store_dpapi');
  return {path: path.join(directory, masterFile), protectedKey};
}

export function loadWindowsSecretKey(directory, owner) {
  const key = invoke('unprotect', directory, owner);
  if (key.length !== 32) { key.fill(0); throw new IdentityError('secret_store_dpapi'); }
  return key;
}

export function checkWindowsSecretFile(filename, maxBytes) {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > maxBytes)
    throw new IdentityError('secret_store_file_permissions');
}
