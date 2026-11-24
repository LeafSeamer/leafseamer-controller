import fs from 'node:fs';
import path from 'node:path';
import {isIP} from 'node:net';
import {createSecureContext} from 'node:tls';
import {pairingFields, pairingUuid} from './peer-pairing-value.mjs';

function reject(code) {
  throw Object.assign(new Error(code), {code});
}

function read(file, limit) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) reject('protected_ingress_profile');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd), {size} = stat;
    if (!stat.isFile() || size < 1 || size > limit) reject('protected_ingress_profile');
    const bytes = Buffer.alloc(size + 1);
    let length = 0, count;
    while (length < bytes.length && (count = fs.readSync(fd, bytes, length, bytes.length - length)) > 0) length += count;
    if (length !== size) reject('protected_ingress_profile');
    return bytes.subarray(0, length);
  } finally {
    fs.closeSync(fd);
  }
}

export function readProtectedIngressProfile(file) {
  if (process.platform !== 'linux') reject('protected_ingress_platform');
  try {
    const profile = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(read(file, 16384)));
    pairingFields(profile, 'address,certificate_file,database_instance_id,format,origin,port,private_key_file,service_id');
    const {format, address, port, origin, service_id, database_instance_id} = profile;
    pairingUuid(service_id);
    pairingUuid(database_instance_id);
    if (format !== 'leafseamer.controller-protected-ingress/1' || typeof address !== 'string' || !isIP(address) ||
        !Number.isInteger(port) || port < 1 || port > 65535 || typeof origin !== 'string') reject('protected_ingress_profile');
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin) reject('protected_ingress_profile');
    const cert = read(profile.certificate_file, 65536), key = read(profile.private_key_file, 32768);
    createSecureContext({cert, key});
    return {host: address, port, tls: {origin, cert, key}, protectedIngressIdentity: {service_id, database_instance_id}};
  } catch {
    reject('protected_ingress_profile');
  }
}
