import fs from 'node:fs';

const procfs = 0x9fa0, sysfs = 0x62656572;
const mountLimit = 256 * 1024;

function reject(code) { throw Object.assign(new Error(code), {code}); }

function readProc(file, limit) {
  if (fs.statfsSync(file).type !== procfs) reject('clock_kernel_sleep_unverified');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const buffer = Buffer.alloc(limit + 1);
    let used = 0, count;
    while (used < buffer.length && (count = fs.readSync(fd, buffer, used, buffer.length - used, null)) > 0) used += count;
    if (!used || used > limit) reject('clock_kernel_sleep_unverified');
    return buffer.toString('utf8', 0, used);
  } finally { fs.closeSync(fd); }
}

export function verifyLinuxKernelSleepDisabled() {
  try {
    const fd = fs.openSync('/sys', fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY);
    try {
      const root = '/proc/self/fd/'+fd;
      const mountId = /^mnt_id:\s*([0-9]+)$/m.exec(readProc('/proc/self/fdinfo/'+fd, 4096))?.[1];
      if (!mountId || fs.statfsSync(root).type !== sysfs) reject('clock_kernel_sleep_unverified');
      let verifiedRoot = false;
      for (const line of readProc('/proc/self/mountinfo', mountLimit).trimEnd().split('\n')) {
        const [mount, filesystem] = line.split(' - ');
        const [id, , , subroot, location] = mount.split(' ');
        if (!filesystem || !location) reject('clock_kernel_sleep_unverified');
        if (location === '/sys/power' || location.startsWith('/sys/power/')) reject('clock_kernel_sleep_unverified');
        if (id === mountId) verifiedRoot = subroot === '/' && location === '/sys' && filesystem.startsWith('sysfs ');
      }
      if (!verifiedRoot) reject('clock_kernel_sleep_unverified');
      const power = fs.lstatSync(root+'/power', {throwIfNoEntry: false});
      if (power && !power.isDirectory()) reject('clock_kernel_sleep_unverified');
      if (fs.lstatSync(root+'/power/state', {throwIfNoEntry: false})) reject('clock_kernel_sleep_available');
      return mountId;
    } finally { fs.closeSync(fd); }
  } catch (error) {
    if (error.code === 'clock_kernel_sleep_available') throw error;
    reject('clock_kernel_sleep_unverified');
  }
}
