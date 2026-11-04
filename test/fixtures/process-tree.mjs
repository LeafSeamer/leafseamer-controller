import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
if (process.argv[2] === 'leaf') {
  process.stdout.write(JSON.stringify({event: 'leaf_running', pid: process.pid}) + '\n');
  setInterval(() => {}, 1000);
} else {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), 'leaf'], {stdio: ['ignore', 'inherit', 'inherit'], detached: true, windowsHide: true});
  child.unref();
  process.stdout.write(JSON.stringify({event: 'tree_running', pid: process.pid, leaf_pid: child.pid}) + '\n');
  process.stdin.on('data', () => process.exit(0));
}
