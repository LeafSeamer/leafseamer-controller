import net from 'node:net';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import canonicalize from 'canonicalize';
import {createCoreBootstrapChannel} from '../../dist/core-bootstrap.mjs';
import {decodeSupervisorControl, supervisorControlVersion} from '../../dist/sdk/supervisor-control.mjs';
const args = process.argv.slice(3), options = Object.fromEntries(Array.from({length: args.length / 2}, (_, i) => [args[i * 2], args[i * 2 + 1]]));
const bootstrap = createCoreBootstrapChannel(process.stdin, process.stdout, {timeoutMs: 10000});
const assignment = await bootstrap.assignment(), receipt = await bootstrap.proveAndReceive(assignment); bootstrap.release();
const policy = JSON.parse(options['--bootstrap-policy']), mode = options['--mode'];
process.stderr.write(JSON.stringify({event: 'bootstrapped', pid: process.pid}) + '\n');
if (mode === 'peer') {
  const child = spawn(process.execPath, [fileURLToPath(new URL('./control-intruder.mjs', import.meta.url)), options['--supervisor-pipe']], {stdio: 'ignore', windowsHide: true});
  process.stderr.write(JSON.stringify({event: 'intruder', pid: child.pid}) + '\n');
  setInterval(() => {}, 1000);
} else {
  const socket = net.createConnection(options['--supervisor-pipe']);
  socket.on('error', () => {});
  const frame = {version: supervisorControlVersion, type: 'LAUNCH_QUERY',
    scope: {service_id: policy.service_id, database_instance_id: policy.database_instance_id, supervisor_instance_id: assignment.clock_domain_descriptor.supervisor_instance_id, domain_ref: receipt.domain_ref},
    channel_id: options['--supervisor-channel'], sequence: '1', message_id: 'first', reply_to: null,
    payload: {launch_id: receipt.launch_id, launch_intent_digest: receipt.launch_intent_digest}};
  if (mode === 'scope') frame.scope.database_instance_id = 'other';
  if (mode === 'channel') frame.channel_id = 'other';
  if (mode === 'sequence') frame.sequence = '2';
  if (mode === 'reply') frame.reply_to = 'unsolicited';
  if (mode === 'direction') frame.type = 'LAUNCH_RESULT';
  if (mode === 'conflict') frame.payload.launch_intent_digest = 'sha256:' + '0'.repeat(64);
  if (mode === 'missing') frame.payload.launch_id = 'missing';
  const line = canonicalize(frame) + '\n';
  socket.once('connect', () => {
    if (mode === 'disconnect') { socket.destroy(); return; }
    if (mode === 'silent') return;
    socket.write(mode === 'duplicate-key' ? line.replace('"type":', '"type":"LAUNCH_QUERY","type":') : line);
  });
  let buffer = '';
  socket.on('data', async bytes => {
    buffer += bytes; if (!buffer.endsWith('\n')) return;
    const response = await decodeSupervisorControl(Buffer.from(buffer.slice(0, -1)), mode === 'conflict' ? 'ERROR' : 'LAUNCH_RESULT'); buffer = '';
    process.stderr.write(JSON.stringify({event: 'response', sequence: response.sequence, reply_to: response.reply_to, payload: response.payload}) + '\n');
    if (mode === 'replay') socket.write(line);
  });
  process.stdin.setEncoding('utf8').on('data', data => { if (data === 'stop\n') { socket.destroy(); process.stdin.destroy(); } });
  process.stdin.resume();
}
