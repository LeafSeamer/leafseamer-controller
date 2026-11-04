// 合成不合作核心，仅用于真实继承管道与Job失败路径集成。
import canonicalize from 'canonicalize';
import {createCoreBootstrapChannel, coreProof} from '../../dist/core-bootstrap.mjs';
const args = process.argv.slice(3), options = Object.fromEntries(Array.from({length: args.length / 2}, (_, i) => [args[i * 2], args[i * 2 + 1]]));
const mode = options['--mode'];
const channel = createCoreBootstrapChannel(process.stdin, process.stdout, {timeoutMs: 10000});
const assignment = await channel.assignment();
if (mode === 'eof') { channel.close(); process.stdout.end(); process.stdin.destroy(); }
else if (mode === 'timeout') { setInterval(() => {}, 1000); }
else {
  const proof = coreProof(assignment);
  if (mode === 'proof') proof.payload.proof = 'A'.repeat(43);
  if (mode === 'role') proof.payload.role = 'worker';
  const line = canonicalize(proof) + '\n';
  process.stdout.write(mode === 'duplicate' ? line + line : line);
  setInterval(() => {}, 1000);
}
