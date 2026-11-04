import net from 'node:net';
const socket = net.createConnection(process.argv[2]);
socket.on('error', () => {});
setInterval(() => {}, 1000);
