const { Worker, MessageChannel } = require('node:worker_threads');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { unlink } = require('node:fs/promises');

(async () => {
  let source = '';
  for await (const chunk of process.stdin) source += chunk;
  const socket = process.env.EGO_BROWSER_NATIVE_SOCKET;
  const server = net.createServer({ allowHalfOpen: true });
  server.listen(socket);
  await once(server, 'listening');
  const connected = once(server, 'connection');
  const native = spawn(process.env.EGO_BROWSER_NATIVE_EXECUTABLE, ['nodejs'], { stdio: ['pipe', 'pipe', 'pipe'] });
  native.stdin.end(`${nativeHostSource}\nawait serveNativeBrowser(${JSON.stringify(socket)});`);
  native.stdout.pipe(process.stdout, { end: false });
  native.stderr.pipe(process.stderr, { end: false });
  const failed = new Promise((_, reject) => {
    native.once('error', reject);
    native.once('exit', () => reject(new Error('native browser host disconnected')));
  });
  const [client] = await Promise.race([connected, failed]);
  server.close();
  let worker;
  let port;
  let wake;
  let buffer = '';
  const finished = new Promise((resolve, reject) => {
    client.setEncoding('utf8');
    client.on('data', chunk => {
      buffer += chunk;
      if (Buffer.byteLength(buffer) > 16 * 1024 * 1024) { reject(new Error('native response exceeds limit')); return; }
      let index;
      while ((index = buffer.indexOf('\n')) >= 0) {
        let message;
        try { message = JSON.parse(buffer.slice(0, index)); } catch (error) { reject(error); return; }
        buffer = buffer.slice(index + 1);
        if (!worker) {
          if (!message.context) { reject(new Error('native context unavailable')); return; }
          const { port1, port2 } = new MessageChannel();
          port = port1;
          const signal = new SharedArrayBuffer(4);
          wake = new Int32Array(signal);
          worker = new Worker(nativeWorkerSource, {
            eval: true, stdout: true, stderr: true,
            workerData: { port: port2, signal, source, context: message.context }, transferList: [port2],
          });
          worker.stdout.pipe(process.stdout, { end: false });
          worker.stderr.pipe(process.stderr, { end: false });
          port.on('message', request => client.write(JSON.stringify(request) + '\n'));
          worker.once('message', result => { if (result.done) resolve(result.code); });
          worker.once('exit', resolve);
          worker.once('error', reject);
        } else {
          port.postMessage(message);
          Atomics.add(wake, 0, 1);
          Atomics.notify(wake, 0);
        }
      }
    });
    client.once('error', reject);
    client.once('end', () => reject(new Error('native browser host disconnected')));
  });
  let code;
  try { code = await Promise.race([finished, failed]); }
  finally {
    if (worker) await worker.terminate();
    if (port) port.close();
    client.end();
    await unlink(socket).catch(() => {});
  }
  native.removeAllListeners('exit');
  await Promise.race([once(native, 'exit'), new Promise(resolve => setTimeout(resolve, 1000))]);
  native.kill();
  process.exitCode = code;
})().catch(error => { console.error(error.message); process.exit(125); });
