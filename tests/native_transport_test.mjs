import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { MessageChannel, Worker } from 'node:worker_threads';

test('native handles preserve live accessors, identity, errors, and wrapped methods', { timeout: 15000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'egb-properties-'));
  const socket = join(directory, 'native.sock');
  const hostSource = await readFile(new URL('../crates/local-bridge/src/native_host.js', import.meta.url), 'utf8');
  const workerSource = await readFile(new URL('../crates/local-bridge/src/native_worker.js', import.meta.url), 'utf8');
  const server = net.createServer();
  server.listen(socket);
  await once(server, 'listening');
  const connected = once(server, 'connection');
  const host = spawn(process.execPath, ['--input-type=module', '-e', `
    let target;
    let reads = 0;
    class Page {
      label = 'p1';
      revision = 0;
      get targetId() { return target; }
      get unavailable() { throw Object.assign(new Error('property unavailable'), {error_code: 'not_ready'}); }
      async goto(id) { target = id; this.revision++; }
      async info() { return {reads, target}; }
    }
    const page = new Page();
    Object.defineProperty(page, 'ownTarget', {get() { reads++; return target; }});
    globalThis.ego = {helpers: {page: () => page}, getBrowserVersion: () => 'fixture'};
    ${hostSource}
    await serveNativeBrowser(${JSON.stringify(socket)});
  `], { stdio: ['ignore', 'pipe', 'pipe'] });
  let errors = '';
  host.stderr.on('data', chunk => { errors += chunk; });
  let client;
  let worker;
  let port;
  try {
    [client] = await connected;
    let buffer = '';
    const done = new Promise((resolve, reject) => {
      client.setEncoding('utf8');
      client.on('data', chunk => {
        buffer += chunk;
        let index;
        while ((index = buffer.indexOf('\n')) >= 0) {
          const message = JSON.parse(buffer.slice(0, index));
          buffer = buffer.slice(index + 1);
          if (!worker) {
            const {port1, port2} = new MessageChannel();
            port = port1;
            const signal = new SharedArrayBuffer(4);
            const wake = new Int32Array(signal);
            client.wake = wake;
            worker = new Worker(workerSource, {eval: true, stdout: true, stderr: true,
              workerData: {port: port2, signal, context: message.context, source: `
                const assert = (await import('node:assert/strict')).default;
                const p = page();
                assert.equal((await p.info()).reads, 0);
                assert.equal(p.targetId, undefined);
                assert.equal(p.ownTarget, undefined);
                await p.goto('first-target');
                assert.equal(p.targetId, 'first-target');
                assert.equal(p.ownTarget, 'first-target');
                const info = p.info;
                p.info = (...args) => info(...args);
                const wrapped = p.info;
                assert.equal(page(), p);
                assert.equal(p.info, wrapped);
                assert.equal(p.revision, 1);
                assert.equal((await p.info()).reads, 2);
                assert.equal(Object.getOwnPropertyDescriptor(p, 'ownTarget').enumerable, false);
                await p.goto('second-target');
                assert.equal(p.targetId, 'second-target');
                assert.throws(() => p.unavailable, {message: 'property unavailable', error_code: 'not_ready'});
                const pending = p.info();
                assert.equal(p.targetId, 'second-target');
                assert.equal((await pending).target, 'second-target');
              `}, transferList: [port2]});
            worker.stderr.on('data', chunk => { errors += chunk; });
            port.on('message', request => client.write(JSON.stringify(request) + '\n'));
            worker.once('message', resolve);
            worker.once('error', reject);
          } else {
            port.postMessage(message);
            Atomics.add(client.wake, 0, 1);
            Atomics.notify(client.wake, 0);
          }
        }
      });
      client.once('error', reject);
      host.once('error', reject);
      host.once('exit', code => reject(new Error(`native host exited ${code}: ${errors}`)));
    });
    assert.deepEqual(await done, {done: true, code: 0}, errors);
  } finally {
    if (worker) await worker.terminate();
    port?.close();
    client?.destroy();
    host.kill();
    server.close();
    await rm(directory, {recursive: true, force: true});
  }
});
