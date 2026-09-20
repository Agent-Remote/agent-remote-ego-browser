const { parentPort, workerData, receiveMessageOnPort } = require('node:worker_threads');
const { port, signal, source, context } = workerData;
const wake = new Int32Array(signal);
const handles = new Map();
const pending = new Map();
let sequence = 0;
const encode = value => {
  if (typeof value === 'function') return { kind: 'function', source: value.toString() };
  if (!value || typeof value !== 'object') return value;
  if (value instanceof RegExp) return { kind: 'regexp', source: value.source, flags: value.flags };
  if (value.__remoteHandle !== undefined) return { kind: 'reference', id: value.__remoteHandle };
  if (Array.isArray(value)) return value.map(encode);
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encode(item)]));
};
const unwrap = reply => {
  if (reply.error) throw Object.assign(new Error(reply.error.message), reply.error.details);
  return decode(reply.value);
};
const rpc = (id, method, args, synchronous) => {
  const call = ++sequence;
  const message = { call, id, method, args: encode(args) };
  if (!synchronous) return new Promise((resolve, reject) => {
    pending.set(call, { resolve, reject });
    port.postMessage(message);
  });
  let tick = Atomics.load(wake, 0);
  port.postMessage(message);
  for (;;) {
    const reply = receiveMessageOnPort(port)?.message;
    if (reply) {
      if (reply.call === call) return unwrap(reply);
      deliver(reply);
      continue;
    }
    Atomics.wait(wake, 0, tick, 1000);
    tick = Atomics.load(wake, 0);
  }
};
const decode = value => {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(decode);
  if (value.kind !== 'handle') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, decode(item)]));
  if (handles.has(value.id)) return handles.get(value.id);
  const object = {};
  Object.defineProperty(object, '__remoteHandle', { value: value.id });
  handles.set(value.id, object);
  for (const [key, item] of Object.entries(value.fields)) object[key] = decode(item);
  for (const [method, synchronous] of Object.entries(value.methods)) {
    object[method] = (...args) => method === 'waitForURL' && typeof args[0] === 'function'
      ? waitForURLPredicate(object, ...args)
      : rpc(value.id, method, args, synchronous);
  }
  return object;
};
async function waitForURLPredicate(page, predicate, options = {}) {
  // URL predicates run in the script realm and may capture its local variables.
  const timeout = options.timeout ?? 30000;
  const deadline = Date.now() + timeout;
  for (;;) {
    const url = await page.url();
    if (predicate(new URL(url))) return;
    if (Date.now() >= deadline) throw new Error(`page.waitForURL timed out after ${timeout}ms on page ${page.label}; last URL was ${JSON.stringify(url)}`);
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}
const deliver = reply => {
  const call = pending.get(reply.call);
  if (!call) return;
  pending.delete(reply.call);
  try { call.resolve(unwrap(reply)); } catch (error) { call.reject(error); }
};
port.on('message', deliver);
Object.assign(globalThis, decode(context));
globalThis.cliLog = (...args) => console.log(...args);
(async () => {
  try {
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    await new AsyncFunction(`"use strict";\n${source}`)();
    await Promise.all([new Promise(resolve => process.stdout.write('', resolve)), new Promise(resolve => process.stderr.write('', resolve))]);
    parentPort.postMessage({ done: true, code: 0 });
  } catch (error) {
    console.error(error?.stack || String(error));
    await Promise.all([new Promise(resolve => process.stdout.write('', resolve)), new Promise(resolve => process.stderr.write('', resolve))]);
    parentPort.postMessage({ done: true, code: 1 });
  }
})();
