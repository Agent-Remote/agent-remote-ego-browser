async function serveNativeBrowser(socket) {
  const net = await import('node:net');
  const { once } = await import('node:events');
  const client = net.createConnection({ path: socket, allowHalfOpen: true });
  client.setTimeout(5000, () => client.destroy(new Error('execution supervisor unavailable')));
  await once(client, 'connect');
  client.setTimeout(0);
  const values = new Map();
  const ids = new WeakMap();
  let nextId = 0;
  let active = true;
  const encode = value => {
    if (!value || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map(encode);
    const methods = {};
    const fields = {};
    const properties = {};
    const descriptors = new Map(Object.entries(Object.getOwnPropertyDescriptors(value))
      .filter(([, descriptor]) => descriptor.enumerable || descriptor.get || descriptor.set));
    for (let prototype = Object.getPrototypeOf(value); prototype && prototype !== Object.prototype;
      prototype = Object.getPrototypeOf(prototype)) {
      for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(prototype))) {
        if (name !== 'constructor' && !Object.hasOwn(value, name) && !descriptors.has(name)) descriptors.set(name, descriptor);
      }
    }
    for (const [name, descriptor] of descriptors) {
      // SDK accessors can change after navigation and must run only when read.
      if (descriptor.get || descriptor.set) {
        properties[name] = descriptor.enumerable;
        continue;
      }
      const item = descriptor.value;
      if (typeof item === 'function') methods[name] = ['page', 'userPage', 'help', 'url', 'suggestedFilename', 'isMultiple'].includes(name);
      else fields[name] = encode(item);
    }
    if (!Object.keys(methods).length && !Object.keys(properties).length) return fields;
    let id = ids.get(value);
    if (id === undefined) { id = ++nextId; ids.set(value, id); values.set(id, value); }
    return { kind: 'handle', id, fields, methods, properties };
  };
  const decode = value => {
    if (!value || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map(decode);
    if (value.kind === 'reference') return values.get(value.id);
    if (value.kind === 'function') return Function(`"use strict"; return (${value.source})`)();
    if (value.kind === 'regexp') return new RegExp(value.source, value.flags);
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, decode(item)]));
  };
  const helpers = { ...globalThis.ego?.helpers };
  helpers.ego = { getBrowserVersion: () => globalThis.ego.getBrowserVersion() };
  for (const name of ['taskSpace', 'useOrCreateTaskSpace', 'listTaskSpaces', 'takeOverTaskSpace', 'claimTaskSpace', 'help']) {
    if (typeof globalThis[name] === 'function') helpers[name] = globalThis[name];
  }
  // Each native invocation has its own context even when Node Helper is shared.
  // Guard SDK follow-up commands after the isolated script has been stopped.
  for (const name of Object.getOwnPropertyNames(globalThis.ego || {})) {
    if (typeof ego[name] !== 'function') continue;
    const original = ego[name].bind(ego);
    ego[name] = (...args) => {
      if (!active) throw new Error('execution_stopped');
      return original(...args);
    };
  }
  const send = value => client.write(JSON.stringify(value) + '\n');
  send({ context: encode(helpers) });
  let buffer = '';
  client.setEncoding('utf8');
  client.on('data', chunk => {
    buffer += chunk;
    if (Buffer.byteLength(buffer) > 16 * 1024 * 1024) { client.destroy(); return; }
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      void dispatch(JSON.parse(line));
    }
  });
  async function dispatch({ call, id, method, args, operation = 'call' }) {
    if (!active) return;
    let reply;
    try {
      const object = values.get(id);
      const result = operation === 'get' ? object[method] : await object[method](...decode(args));
      reply = { call, value: encode(result) };
    } catch (error) {
      reply = { call, error: { message: error?.message || String(error), details: {
        error_code: error?.error_code, executionStopped: error?.executionStopped,
        mayHaveLateEffects: error?.mayHaveLateEffects, pageResponsive: error?.pageResponsive,
      } } };
    }
    if (active) send(reply);
  }
  await new Promise(resolve => {
    client.once('end', resolve);
    client.once('error', resolve);
    client.once('close', resolve);
  });
  active = false;
  client.end();
}
