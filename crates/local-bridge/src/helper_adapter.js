async function installRemoteHelpers({ socket, taskSpace: dedicatedSpace, artifactDir }) {
  const net = await import('node:net');
  const path = await import('node:path');
  const { randomUUID } = await import('node:crypto');
  const guarded = new WeakSet();
  const request = async (operation, filePath, token = null) => {
    if (!socket) throw new Error('artifact_error: helper file allowlist is not configured');
    if (typeof filePath !== 'string' || !filePath) throw new Error('artifact_error: helper file path rejected');
    return await new Promise((resolve, reject) => {
      const client = net.createConnection({ path: socket });
      let response = '';
      client.setEncoding('utf8');
      client.setTimeout(5000, () => client.destroy(new Error('timeout')));
      client.on('connect', () => client.end(JSON.stringify({ operation, path: filePath, token }) + '\n'));
      client.on('data', chunk => {
        response += chunk;
        if (Buffer.byteLength(response) > 16384) client.destroy(new Error('overflow'));
      });
      client.on('error', () => reject(new Error('artifact_error: helper file validation unavailable')));
      client.on('end', () => {
        try {
          const value = JSON.parse(response);
          if (!value.ok || typeof value.path !== 'string') throw new Error('rejected');
          resolve(value);
        } catch {
          reject(new Error('artifact_error: helper file path rejected'));
        }
      });
    });
  };
  const upload = async files => Array.isArray(files)
    ? await Promise.all(files.map(async file => (await request('upload', file)).path))
    : (await request('upload', files)).path;
  const save = async (destination, write) => {
    const prepared = await request('prepare_download', destination);
    const result = await write(prepared.path);
    await request('commit_download', prepared.path, prepared.token);
    return result;
  };
  const replace = (object, name, wrap) => {
    if (typeof object[name] === 'function') {
      const original = object[name].bind(object);
      Object.defineProperty(object, name, { value: wrap(original), configurable: true, writable: true });
    }
  };
  const protect = object => {
    if (!object || typeof object !== 'object' || guarded.has(object)) return object;
    guarded.add(object);
    if (Array.isArray(object)) return object.map(protect);
    replace(object, 'setInputFiles', original => async (selector, files, ...rest) =>
      original(selector, await upload(files), ...rest));
    replace(object, 'setFiles', original => async (files, ...rest) => original(await upload(files), ...rest));
    replace(object, 'saveAs', original => async destination => save(destination, original));
    replace(object, 'fetch', original => async (url, options = {}) => options.saveAs === undefined
      ? original(url, options)
      : save(options.saveAs, destination => original(url, { ...options, saveAs: destination })));
    replace(object, 'screenshot', original => async (options = {}) => {
      // Remote callers receive the collected artifact, never a path on the Mac.
      const destination = path.join(artifactDir, `screenshot-${randomUUID()}.png`);
      return original({ ...options, path: destination });
    });
    replace(object, 'cdp', original => async (method, ...args) => {
      try { return await original(method, ...args); }
      catch (error) {
        if (method === 'Browser.getVersion' && /not found|wasn't found|not supported/i.test(error.message)) {
          throw new Error('Browser.getVersion is unavailable in this ego lite runtime; use await ego.getBrowserVersion() for the installed runtime version');
        }
        throw error;
      }
    });
    for (const name of ['page', 'userPage']) replace(object, name, original => (...args) => protect(original(...args)));
    for (const name of ['newPage', 'adopt', 'pages', 'tabs', 'waitForEvent', 'waitForFileChooser']) {
      replace(object, name, original => async (...args) => protect(await original(...args)));
    }
    // Tab descriptors carry their Page separately from the managed label.
    if (object.page && typeof object.page === 'object') protect(object.page);
    return object;
  };
  const select = globalThis.taskSpace || globalThis.useOrCreateTaskSpace;
  if (typeof select !== 'function') throw new Error('ego_runtime_unavailable: taskSpace helper unavailable');
  globalThis.taskSpace = globalThis.useOrCreateTaskSpace = async (_nameOrId, ...rest) =>
    protect(await select(dedicatedSpace, ...rest));
  // Explicit ownership recovery keeps its original target and confirmation semantics.
  for (const name of ['takeOverTaskSpace', 'claimTaskSpace']) {
    replace(globalThis, name, original => async (...args) => protect(await original(...args)));
  }
  for (const name of ['uploadFile', 'setInputFiles']) {
    replace(globalThis, name, original => async (selector, files, ...rest) =>
      original(selector, await upload(files), ...rest));
  }
  if (globalThis.download) protect(globalThis.download);
}
