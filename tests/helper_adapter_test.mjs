import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const source = await readFile(new URL('../crates/local-bridge/src/helper_adapter.js', import.meta.url), 'utf8');
const install = Function(`${source}; return installRemoteHelpers;`)();

function fixture() {
  const calls = [];
  const page = {
    async setInputFiles(selector, files) { calls.push(['upload', files]); },
    async waitForFileChooser() { return { async setFiles(files) { calls.push(['chooser', files]); } }; },
    async waitForEvent(event) {
      return event === 'popup' ? { ...page } : { async saveAs(path) { calls.push(['download', path]); } };
    },
    async fetch(url, options) { calls.push(['fetch', options?.saveAs]); return { ok: true }; },
    async screenshot(options) { calls.push(['screenshot', options.path]); return options.path; },
  };
  const task = {
    page() { return page; }, userPage() { return page; },
    async newPage() { return { ...page }; }, async adopt(value) { return value; },
    async pages() { return [page]; }, async tabs() { return [{ page, label: 'p1' }]; },
  };
  globalThis.taskSpace = async name => { calls.push(['select', name]); return task; };
  globalThis.takeOverTaskSpace = async id => { calls.push(['takeover', id]); return task; };
  globalThis.claimTaskSpace = async id => { calls.push(['claim', id]); return task; };
  return { calls, page, task };
}

test('v2 handles enforce the guard and canonical selection while preserving explicit ownership recovery', async () => {
  const root = await mkdtemp(join(tmpdir(), 'egb-guard-'));
  const socket = join(root, 'guard.sock');
  const operations = [];
  const server = createServer({ allowHalfOpen: true }, client => {
    let text = '';
    client.on('data', chunk => { text += chunk; });
    client.on('end', () => {
      const request = JSON.parse(text);
      operations.push(request);
      const ok = request.path.startsWith('/allowed/') || request.path === '/staged/output';
      const path = request.operation === 'upload' ? '/staged/input' : '/staged/output';
      client.end(JSON.stringify({ ok, path, token: 'test-token' }));
    });
  });
  await new Promise(resolve => server.listen(socket, resolve));
  try {
    const { calls } = fixture();
    await install({ socket, taskSpace: 'agent-remote:session-test', artifactDir: root });
    const task = await taskSpace(987);
    const page = task.page('p1');
    await page.setInputFiles('input', ['/allowed/input']);
    assert.deepEqual(calls.find(item => item[0] === 'upload'), ['upload', ['/staged/input']]);
    await assert.rejects(page.setInputFiles('input', '/outside/input'), /helper file path rejected/);
    const chooser = await page.waitForFileChooser();
    await chooser.setFiles('/allowed/input');
    await assert.rejects(chooser.setFiles('/outside/input'), /helper file path rejected/);
    const download = await page.waitForEvent('download');
    await download.saveAs('/allowed/output');
    await assert.rejects(download.saveAs('/outside/output'), /helper file path rejected/);
    await page.fetch('/file', { saveAs: '/allowed/output' });
    await assert.rejects(page.fetch('/file', { saveAs: '/outside/output' }), /helper file path rejected/);
    assert.equal(operations.filter(item => item.operation === 'commit_download').length, 2);
    const screenshot = await page.screenshot({ path: '/outside/screenshot.png' });
    assert(screenshot.startsWith(root + '/screenshot-'));
    for (const child of [await task.newPage(), await page.waitForEvent('popup'), (await task.tabs())[0].page]) {
      await assert.rejects(child.setInputFiles('input', '/outside/input'), /helper file path rejected/);
    }
    await takeOverTaskSpace(7);
    await claimTaskSpace(8);
    assert.deepEqual(calls.filter(item => ['select', 'takeover', 'claim'].includes(item[0])), [
      ['select', 'agent-remote:session-test'], ['takeover', 7], ['claim', 8],
    ]);
  } finally {
    await new Promise(resolve => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

test('every v2 file helper fails closed without a policy', async () => {
  fixture();
  await install({ socket: null, taskSpace: 'agent-remote:session-test', artifactDir: '/artifacts' });
  const page = (await taskSpace('ignored')).page('p1');
  await assert.rejects(page.setInputFiles('input', '/file'), /allowlist is not configured/);
  await assert.rejects((await page.waitForFileChooser()).setFiles('/file'), /allowlist is not configured/);
  await assert.rejects((await page.waitForEvent('download')).saveAs('/file'), /allowlist is not configured/);
  await assert.rejects(page.fetch('/file', { saveAs: '/file' }), /allowlist is not configured/);
});
