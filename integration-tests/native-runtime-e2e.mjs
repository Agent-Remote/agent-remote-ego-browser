import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, access, rm, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const executable = process.env.EGO_BROWSER_NATIVE_EXECUTABLE;
assert(executable, 'Set EGO_BROWSER_NATIVE_EXECUTABLE to the installed native CLI');
const root = await mkdtemp(join(tmpdir(), 'egb-native-test-'));
const bridge = resolve('target/debug/ego-browser-bridge');
async function run(source, cancel = false, timeoutMs = 15000) {
  const child = spawn(bridge, ['--execution-supervisor'], {
    env: {
      EGO_BROWSER_SUPERVISED_EXECUTABLE: executable,
      EGO_BROWSER_ARTIFACT_DIR: root,
      EGO_BROWSER_SUPERVISED_NATIVE: '1',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', code => resolve(code));
  });
  child.stdout.on('data', chunk => {
    stdout += chunk;
    if (cancel && stdout.includes('CANCEL_READY')) child.stdin.end();
  });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const script = Buffer.from(source);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(script.length));
  child.stdin.write(length);
  child.stdin.write(script);
  const timeout = setTimeout(() => child.stdin.end(), timeoutMs);
  try {
    const code = await done;
    return { code, stdout, stderr };
  } finally { clearTimeout(timeout); }
}
try {
  const success = await run('console.log("NATIVE_OK", process.env.EGO_BROWSER_ARTIFACT_DIR); console.log(await help("taskSpace"));');
  assert.equal(success.code, 0, JSON.stringify(success));
  assert(success.stdout.includes('NATIVE_OK') && success.stdout.includes(root), JSON.stringify(success));
  assert(success.stdout.includes('taskSpace'), JSON.stringify(success));
  const failure = await run('console.log("before-error"); throw new Error("native-intentional-error");');
  assert.equal(failure.code, 1, JSON.stringify(failure));
  assert(failure.stdout.includes('before-error') && failure.stderr.includes('native-intentional-error'), JSON.stringify(failure));
  for (const busy of [false, true]) {
    const marker = join(root, `late-${busy}.txt`);
    const result = await run(`
      const fs = await import('node:fs/promises');
      console.log('CANCEL_READY');
      ${busy ? 'const until = Date.now() + 2000; while (Date.now() < until) {}' : 'await new Promise(resolve => setTimeout(resolve, 2000));'}
      await fs.writeFile(${JSON.stringify(marker)}, 'late-effect');
    `, true);
    assert.equal(result.code, 125, JSON.stringify(result));
    await delay(2200);
    await assert.rejects(access(marker));
  }
  const childMarker = join(root, 'late-child.txt');
  const descendant = await run(`
    const { spawn } = await import('node:child_process');
    const child = spawn(process.execPath, ['-e', ${JSON.stringify(`setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(childMarker)}, 'late'), 2000)`)}]);
    await new Promise(resolve => child.once('spawn', resolve));
    console.log('CANCEL_READY');
    await new Promise(resolve => child.once('exit', resolve));
  `, true);
  assert.equal(descendant.code, 125, JSON.stringify(descendant));
  await delay(2200);
  await assert.rejects(access(childMarker));
  const after = await run('console.log("NATIVE_STILL_AVAILABLE");');
  assert.equal(after.code, 0, JSON.stringify(after));
  assert(after.stdout.includes('NATIVE_STILL_AVAILABLE'));
  console.log('Native runtime: output, errors, environment, async/CPU/descendant cancellation, shared host survival passed');
  if (process.env.EGO_BROWSER_NATIVE_TEST_SCRIPT) {
    const additional = await run(await readFile(process.env.EGO_BROWSER_NATIVE_TEST_SCRIPT, 'utf8'), false, 90000);
    console.log(additional.stdout);
    assert.equal(additional.code, 0, JSON.stringify(additional));
  }
  if (process.env.EGO_BROWSER_NATIVE_TASK_SPACE) {
    const adapter = await readFile('crates/local-bridge/src/helper_adapter.js', 'utf8');
    const config = { socket: null, taskSpace: process.env.EGO_BROWSER_NATIVE_TASK_SPACE, artifactDir: root };
    const pageTest = await run(`${adapter}
      await installRemoteHelpers(${JSON.stringify(config)});
      const task = await taskSpace('ignored-user-supplied-name');
      console.log('TEST_TASK_SPACE', task.spaceId, task.name);
      const page = task.page('p1');
      await page.goto('http://127.0.0.1:18765/');
      const expectedPort = '18765';
      await page.waitForURL(url => url.port === expectedPort, {timeout: 1000});
      await page.waitForURL(/127\\.0\\.0\\.1:18765/, {timeout: 1000});
      console.log(await page.snapshot());
      console.log('TITLE', await page.title());
      console.log('EVALUATE', await page.evaluate(() => document.title));
      console.log('SCREENSHOT', await page.screenshot({path:'/tmp/ignored-remote-path.png'}));
      try { await page.setInputFiles('input[type=file]', '/tmp/not-allowed.txt'); throw new Error('upload was not guarded'); }
      catch(error) { if (!error.message.includes('allowlist is not configured')) throw error; console.log('UPLOAD_REJECTED'); }
      console.log('PAGE_DONE');
    `);
    assert.equal(pageTest.code, 0, JSON.stringify(pageTest));
    assert(pageTest.stdout.includes('PAGE_DONE') && pageTest.stdout.includes('UPLOAD_REJECTED'), JSON.stringify(pageTest));
    const screenshots = (await readdir(root)).filter(name => name.endsWith('.png'));
    assert.equal(screenshots.length, 1);
    const bytes = await readFile(join(root, screenshots[0]));
    assert(bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])));
    console.log(pageTest.stdout);
    console.log('Native Page API: canonical TaskSpace, page, navigation, snapshot, title, evaluate, screenshot collector, upload rejection passed');
  }
} finally { await rm(root, { recursive: true, force: true }); }
