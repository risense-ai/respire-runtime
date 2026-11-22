import assert from 'node:assert/strict';
import {createCipheriv, createHash, hkdfSync, randomBytes, randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {createWriteStream, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {availableParallelism, cpus} from 'node:os';
import {join, resolve} from 'node:path';
import {createInterface} from 'node:readline';
import {setTimeout as delay} from 'node:timers/promises';

const target = 'x86_64-unknown-linux-musl';
const metadata = JSON.parse(readFileSync(`candidate/runtime-build-${target}.json`, 'utf8'));
const payload = resolve('candidate/payload');
const executable = join(payload, metadata.binary_file);
const report = {target, source: metadata.source_commit, sha256: metadata.binary_sha256,
  cpu: cpus()[0].model, availableCpus: availableParallelism(), cases: []};
const writeReport = () => writeFileSync('benchmark-report/results.json', JSON.stringify(report, null, 2));
const model = 'granite-311m-r2';
const profile = {id: model,
  embedding: {model_id: 'ibm-granite/granite-embedding-311m-multilingual-r2',
    revision: '44399559930365213510b1ee2eb15ded83374f0e',
    dimensions: 768, max_tokens: 512, pooling: 'cls', normalize: true,
    query_prefix: '', document_prefix: '', pad_token_id: 0, pad_to_max_tokens: false},
  onnx: {input_ids: 'input_ids', attention_mask: 'attention_mask', output: 'last_hidden_state'},
  weights: {path: resolve('candidate/granite.onnx'), size: 313421909,
    sha256: 'f1fdd44e7e1ac51f12ab7957c7bd092e064d596c288513bf9d326842f669edee'},
  tokenizer: {path: resolve('candidate/tokenizer.json'), size: 33384821,
    sha256: '0087c868b33bad550a78a08d19798cfd7f713cde4f020803b8f51f405503e15f'}};
report.model = profile.embedding;
const corpus = Array.from({length: 32}, (_, i) => {
  const subject = ['water treatment', 'rail scheduling', 'soil sampling', 'building ventilation'][i % 4];
  return Array.from({length: 20}, (_, j) =>
    `Exercise ${i + 1}, checkpoint ${j + 1}: The ${subject} team reviews the inspection records, checks measurements, compares the results with last week, and assigns a follow-up visit to the site coordinator.`).join(' ');
});
report.entries = corpus.length;
report.characters = corpus.reduce((sum, text) => sum + text.length, 0);

async function run(background) {
  const data = mkdtempSync('/tmp/respire-granite-');
  const models = join(data, 'empty-m3');
  mkdirSync(models);
  mkdirSync(join(data, 'runtime'));
  const entropy = randomBytes(18), salt = randomBytes(16), nonce = randomBytes(12);
  const secret = `A3-${entropy.toString('hex')}`;
  const key = hkdfSync('sha256', entropy, salt, Buffer.from('onememory:kek:v4'), 32);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const wrapped = Buffer.concat([cipher.update(randomBytes(32)), cipher.final(), cipher.getAuthTag()]);
  const session = JSON.stringify({user: 'runtime-smoke', addr: 'https://smoke.invalid',
    vault_version: 4, kdf_salt: salt.toString('hex'), urk_nonce: nonce.toString('hex'),
    wrapped_urk: wrapped.toString('hex')});
  const token = randomBytes(32).toString('hex');
  writeFileSync(join(data, 'session.json'), session, {mode: 0o600});
  writeFileSync(join(data, 'runtime', 'token'), token, {mode: 0o600});
  const port = 19720 + background, base = `http://127.0.0.1:${port}`;
  const child = spawn(executable, ['serve', '--host', '127.0.0.1', '--port', String(port), '--data-dir', data],
    {cwd: payload, stdio: ['ignore', 'ignore', 'pipe'], env: {...process.env, RSRS_DATA_DIR: data,
      RSRS_M3_DIR: models, RSRS_BIN_DIR: payload, RSRS_CLIENT_ONLY: '0', RSRS_NO_AUTOSTART: '0',
      RSRS_NO_AUTOSYNC: '1', RSRS_INTRA_THREADS: String(background), RSRS_REBUILD_TRACE: '1'}});
  const log = createWriteStream(`benchmark-report/runtime-${background}.log`);
  const traces = [];
  const lines = createInterface({input: child.stderr});
  lines.on('line', line => {
    log.write(line + '\n');
    const trace = /^\[rebuild\] (\d+)\/(\d+) chars=\d+ art=\d+B open=(\d+)ms prepare=(\d+)ms$/.exec(line);
    if (trace) {
      traces.push({item: Number(trace[1]), total: Number(trace[2]), openMs: Number(trace[3]),
        prepareMs: Number(trace[4]), observedMs: Math.round(performance.now())});
    }
  });
  const exited = new Promise(resolveExit => child.once('close', (code, signal) => resolveExit({code, signal})));
  const observation = {requestedBackground: background, traces};
  report.cases.push(observation);
  let scope;
  async function request(path, payload, headers = {}) {
    const response = await fetch(base + path, {method: payload === undefined ? 'GET' : 'POST',
      headers: {'Content-Type': 'application/json', ...headers},
      body: payload === undefined ? undefined : JSON.stringify(payload), signal: AbortSignal.timeout(15000)});
    assert.ok(response.ok, `${path} HTTP ${response.status}`);
    return response.json();
  }
  async function rpc(method, args = [], scoped = true) {
    const id = randomUUID();
    const body = {v: 1, id, method, args};
    if (scoped) Object.assign(body, {scope, operation_id: id, idempotency_key: id});
    const reply = await request('/api/rpc', body);
    assert.equal(reply.id, id);
    assert.equal(reply.ok, true, `${method}: ${JSON.stringify(reply)}`);
    return reply.envelope.summary;
  }
  try {
    let health, unlocked = false;
    for (let i = 0; i < 240; i++) {
      assert.equal(child.exitCode, null, 'Runtime exited during startup');
      try {
        health = await request('/api/health');
      } catch (error) {
        if (error.cause?.code !== 'ECONNREFUSED') throw error;
        await delay(250);
        continue;
      }
      if (health.store_ready && health.state === 'ready') break;
      if (!unlocked && health.startup_complete && health.credential_state === 'required') {
        const outcome = await request('/api/runtime/unlock', {schema_version: 1, profile: data,
          session_sha256: createHash('sha256').update(session).digest('hex'), instance_id: health.instance_id,
          generation: health.generation, super_password: secret, login_password: null},
        {Authorization: `Bearer ${token}`});
        assert.equal(outcome.store_ready, true);
        unlocked = true;
      }
      await delay(250);
    }
    assert.ok(unlocked && health?.store_ready && health.state === 'ready');
    assert.equal(health.image_sha256, metadata.binary_sha256);
    scope = Object.fromEntries(['account_id', 'instance_id', 'generation'].map(name => [name, health[name]]));
    const ids = new Set();
    for (const [i, text] of corpus.entries()) {
      const result = await rpc('cli.exec', ['--json', 'remember', text, '--importance', 'trivial',
        '--title', `Granite rebuild exercise ${i + 1}`]);
      assert.equal(typeof result.id, 'string');
      ids.add(result.id);
    }
    assert.equal(ids.size, corpus.length);
    assert.equal((await rpc('model.configure', [JSON.stringify({model_profile: profile})])).saved, true);

    const start = performance.now();
    const task = await rpc('model.switch', [JSON.stringify({model, backend: 'onnx', engine: 'cpu'})]);
    assert.equal(task.state, 'pending');
    let progress, threads, indexStart, indexEnd;
    while (performance.now() - start < 10 * 60_000) {
      progress = await rpc('model.progress', [], false);
      assert.equal(progress.switch.id, task.id);
      assert.notEqual(progress.switch.state, 'failed', JSON.stringify(progress.switch));
      if (progress.operation.phase === 'switch-index') {
        indexStart ??= performance.now();
        threads ??= (await request('/api/health')).inference?.intra_threads;
      } else if (indexStart !== undefined) {
        indexEnd ??= performance.now();
      }
      if (progress.switch.state === 'ready') break;
      await delay(250);
    }
    assert.equal(progress?.switch.state, 'ready', JSON.stringify(progress));
    assert.equal(progress.switch.result.selection.model, model);
    observation.wallMs = Math.round(performance.now() - start);
    observation.indexWallMs = Math.round(indexEnd - indexStart);
    observation.duringIndex = threads;
    observation.afterSwitch = (await request('/api/health')).inference?.intra_threads;
    observation.indexGeneration = progress.switch.result.selection.generation;
    assert.match(observation.indexGeneration, /\S/);
    assert.deepEqual(observation.duringIndex, {foreground: 1, background});
    assert.deepEqual(observation.afterSwitch, {foreground: 1, background});
    assert.ok(Number.isFinite(observation.indexWallMs) && observation.indexWallMs > 0);
    await delay(200);
    assert.deepEqual(traces.map(({item, total}) => [item, total]), corpus.map((_, i) => [i + 1, corpus.length]));
    observation.totalPrepareMs = traces.reduce((sum, trace) => sum + trace.prepareMs, 0);
    observation.entriesPerSecond = corpus.length * 1000 / observation.indexWallMs;
    console.log(JSON.stringify({...observation, traces: undefined}));
    const stop = await request('/api/runtime/stop', {...scope, installation_id: health.installation_id},
      {'X-Respire-Lifecycle': 'coordinator-v1'});
    assert.equal(stop.ok, true);
    assert.equal(stop.state, 'accepted');
    const exit = await Promise.race([exited, delay(35000, undefined, {ref: false}).then(() => {
      throw new Error('Runtime drain did not finish');
    })]);
    assert.deepEqual(exit, {code: 0, signal: null});
    const receipt = JSON.parse(readFileSync(join(data, 'runtime', `stop-${health.instance_id}.json`), 'utf8'));
    assert.equal(receipt.operation_id, stop.operation_id);
    assert.equal(receipt.state, 'drained');
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      const stopped = await Promise.race([exited.then(() => true), delay(3000).then(() => false)]);
      if (!stopped) {
        child.kill('SIGTERM');
        await exited;
      }
    }
    log.end();
    writeReport();
  }
}

await run(1);
await run(5);
assert.equal(report.cases[0].indexGeneration, report.cases[1].indexGeneration);
report.indexSpeedup = report.cases[0].indexWallMs / report.cases[1].indexWallMs;
report.prepareSpeedup = report.cases[0].totalPrepareMs / report.cases[1].totalPrepareMs;
report.passed = true;
writeReport();
console.log(`Index phase speedup: ${report.indexSpeedup.toFixed(2)}x`);
