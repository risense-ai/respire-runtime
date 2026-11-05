import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawn, execFileSync} from 'node:child_process';
import {chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync} from 'node:fs';
import {isAbsolute, join, relative, resolve, sep, win32} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function normalizedPath(value, platform = process.platform) {
  if (platform !== 'win32') return value;
  // Node may retain the extended prefix even after resolving the same file.
  if (value.startsWith('\\\\?\\UNC\\')) value = '\\\\' + value.slice(8);
  else if (value.startsWith('\\\\?\\') && /^[A-Za-z]:\\/.test(value.slice(4))) value = value.slice(4);
  return win32.normalize(value);
}
function assertSamePath(actual, expected, platform = process.platform) {
  assert.equal(normalizedPath(actual, platform), normalizedPath(expected, platform));
}
function safePath(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 1024 &&
    !/[\\:\x00-\x1f\x7f]/.test(value) &&
    value.split('/').every(part => part && part !== '.' && part !== '..');
}
function archiveArgs(mode, archiveFile, destination) {
  // GNU tar treats a drive-letter archive path as a remote host.
  assert.ok(safePath(archiveFile) && !archiveFile.includes('/'), 'archive must be a relative filename');
  return [mode, archiveFile, ...(destination ? ['-C', destination] : [])];
}
function archiveTool(platform, systemRoot) {
  if (platform !== 'win32') return 'tar';
  assert.ok(typeof systemRoot === 'string' && systemRoot.trim() && win32.isAbsolute(systemRoot),
    'Windows smoke requires an absolute SystemRoot; refusing PATH tar');
  // Git's GNU tar cannot interpret native Windows extraction directories.
  return win32.join(systemRoot, 'System32', 'tar.exe');
}
function assertNativeIntel({runnerArch, platform, arch, arm64, translated}) {
  assert.equal(runnerArch, 'X64', 'Intel acceptance requires an X64 runner');
  assert.equal(platform, 'darwin', 'Intel acceptance requires macOS');
  assert.equal(arch, 'x64', 'Intel acceptance requires an x64 process');
  assert.ok(['', '0'].includes(arm64), 'Intel acceptance forbids ARM64 hardware');
  assert.ok(['', '0'].includes(translated), 'Intel acceptance forbids Rosetta');
}
function assertDrained(receipt, health, operationID) {
  assertProtocol(health);
  assert.equal(receipt.schema_version, 1);
  assert.equal(receipt.protocol_version, 1);
  assert.equal(receipt.operation_id, operationID);
  for (const key of ['installation_id', 'instance_id', 'pid', 'process_start_id',
    'image_sha256', 'runtime_version', 'account_id', 'generation']) {
    assert.equal(receipt[key], health[key], `final stop identity differs: ${key}`);
  }
  assertSamePath(receipt.image_path, health.image_path);
  assert.equal(receipt.state, 'drained');
  assert.deepEqual(receipt.unfinished, []);
}
function assertProtocol(health) {
  assert.equal(health.v, 1, 'Runtime wire protocol differs from the frozen contract');
  assert.deepEqual(health.protocol_range, {minimum: 1, maximum: 1});
}
function modelRequest(health, phase, args) {
  return {v: 1, id: `smoke-model-${phase}`, operation_id: `smoke-model-${phase}-operation`,
    idempotency_key: `smoke-model-${phase}-key`,
    scope: Object.fromEntries(['account_id', 'instance_id', 'generation'].map(key => [key, health[key]])),
    method: 'cli.exec', args: ['--json', 'model', 'engine', ...args]};
}
function assertModelResponse(reply, request, health) {
  assert.equal(reply.v, 1);
  for (const key of ['id', 'operation_id', 'idempotency_key', 'scope']) {
    assert.deepEqual(reply[key], request[key], `model response differs: ${key}`);
  }
  assert.equal(reply.pid, health.pid);
  assert.equal(reply.ok, true);
  assert.equal(reply.exit, 0);
  assert.equal(reply.error, null);
  assert.equal(reply.code, null);
  assert.equal(reply.envelope?.command, 'model');
  assert.equal(reply.envelope?.status, 'ok');
  assert.deepEqual(reply.envelope?.errors, []);
  const summary = reply.envelope.summary;
  assert.equal(summary.engine, 'cpu');
  assert.equal(summary.model, 'quantized');
  assert.equal(summary.active_selection, null);
  assert.ok(Array.isArray(summary.variants));
  assert.equal(summary.variants.filter(variant => variant.name === 'quantized').length, 1);
  assert.ok(summary.variants.every(variant => variant.state === 'baseline_missing'));
  return summary;
}
if (process.argv.includes('--self-check')) {
  const windowsImage = 'D:\\payload\\rsrs-runtime.exe';
  assertSamePath('\\\\?\\D:\\payload\\rsrs-runtime.exe', windowsImage, 'win32');
  assertSamePath('D:/payload/rsrs-runtime.exe', windowsImage, 'win32');
  assertSamePath('\\\\?\\UNC\\server\\share\\rsrs-runtime.exe', '\\\\server\\share\\rsrs-runtime.exe', 'win32');
  for (const foreign of ['\\\\?\\D:\\foreign\\rsrs-runtime.exe', '\\\\?\\E:\\payload\\rsrs-runtime.exe',
    '\\\\?\\D:\\payload\\foreign.exe', '\\\\?\\UNC\\server\\foreign\\rsrs-runtime.exe']) {
    assert.throws(() => assertSamePath(foreign, windowsImage, 'win32'));
  }
  assert.throws(() => assertSamePath('\\\\?\\UNC\\foreign\\share\\rsrs-runtime.exe',
    '\\\\server\\share\\rsrs-runtime.exe', 'win32'));
  assert.throws(() => assertSamePath('/foreign/runtime', '/fixture/runtime', 'linux'));
  assert.equal(archiveTool('win32', 'C:\\Windows'), 'C:\\Windows\\System32\\tar.exe');
  assert.equal(archiveTool('win32', 'D:/Windows'), 'D:\\Windows\\System32\\tar.exe');
  for (const root of [undefined, null, '', ' ', 'Windows', 'C:Windows']) {
    assert.throws(() => archiveTool('win32', root), /requires an absolute SystemRoot/);
  }
  for (const platform of ['linux', 'darwin']) assert.equal(archiveTool(platform, undefined), 'tar');
  const archiveFile = 'rsrs-runtime-x86_64-pc-windows-msvc.tar.gz';
  for (const mode of ['-tzf', '-tvzf', '-xzf']) {
    assert.deepEqual(archiveArgs(mode, archiveFile), [mode, archiveFile]);
    for (const unsafe of [`D:\\assets\\${archiveFile}`, `C:/assets/${archiveFile}`, '../escape', '/absolute']) {
      assert.throws(() => archiveArgs(mode, unsafe));
    }
  }
  assert.deepEqual(archiveArgs('-xzf', archiveFile, 'D:\\temp\\payload'),
    ['-xzf', archiveFile, '-C', 'D:\\temp\\payload']);
  const intel = {runnerArch: 'X64', platform: 'darwin', arch: 'x64', arm64: '', translated: ''};
  assertNativeIntel(intel);
  assertNativeIntel({...intel, arm64: '0', translated: '0'});
  for (const invalid of [{runnerArch: 'ARM64'}, {platform: 'linux'}, {arch: 'arm64'},
    {arm64: '1'}, {translated: '1'}, {arm64: 'unknown'}, {translated: 'unknown'}]) {
    assert.throws(() => assertNativeIntel({...intel, ...invalid}));
  }
  for (const value of ['../escape', '/absolute', 'a\\b', 'a/../b', 'C:stream', 'a\nb', 'a//b']) {
    assert.equal(safePath(value), false);
  }
  assert.equal(safePath('lib/provider.json'), true);
  const health = {v: 1, protocol_range: {minimum: 1, maximum: 1}, installation_id: 'i', instance_id: 'n', pid: 2, process_start_id: 'b',
    image_path: '/fixture/runtime', image_sha256: 'a'.repeat(64), runtime_version: '1.2.3',
    account_id: 'a', generation: 1};
  const receipt = {...health, schema_version: 1, protocol_version: 1, operation_id: 'o', state: 'drained', unfinished: []};
  assertDrained(receipt, health, 'o');
  assert.throws(() => assertDrained({...receipt, image_path: '/foreign/runtime'}, health, 'o'));
  assert.throws(() => assertDrained({...receipt, generation: 2}, health, 'o'));
  assert.throws(() => assertDrained({...receipt, unfinished: [{operation_id: 'x', result: 'unknown'}]}, health, 'o'));
  assert.throws(() => assertDrained({...receipt, protocol_version: 2}, {...health, v: 2}, 'o'));
  assert.throws(() => assertDrained({...receipt, protocol_version: undefined}, {...health, v: undefined}, 'o'));
  assert.throws(() => assertProtocol({...health, protocol_range: {minimum: 1, maximum: 2}}));
  const request = modelRequest(health, 'save', ['cpu', '--model', 'quantized']);
  assert.deepEqual(request, {v: 1, id: 'smoke-model-save', operation_id: 'smoke-model-save-operation',
    idempotency_key: 'smoke-model-save-key', scope: {account_id: 'a', instance_id: 'n', generation: 1},
    method: 'cli.exec', args: ['--json', 'model', 'engine', 'cpu', '--model', 'quantized']});
  assert.deepEqual(modelRequest(health, 'read', []).args, ['--json', 'model', 'engine']);
  const reply = {...request, pid: health.pid, ok: true, exit: 0, error: null, code: null,
    envelope: {command: 'model', status: 'ok', errors: [], summary: {engine: 'cpu', model: 'quantized',
      active_selection: null, variants: [{name: 'quantized', state: 'baseline_missing'}]}}};
  assertModelResponse(reply, request, health);
  for (const invalid of [{v: 2}, {id: 'foreign'}, {operation_id: 'foreign'}, {idempotency_key: 'foreign'},
    {scope: {...request.scope, generation: 2}}, {pid: 3}, {ok: false}, {exit: 1}, {error: 'failed'}, {code: 'failed'}]) {
    assert.throws(() => assertModelResponse({...reply, ...invalid}, request, health));
  }
  for (const invalid of [{command: 'status'}, {status: 'fail'}, {errors: ['failed']},
    ...[{engine: 'gpu'}, {model: 'fp16'}, {active_selection: {}}, {variants: []},
      {variants: [{name: 'quantized', state: 'ready'}]}].map(value => ({summary: {...reply.envelope.summary, ...value}}))]) {
    assert.throws(() => assertModelResponse({...reply, envelope: {...reply.envelope, ...invalid}}, request, health));
  }
  console.log('Smoke validator self-check passed; no binary, archive or endpoint was accessed.');
  process.exit(0);
}
if (process.argv.includes('--check-native-intel')) {
  assert.equal(process.env.GITHUB_ACTIONS, 'true', 'native Intel evidence requires a GitHub runner');
  assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted', 'native Intel evidence requires a hosted runner');
  // -i ignores an absent OID; other sysctl failures still abort the guard.
  const sysctl = name => execFileSync('/usr/sbin/sysctl', ['-in', name], {encoding: 'utf8'}).trim();
  assertNativeIntel({runnerArch: process.env.RUNNER_ARCH, platform: process.platform, arch: process.arch,
    arm64: sysctl('hw.optional.arm64'), translated: sysctl('sysctl.proc_translated')});
  console.log('Native Intel macOS evidence verified; ARM64 hardware and Rosetta are forbidden.');
  process.exit(0);
}

// A dedicated native CI runner is required; this script must not run on a developer host.
assert.equal(process.env.GITHUB_ACTIONS, 'true', 'release smoke requires a dedicated GitHub runner');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted', 'release smoke requires an ephemeral hosted runner');
assert.ok(isAbsolute(process.env.RUNNER_TEMP ?? ''), 'RUNNER_TEMP must be absolute');
const target = process.env.RUNTIME_TARGET, version = process.env.RUNTIME_VERSION;
assert.match(target ?? '', /^[A-Za-z0-9_-]+$/);
assert.match(version ?? '', /^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/);
const assets = resolve('release-assets');
const metadata = JSON.parse(readFileSync(join(assets, `runtime-build-${target}.json`), 'utf8'));
assert.equal(metadata.schema_version, 2);
assert.equal(metadata.target_triple, target);
assert.equal(metadata.runtime_version, version);
assert.deepEqual(metadata.protocol_range, {minimum: 1, maximum: 1});
assert.equal(metadata.capabilities?.business_executor, '1');
assert.equal(metadata.capabilities?.mcp_server, '1');
assert.equal(metadata.archive_file, `rsrs-runtime-${target}.tar.gz`);
assert.ok(safePath(metadata.binary_file) && !metadata.binary_file.includes('/'));
assert.match(metadata.binary_sha256 ?? '', /^[a-f0-9]{64}$/);
assert.equal(digest(readFileSync(join(assets, metadata.archive_file))), metadata.archive_sha256);
const root = mkdtempSync(join(process.env.RUNNER_TEMP, 'respire-runtime-smoke-'));
const temporaryRelative = relative(normalizedPath(realpathSync(process.env.RUNNER_TEMP)), normalizedPath(realpathSync(root)));
assert.ok(temporaryRelative && !isAbsolute(temporaryRelative) && temporaryRelative.split(sep).every(part => part !== '..'));
const payload = join(root, 'payload'), dataDir = join(root, 'data'), modelDir = join(root, 'empty-models');
mkdirSync(payload);
mkdirSync(dataDir);
mkdirSync(modelDir);
let child, exitState, spawnError;
const reportPath = resolve('smoke-report', `runtime-smoke-${target}.json`);
const report = {target, version, source_commit: metadata.source_commit,
  run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
  archive_sha256: metadata.archive_sha256, binary_sha256: metadata.binary_sha256,
  coverage: ['complete-release-payload', 'os-bound-startup-health', 'scoped-model-settings-no-assets', 'normal-stop-final-receipt'],
  g1Passed: false, passed: false};
try {
  const tar = archiveTool(process.platform, process.env.SystemRoot);
  const archive = metadata.archive_file;
  const names = execFileSync(tar, archiveArgs('-tzf', archive), {cwd: assets, encoding: 'utf8', maxBuffer: 2 << 20})
    .trim().split(/\r?\n/).filter(Boolean);
  assert.ok(names.length > 0 && names.length <= 4096);
  const seen = new Set();
  for (const raw of names) {
    const name = raw.replace(/^\.\//, '').replace(/\/$/, '');
    if (name === '' || name === '.') continue;
    assert.ok(safePath(name), `unsafe archive path: ${JSON.stringify(name)}`);
    assert.ok(!seen.has(name.toLowerCase()), `duplicate archive path: ${name}`);
    seen.add(name.toLowerCase());
  }
  const listing = execFileSync(tar, archiveArgs('-tvzf', archive), {cwd: assets, encoding: 'utf8', maxBuffer: 4 << 20}).trim().split(/\r?\n/);
  assert.equal(listing.length, names.length);
  for (const line of listing) {
    assert.ok(/^[d-]/.test(line) && !line.includes(' -> ') && !line.includes(' link to '),
      'release smoke accepts only regular files and directories');
  }
  execFileSync(tar, archiveArgs('-xzf', archive, payload), {cwd: assets, stdio: 'pipe'});
  assert.ok(Array.isArray(metadata.files) && metadata.files.length > 0);
  const expected = new Set();
  for (const entry of metadata.files) {
    assert.ok(safePath(entry.path));
    assert.ok(!expected.has(entry.path.toLowerCase()), 'duplicate release metadata file');
    expected.add(entry.path.toLowerCase());
    const file = join(payload, ...entry.path.split('/')), stat = lstatSync(file);
    assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1);
    assert.ok(Number.isSafeInteger(entry.size) && entry.size >= 0);
    assert.equal(stat.size, entry.size);
    assert.equal(digest(readFileSync(file)), entry.sha256);
  }
  const actual = [];
  function walk(directory, prefix = '') {
    for (const item of readdirSync(directory, {withFileTypes: true})) {
      const name = prefix + item.name;
      if (item.isDirectory()) walk(join(directory, item.name), name + '/');
      else {
        assert.ok(item.isFile() && !item.isSymbolicLink());
        actual.push(name.toLowerCase());
      }
    }
  }
  walk(payload);
  assert.deepEqual(actual.sort(), [...expected].sort());
  const executable = join(payload, metadata.binary_file);
  assert.equal(digest(readFileSync(executable)), metadata.binary_sha256);
  chmodSync(executable, 0o755);
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^RSRS_/i.test(key) && !/^(GH_TOKEN|GITHUB_TOKEN|RSRS_CORE_SDK_DIR|ONEMEMORY_CORE_SDK_DIR|RESPIRE_CORE_SDK_DIR)$/i.test(key)));
  Object.assign(environment, {RSRS_DATA_DIR: dataDir, RSRS_M3_DIR: modelDir, RSRS_BIN_DIR: payload,
    RSRS_CLIENT_ONLY: '0', RSRS_NO_AUTOSTART: '0'});
  const port = 15000 + (process.pid % 20000), endpoint = `http://127.0.0.1:${port}`;
  child = spawn(executable, ['serve', '--host', '127.0.0.1', '--port', String(port), '--data-dir', dataDir],
    {cwd: payload, env: environment, stdio: ['ignore', 'ignore', 'inherit']});
  const exited = new Promise(resolveExit => child.once('exit', (code, signal) => {
    exitState = {code, signal};
    resolveExit(exitState);
  }));
  child.once('error', error => { spawnError = error; });
  let health;
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError;
    assert.equal(exitState, undefined, 'Runtime exited before readiness');
    let response;
    try {
      response = await fetch(`${endpoint}/api/health`, {signal: AbortSignal.timeout(3000)});
    } catch {
      await delay(250);
      continue;
    }
    assert.ok(response.ok, `health HTTP ${response.status}`);
    const candidate = await response.json();
    assertProtocol(candidate);
    assert.equal(candidate.pid, child.pid);
    assert.equal(candidate.image_sha256, metadata.binary_sha256);
    assertSamePath(realpathSync(candidate.image_path), realpathSync(executable));
    assertSamePath(realpathSync(candidate.installation_root), realpathSync(dataDir));
    assert.equal(candidate.runtime_version, version);
    assert.ok(Array.isArray(candidate.capabilities) &&
      ['business_executor', 'mcp_server'].every(capability => candidate.capabilities.includes(capability)));
    assert.equal(candidate.runtime?.runtime_compat?.min_cli, process.env.EXPECTED_MIN_CLI);
    assert.equal(candidate.runtime?.runtime_compat?.max_cli, process.env.EXPECTED_MAX_CLI);
    if (candidate.store_ready === true && candidate.state === 'ready') { health = candidate; break; }
    assert.ok(['starting', 'ready'].includes(candidate.state));
    await delay(250);
  }
  assert.ok(health, 'Runtime did not become ready');
  assert.match(health.instance_id ?? '', /^[A-Za-z0-9_-]{1,128}$/);
  assert.ok(health.installation_id && health.account_id && health.process_start_id);
  assert.ok(Number.isSafeInteger(health.generation) && health.generation > 0);
  // Settings must commit without model assets; a self-waiting config lock must time out, not pass health-only smoke.
  assert.deepEqual(readdirSync(modelDir), []);
  report.model_settings = {};
  async function execModel(phase, args) {
    const request = modelRequest(health, phase, args);
    const evidence = report.model_settings[phase] = {request};
    const response = await fetch(`${endpoint}/api/rpc`, {method: 'POST',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request), signal: AbortSignal.timeout(30000)});
    evidence.http_status = response.status;
    evidence.body = await response.text();
    assert.ok(response.ok, `model ${phase} HTTP ${response.status}`);
    const reply = JSON.parse(evidence.body);
    const summary = assertModelResponse(reply, request, health);
    assertSamePath(realpathSync(reply.data_dir), realpathSync(dataDir));
    return summary;
  }
  const saved = await execModel('save', ['cpu', '--model', 'quantized']);
  const settingsBytes = readFileSync(join(dataDir, 'inference.json'));
  assert.match(saved.revision ?? '', /^[a-f0-9]{64}$/);
  assert.equal(digest(settingsBytes), saved.revision);
  const settings = JSON.parse(settingsBytes.toString('utf8'));
  assert.equal(settings.engine, 'cpu');
  assert.equal(settings.model, 'quantized');
  assert.equal(settings.force_cpu, false);
  await execModel('read', []);
  assert.deepEqual(readdirSync(modelDir), [], 'model settings unexpectedly installed assets');
  const response = await fetch(`${endpoint}/api/runtime/stop`, {
    method: 'POST', headers: {'Content-Type': 'application/json', 'X-Respire-Lifecycle': 'coordinator-v1'},
    body: JSON.stringify(Object.fromEntries(['installation_id', 'instance_id', 'account_id', 'generation'].map(key => [key, health[key]]))),
    signal: AbortSignal.timeout(5000),
  });
  assert.ok(response.ok);
  const accepted = await response.json();
  assert.equal(accepted.ok, true);
  assert.equal(accepted.state, 'accepted');
  assert.ok(typeof accepted.operation_id === 'string' && accepted.operation_id.length > 0);
  const result = await Promise.race([exited, delay(35000, undefined, {ref: false}).then(() => { throw new Error('Runtime drain did not finish'); })]);
  assert.equal(result.code, 0);
  assert.equal(result.signal, null);
  const receiptPath = join(dataDir, 'runtime', `stop-${health.instance_id}.json`);
  const receiptInfo = lstatSync(receiptPath);
  assert.ok(receiptInfo.isFile() && !receiptInfo.isSymbolicLink() && receiptInfo.size <= 1 << 20);
  assertDrained(JSON.parse(readFileSync(receiptPath, 'utf8')), health, accepted.operation_id);
  report.passed = true;
} catch (error) {
  report.error = String(error);
  process.exitCode = 1;
} finally {
  // Force cleanup is failure-only and never becomes a drained/pass receipt.
  if (child && !exitState) { child.kill(); report.passed = false; process.exitCode = 1; }
  mkdirSync(resolve('smoke-report'), {recursive: true});
  writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n');
  if (report.passed) rmSync(root, {recursive: true});
}
