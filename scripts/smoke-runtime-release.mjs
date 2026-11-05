import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawn, execFileSync} from 'node:child_process';
import {chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync} from 'node:fs';
import {isAbsolute, join, relative, resolve, sep} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
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
  assert.equal(receipt.image_path, health.image_path);
  assert.equal(receipt.state, 'drained');
  assert.deepEqual(receipt.unfinished, []);
}
function assertProtocol(health) {
  assert.equal(health.v, 1, 'Runtime wire protocol differs from the frozen contract');
  assert.deepEqual(health.protocol_range, {minimum: 1, maximum: 1});
}
if (process.argv.includes('--self-check')) {
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
  assert.throws(() => assertDrained({...receipt, generation: 2}, health, 'o'));
  assert.throws(() => assertDrained({...receipt, unfinished: [{operation_id: 'x', result: 'unknown'}]}, health, 'o'));
  assert.throws(() => assertDrained({...receipt, protocol_version: 2}, {...health, v: 2}, 'o'));
  assert.throws(() => assertDrained({...receipt, protocol_version: undefined}, {...health, v: undefined}, 'o'));
  assert.throws(() => assertProtocol({...health, protocol_range: {minimum: 1, maximum: 2}}));
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
const temporaryRelative = relative(realpathSync(process.env.RUNNER_TEMP), realpathSync(root));
assert.ok(temporaryRelative && !isAbsolute(temporaryRelative) && temporaryRelative.split(sep).every(part => part !== '..'));
const payload = join(root, 'payload'), dataDir = join(root, 'data');
mkdirSync(payload);
mkdirSync(dataDir);
let child, exitState, spawnError;
const reportPath = resolve('smoke-report', `runtime-smoke-${target}.json`);
const report = {target, version, source_commit: metadata.source_commit,
  run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT,
  archive_sha256: metadata.archive_sha256, binary_sha256: metadata.binary_sha256,
  coverage: ['complete-release-payload', 'os-bound-startup-health', 'normal-stop-final-receipt'],
  g1Passed: false, passed: false};
try {
  const archive = metadata.archive_file;
  const names = execFileSync('tar', archiveArgs('-tzf', archive), {cwd: assets, encoding: 'utf8', maxBuffer: 2 << 20})
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
  const listing = execFileSync('tar', archiveArgs('-tvzf', archive), {cwd: assets, encoding: 'utf8', maxBuffer: 4 << 20}).trim().split(/\r?\n/);
  assert.equal(listing.length, names.length);
  for (const line of listing) {
    assert.ok(/^[d-]/.test(line) && !line.includes(' -> ') && !line.includes(' link to '),
      'release smoke accepts only regular files and directories');
  }
  execFileSync('tar', archiveArgs('-xzf', archive, payload), {cwd: assets, stdio: 'pipe'});
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
  Object.assign(environment, {RSRS_DATA_DIR: dataDir, RSRS_BIN_DIR: payload, RSRS_CLIENT_ONLY: '0', RSRS_NO_AUTOSTART: '0'});
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
    assert.equal(realpathSync(candidate.image_path), realpathSync(executable));
    assert.equal(realpathSync(candidate.installation_root), realpathSync(dataDir));
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
