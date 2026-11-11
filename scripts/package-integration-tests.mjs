import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmodSync, copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync} from 'node:fs';
import {arch, platform, tmpdir} from 'node:os';
import {isAbsolute, join, relative, resolve, sep} from 'node:path';
import {spawnSync} from 'node:child_process';
import {auditSdkDirectory, canonicalEntry, planCaches} from './sdk-ci-cache.mjs';

const repository = 'risense-ai/respire-runtime';
const features = ['cpu-owned-ort-experiment'];
const targets = [
  {target: 'x86_64-unknown-linux-gnu', os: 'ubuntu-24.04', platform: 'linux', arch: 'x64'},
  {target: 'x86_64-unknown-linux-musl', os: 'ubuntu-24.04', platform: 'linux', arch: 'x64'},
  {target: 'aarch64-unknown-linux-gnu', os: 'ubuntu-24.04-arm', platform: 'linux', arch: 'arm64'},
  {target: 'aarch64-unknown-linux-musl', os: 'ubuntu-24.04-arm', platform: 'linux', arch: 'arm64'},
  {target: 'x86_64-pc-windows-msvc', os: 'windows-latest', platform: 'win32', arch: 'x64'},
  {target: 'aarch64-pc-windows-msvc', os: 'windows-11-arm', platform: 'win32', arch: 'arm64'},
  {target: 'aarch64-apple-darwin', os: 'macos-latest', platform: 'darwin', arch: 'arm64'},
];
const businessTests = [
  'account::authorization_preserves_and_commits_profiles',
  'account::space_create_list_use_remove',
  'account::spaces_coordinate_with_the_owned_runtime',
  'capture_main::memory_revision_without_runtime_fails_without_local_business_fallback',
  'capture_main::residual_host_and_parser_errors_remain_user_errors',
  'diary_identity::canonical_identity_merges_legacy_tracks_without_touching_other_users_or_days',
  'diary_identity::concurrent_same_day_client_commands_preserve_each_successful_addition_once',
  'diary_identity::deleted_stable_track_uses_legacy_fallback_and_deleted_history_is_not_resurrected',
  'diary_identity::environment_key_fallback_does_not_adopt_unlocked_profile_alias',
  'diary_identity::explicit_titles_preserve_entries_and_leave_the_daily_track_unchanged',
  'diary_identity::important_remember_pending_candidates_preserve_ciphertext_and_outbox',
  'diary_identity::missing_entry_and_usage_failures_have_machine_diagnostics',
  'diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay',
  'diary_identity::old_owner_normalized_diary_keeps_its_author_after_public_title_edit',
  'diary_identity::public_title_edit_and_blank_title_still_append_without_changing_metadata',
  'diary_identity::remember_public_payload_covers_created_appended_and_merged',
  'diary_identity::unrelated_canonical_author_fails_without_writes_or_private_output',
  'memory_revision::memory_revision_direct_is_model_free_and_follows_resolved_profile',
  'memory_revision::memory_revision_direct_respects_client_only_policy',
  'memory_revision::memory_revision_does_not_initialize_or_autostart',
  'memory_revision::memory_revision_does_not_recover_interrupted_login',
  'memory_revision::memory_revision_legacy_database_and_ambiguous_names',
  'memory_revision::memory_revision_preserves_legacy_environment_alias',
  'snapshot_lifecycle::concurrent_host_recover_cannot_interleave_with_restore_commit',
  'snapshot_lifecycle::healthy_snapshot_rescue_preserves_unparseable_current_witness',
  'snapshot_lifecycle::public_empty_recall_returns_its_query_log_identity',
  'snapshot_lifecycle::public_feedback_attribution_uses_exact_request_and_refuses_readonly_writes',
  'snapshot_lifecycle::public_snapshot_restore_reopens_runtime_and_keeps_sync_quarantined',
  'snapshot_lifecycle::public_witness_verifies_restored_chain_and_reports_tamper_without_writes',
  'snapshot_lifecycle::queued_direct_resume_rechecks_maintenance_after_library_ownership_wait',
  'snapshot_lifecycle::staged_store_open_failure_cannot_pass_boot_readiness_and_is_recoverable',
];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function producerReceipt(sourceSha) {
  const workflow = '.github/workflows/prebuilt-integration-tests.yml';
  assert.equal(process.env.GITHUB_WORKFLOW_REF, `${repository}/${workflow}@refs/heads/main`);
  const receipt = {source_sha: sourceSha, workflow, workflow_sha: process.env.GITHUB_SHA};
  assert.match(receipt.workflow_sha ?? '', /^[a-f0-9]{40}$/);
  for (const [key, variable] of [['run_id', 'GITHUB_RUN_ID'], ['run_attempt', 'GITHUB_RUN_ATTEMPT']]) {
    assert.match(process.env[variable] ?? '', /^[1-9][0-9]*$/);
    receipt[key] = Number(process.env[variable]);
    assert.ok(Number.isSafeInteger(receipt[key]), 'Producer IDs must be positive safe integers');
  }
  return receipt;
}
function run(command, args, options = {}) {
  const result = spawnSync(command, args, {encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...options});
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    throw new Error(`${command} failed (exit ${result.status}, signal ${result.signal})`);
  }
  return result.stdout;
}
function locks(root, sourceSha) {
  const paths = ['sdk/core-sdk.lock.json', 'crates/core-sdk/core-sdk.lock.json'];
  const blobs = paths.map(path => run('git', ['cat-file', 'blob', `${sourceSha}:${path}`],
    {cwd: root, encoding: null}));
  assert.deepEqual(blobs[0], blobs[1], 'SDK lock Git blobs differ');
  for (const [index, path] of paths.entries()) {
    assert.deepEqual(readFileSync(join(root, path)), blobs[index],
      `SDK lock checkout bytes differ from the reviewed Git blob: ${path}; check line-ending conversion`);
  }
  const bytes = blobs[0];
  return {bytes, value: JSON.parse(bytes)};
}
function plan(rootLock, crateLock) {
  const bytes = readFileSync(rootLock);
  assert.deepEqual(bytes, readFileSync(crateLock), 'SDK lock bytes differ');
  const cachePlan = planCaches(JSON.parse(bytes), JSON.parse(readFileSync(crateLock)));
  return {include: targets.map(native => {
    const entry = cachePlan.include.find(item => item.target === native.target);
    assert.ok(entry, `Missing SDK cache plan for ${native.target}`);
    return {...native, key: entry.key, archive_key: entry.archive_key, sdk_lock_sha256: hash(bytes)};
  })};
}
function inventory(root, directory = root) {
  return readdirSync(directory).sort().flatMap(name => {
    assert.ok(name !== '.' && name !== '..' && !name.includes('\\'), 'Unsafe bundle path');
    const path = join(directory, name), stat = lstatSync(path);
    assert.ok(!stat.isSymbolicLink(), 'Bundle links are forbidden');
    if (stat.isDirectory()) return inventory(root, path);
    assert.ok(stat.isFile(), 'Bundle entries must be ordinary files');
    return [{path: relative(root, path).split(sep).join('/'), size: stat.size, sha256: hash(readFileSync(path))}];
  });
}
function build(source, target, sourceSha, lockHash, output) {
  assert.match(sourceSha, /^[a-f0-9]{40}$/);
  assert.match(lockHash, /^[a-f0-9]{64}$/);
  assert.equal(process.env.CORE_SDK_READ_TOKEN ?? '', '', 'Build must not hold private SDK credentials');
  assert.equal(process.env.GH_TOKEN ?? '', '', 'Build must not hold GitHub API credentials');
  assert.equal(process.env.GITHUB_TOKEN ?? '', '', 'Build must not hold GitHub API credentials');
  const producer = producerReceipt(sourceSha);
  source = realpathSync(source);
  output = resolve(output);
  assert.equal(run('git', ['rev-parse', 'HEAD'], {cwd: source}).trim(), sourceSha);
  const native = targets.find(item => item.target === target);
  assert.ok(native && native.platform === platform() && native.arch === arch(), 'Native target hardware is required');
  if (platform() === 'win32') {
    // Preserve normal WinML license CRLF; only SDK identities require raw Git bytes.
    for (const path of ['sdk/core-sdk.lock.json', 'crates/core-sdk/core-sdk.lock.json']) {
      writeFileSync(join(source, path), run('git', ['cat-file', 'blob', `${sourceSha}:${path}`],
        {cwd: source, encoding: null}));
    }
  }
  const lock = locks(source, sourceSha);
  assert.equal(hash(lock.bytes), lockHash, 'SDK lock differs from the trusted plan');
  const sdk = join(source, '.sdk', target);
  auditSdkDirectory(sdk, target, canonicalEntry(target, lock.value.targets[target]));
  assert.ok(!existsSync(output), 'Bundle output must be fresh');
  const bin = join(output, 'bin');
  mkdirSync(bin, {recursive: true});
  const targetDir = join(source, 'target', 'prebuilt-integration-tests');
  const release = target.endsWith('-musl');
  const env = {...process.env, RSRS_CORE_SDK_DIR: sdk};
  const base = ['--locked', '--target', target, '--target-dir', targetDir, '--message-format=json',
    ...(release ? ['--release'] : [])];
  const roles = {};
  const definitions = [
    ['business_tests', 'respire_commands', ['--example', 'cli_business_tests'], 'cli_business_tests', true, 'respire_app/cpu-owned-ort-experiment'],
    // The facade re-exports snapshot; its unit tests belong to the domain crate.
    ['app_tests', 'respire_app_domain', ['--lib'], 'respire_app_domain', true, 'cpu-owned-ort-experiment'],
    ['storage_tests', 'respire_storage', ['--lib'], 'respire_storage', true, 'respire_core_sdk/cpu-owned-ort-experiment'],
    ['feedback_contract_probe', 'respire_commands', ['--example', 'feedback_contract_probe'], 'feedback_contract_probe', false, 'respire_app/cpu-owned-ort-experiment'],
    ['ablation_bench', 'respire_commands', ['--example', 'ablation_bench'], 'ablation_bench', false, 'respire_app/cpu-owned-ort-experiment'],
  ];
  for (const [role, packageName, selection, name, test, feature] of definitions) {
    const args = [test ? 'test' : 'build', ...base, '-p', packageName, ...selection,
      '--features', feature, ...(test ? ['--no-run'] : [])];
    const text = run('cargo', args, {cwd: source, env, stdio: ['ignore', 'pipe', 'inherit']});
    const records = text.trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
    const artifacts = records.filter(record => record.reason === 'compiler-artifact' &&
      record.target?.name === name && record.profile?.test === test && record.executable);
    assert.equal(artifacts.length, 1, `Require one actual Cargo executable for ${role}`);
    const executable = realpathSync(artifacts[0].executable);
    const buildRelative = relative(targetDir, executable);
    assert.ok(!isAbsolute(buildRelative) && !buildRelative.startsWith('..'), 'Executable escaped its build directory');
    assert.ok(lstatSync(executable).isFile(), 'Role executable must be a file');
    roles[role] = `bin/${role}${platform() === 'win32' ? '.exe' : ''}`;
    copyFileSync(executable, join(output, roles[role]));
    chmodSync(join(output, roles[role]), 0o755);
  }
  run(process.execPath, [join(source, 'scripts/stage-core-runtime.mjs'), bin], {cwd: source, env, stdio: 'inherit'});
  const files = inventory(output);
  assert.ok(files.some(file => file.path === 'bin/core-runtime.json'), 'Missing staged Core payload inventory');
  assert.ok(files.every(file => file.path.startsWith('bin/')), 'Only role binaries and staged runtime payload may be bundled');
  const temporary = mkdtempSync(join(tmpdir(), 'runtime-test-relocation-'));
  let app, storage;
  try {
    const relocated = join(temporary, 'bundle');
    cpSync(output, relocated, {recursive: true, errorOnExist: true, force: false});
    assert.deepEqual(inventory(relocated), files, 'Relocation must retain every role, dependency and notice');
    const probeEnv = {...process.env, RSRS_CORE_TEST_MODE: '1',
      RSRS_DATA_DIR: join(temporary, 'data'), RSRS_M3_DIR: join(temporary, 'models')};
    for (const key of ['RSRS_CORE_SDK_DIR', 'ONEMEMORY_CORE_SDK_DIR', 'RESPIRE_CORE_SDK_DIR',
      'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'DYLD_FALLBACK_LIBRARY_PATH']) delete probeEnv[key];
    const list = role => run(join(relocated, roles[role]), ['--list'], {cwd: relocated, env: probeEnv})
      .split(/\r?\n/).filter(line => line.endsWith(': test')).map(line => line.slice(0, -6)).sort();
    assert.deepEqual(list('business_tests'), businessTests, 'Require all 31 exact existing business assertions');
    app = list('app_tests').filter(name => name.startsWith('snapshot::tests::'));
    storage = list('storage_tests').filter(name => name.startsWith('transport::local::sync::diary_tests::'));
    assert.ok(app.length > 0 && storage.length > 0, 'Existing libtest filters must select actual tests');
    for (const [role, name] of [
      ['app_tests', 'snapshot::tests::snapshot_captures_committed_wal_excludes_grants_and_preserves_source'],
      ['storage_tests', 'transport::local::sync::diary_tests::conflict_receipt_does_not_replace_a_confirmed_diary_append'],
    ]) {
      const text = run(join(relocated, roles[role]), [name, '--exact', '--test-threads=1'],
        {cwd: relocated, env: probeEnv});
      process.stdout.write(text);
      assert.match(text, /^test result: ok\. 1 passed; 0 failed;/m, 'Relocated existing assertion must actually execute');
    }
    assert.deepEqual(inventory(relocated), files, 'Relocated validation changed the bundle payload');
  } finally {
    rmSync(temporary, {recursive: true});
  }
  assert.equal(run('git', ['rev-parse', 'HEAD'], {cwd: source}).trim(), sourceSha);
  assert.equal(hash(locks(source, sourceSha).bytes), lockHash);
  const manifest = {schema_version: 1, repository, source_sha: sourceSha, target,
    sdk_lock_sha256: lockHash, features, producer, roles, tests: {business: businessTests, app, storage}, files};
  writeFileSync(join(output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, {flag: 'wx'});
  console.log(`Packaged five roles for ${target}; relocated 31 business, ${app.length} snapshot, ${storage.length} diary tests listed; two existing model-free assertions passed. No business tests executed.`);
}
const [command, ...args] = process.argv.slice(2);
if (command === 'plan') {
  assert.equal(args.length, 2);
  console.log(JSON.stringify(plan(...args)));
} else if (command === 'build') {
  assert.equal(args.length, 5);
  build(...args);
} else {
  throw new Error('Usage: package-integration-tests.mjs plan <root-lock> <crate-lock> | build <source> <target> <source-sha> <lock-sha256> <output>');
}
