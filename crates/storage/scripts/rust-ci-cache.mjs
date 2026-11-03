import {createHash} from 'node:crypto';
import {appendFileSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {homedir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export function cacheKey(kind, identity) {
  if (!['workspace', 'coverage'].includes(kind)) throw Error('Unknown Rust cache kind');
  return `rust-ci-v1-${kind}-${createHash('sha256').update(JSON.stringify(identity)).digest('hex')}`;
}

function metadata() {
  return JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--no-deps', '--format-version', '1'], {encoding: 'utf8'}));
}

export function releaseKey(target, identity) {
  if (!/^(?:x86_64|aarch64)-(?:unknown-linux-(?:gnu|musl)|pc-windows-msvc|apple-darwin)$/.test(target || '')) throw Error('Invalid release cache target');
  return `rust-release-v1-${target}-${createHash('sha256').update(JSON.stringify(identity)).digest('hex')}`;
}

function release(action, target) {
  releaseKey(target, {});
  const stage = '.rust-release-cache', output = '.rust-release-save';
  const registry = path.join(process.env.CARGO_HOME || path.join(homedir(), '.cargo'), 'registry');
  const paths = [['target/ci/release', 'host/release'], [`target/ci/${target}/release`, 'target/release']]
    .flatMap(([from, to]) => ['deps', 'build', '.fingerprint'].map(name => [`${from}/${name}`, `${to}/${name}`]));
  paths.push([path.join(registry, 'cache'), 'cargo/cache']);
  if (action === 'key') {
    const files = [...metadata().packages.map(p => p.manifest_path), 'Cargo.toml', 'Cargo.lock', '.cargo/config.toml', 'rust-toolchain.toml',
      'sdk/core-sdk.lock.json', 'crates/core-sdk/core-sdk.lock.json', 'scripts/rust-ci-cache.mjs',
      'scripts/build-linux-musl.sh', 'scripts/build-linux-musl-container.sh', '.github/workflows/release-validation.yml'];
    const identity = {
      target, rust: execFileSync('rustc', ['-Vv'], {encoding: 'utf8'}), cargo: execFileSync('cargo', ['-V'], {encoding: 'utf8'}),
      platform: process.platform, arch: process.arch, image: [process.env.ImageOS || null, process.env.ImageVersion || null],
      compiler: process.platform === 'win32' ? null : execFileSync('cc', ['--version'], {encoding: 'utf8'}),
      container: process.env.RELEASE_CONTAINER_IMAGE || null,
      alpine: existsSync('/etc/alpine-release') ? readFileSync('/etc/alpine-release', 'utf8') : null,
      packages: target.endsWith('-musl') ? execFileSync('apk', ['info', '-v'], {encoding: 'utf8'}).split('\n').sort() : null,
      flags: Object.entries(process.env).filter(([name]) => /^(?:CARGO_PROFILE_|CARGO_TARGET_|CFLAGS|CXXFLAGS|CC_|CXX_|AR_|OPENSSL_|PKG_CONFIG)/.test(name) ||
        ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','CC','CXX','AR','RSRS_CORE_TEST_MODE'].includes(name)).sort(),
      files: files.filter(existsSync).sort().map(file => [path.relative(process.cwd(), path.resolve(file)).replaceAll('\\', '/'), createHash('sha256').update(readFileSync(file)).digest('hex')]),
    };
    if (target.endsWith('-musl') && (!identity.container || !identity.alpine)) throw Error('musl cache identity requires the actual Alpine container');
    const key = releaseKey(target, identity);
    writeFileSync('.rust-release-key', key + '\n');
    appendFileSync(process.env.GITHUB_OUTPUT, `key=${key}\n`);
  } else if (action === 'restore') {
    if (existsSync(stage) && (!existsSync(`${stage}/key`) || readFileSync(`${stage}/key`, 'utf8').trim() !== readFileSync('.rust-release-key', 'utf8').trim())) throw Error('Release dependency cache identity mismatch');
    for (const [to, from] of paths) {
      if (existsSync(`${stage}/${from}`)) { mkdirSync(path.dirname(to), {recursive: true}); cpSync(`${stage}/${from}`, to, {recursive: true, preserveTimestamps: true}); }
    }
  } else if (action === 'pack') {
    const source = {target, sha: process.env.GITHUB_SHA, run_id: process.env.GITHUB_RUN_ID, run_attempt: process.env.GITHUB_RUN_ATTEMPT};
    if (!/^[a-f0-9]{40}$/.test(source.sha || '') || !/^[1-9][0-9]*$/.test(source.run_id || '') || !/^[1-9][0-9]*$/.test(source.run_attempt || '')) throw Error('Missing exact release cache producer');
    const packages = metadata().packages.flatMap(p => ['-p', p.name]);
    // Remove both host and target workspace products; only third-party compilation is reusable.
    for (const extra of [[], ['--target', target]]) execFileSync('cargo', ['clean', '--release', '--target-dir', 'target/ci', ...extra, ...packages], {stdio: 'inherit'});
    rmSync(output, {recursive: true, force: true}); mkdirSync(output, {recursive: true});
    const key = readFileSync('.rust-release-key', 'utf8').trim();
    if (!new RegExp(`^rust-release-v1-${target}-[a-f0-9]{64}$`).test(key)) throw Error('Release cache key changed');
    writeFileSync(`${output}/key`, key + '\n');
    writeFileSync(`${output}/source.json`, JSON.stringify(source) + '\n');
    for (const [from, to] of paths) if (existsSync(from)) { mkdirSync(path.dirname(`${output}/${to}`), {recursive: true}); cpSync(from, `${output}/${to}`, {recursive: true, preserveTimestamps: true, dereference: true}); }
    execFileSync('tar', ['-czf', '.rust-release-save.tar.gz', '-C', output, '.'], {stdio: 'inherit'});
  } else throw Error('Expected release key, restore or pack');
}

function main(action, kind, releaseTarget) {
  if (kind === 'release') return release(action, releaseTarget);
  cacheKey(kind, {});
  const target = kind === 'coverage' ? 'target/llvm-cov-target' : 'target';
  const registry = path.join(process.env.CARGO_HOME || path.join(homedir(), '.cargo'), 'registry');
  const stage = '.rust-ci-cache';
  if (action === 'key') {
    const files = [...metadata().packages.map(p => p.manifest_path), 'Cargo.toml', 'Cargo.lock', '.cargo/config.toml',
      'rust-toolchain.toml', 'sdk/core-sdk.lock.json', 'crates/core-sdk/core-sdk.lock.json', '.github/workflows/ci.yml'];
    const identity = {
      rust: execFileSync('rustc', ['-Vv'], {encoding: 'utf8'}),
      coverage: kind === 'coverage' ? execFileSync('cargo', ['llvm-cov', '--version'], {encoding: 'utf8'}) : null,
      platform: process.platform, arch: process.arch, image: process.env.ImageOS,
      flags: Object.entries(process.env).filter(([key]) => key.startsWith('CARGO_PROFILE_') ||
        ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET'].includes(key)).sort(),
      files: files.filter(existsSync).sort().map(file => [path.relative(process.cwd(), path.resolve(file)),
        createHash('sha256').update(readFileSync(file)).digest('hex')]),
    };
    appendFileSync(process.env.GITHUB_OUTPUT, `key=${cacheKey(kind, identity)}\n`);
  } else if (action === 'restore') {
    for (const [from, to] of [[`${stage}/target/debug`, `${target}/debug`],
      [`${stage}/cargo/cache`, `${registry}/cache`], [`${stage}/cargo/index`, `${registry}/index`]]) {
      if (existsSync(from)) { mkdirSync(path.dirname(to), {recursive: true}); cpSync(from, to, {recursive: true, preserveTimestamps: true}); }
    }
  } else if (action === 'pack') {
    // Cache dependency builds only; workspace binaries and old coverage cannot prove a new run.
    const args = ['clean', '--target-dir', target];
    for (const pkg of metadata().packages) args.push('-p', pkg.name);
    execFileSync('cargo', args, {stdio: 'inherit'});
    const archive = path.join(process.env.RUNNER_TEMP, `rust-build-${kind}.tar.gz`);
    execFileSync('tar', ['--hard-dereference', '-I', 'gzip -1', '-cf', archive,
      '--transform=s,^debug,target/debug,', '--transform=s,^cache,cargo/cache,', '--transform=s,^index,cargo/index,',
      '-C', path.resolve(target), 'debug', '-C', registry, 'cache', 'index'], {stdio: 'inherit'});
  } else throw Error('Expected key, restore or pack');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(...process.argv.slice(2));
}
