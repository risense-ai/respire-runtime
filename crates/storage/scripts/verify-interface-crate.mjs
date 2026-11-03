import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [selection, destination] = process.argv.slice(2);
if (!['protocol', 'sdk'].includes(selection) || !destination) throw new Error('Usage: verify-interface-crate.mjs <protocol|sdk> <new-output>');
const output = resolve(destination);
if (existsSync(output)) throw new Error('Use a fresh crate verification directory');
mkdirSync(output, { recursive: true });
const source = join(root, 'crates', selection === 'sdk' ? 'core-sdk' : 'protocol');
const manifest = readFileSync(join(source, 'Cargo.toml'), 'utf8');
const name = /^name\s*=\s*"([^"]+)"/m.exec(manifest)?.[1];
const version = /^version\s*=\s*"([^"]+)"/m.exec(manifest)?.[1];
if (!name || !version) throw new Error('Missing crate metadata');
const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed`);
};
const target = process.platform === 'win32' ? 'x86_64-pc-windows-msvc' : process.platform === 'linux' ? 'x86_64-unknown-linux-gnu' : null;
if (!target) throw new Error('Crate consumer verification currently runs on Windows x64 or GNU Linux x64');
const environment = { ...process.env, CARGO_TARGET_DIR: join(output, 'target') };
for (const name of ['RSRS_CORE_SDK_DIR', 'ONEMEMORY_CORE_SDK_DIR', 'RESPIRE_CORE_SDK_DIR']) delete environment[name];
if (selection === 'sdk') {
  const protocol = /^version\s*=\s*"([^"]+)"/m.exec(readFileSync(join(root, 'crates/protocol/Cargo.toml'), 'utf8'))?.[1];
  const response = await fetch(`https://static.crates.io/crates/respire_protocol/respire_protocol-${protocol}.crate`);
  if (!response.ok) throw new Error('Publish the matching protocol crate before verifying the SDK registry package');
  await response.body?.cancel();
  run(process.execPath, [join(source, 'prepare-sdk.mjs'), target, join(output, 'sdk')], { env: environment });
  environment.RSRS_CORE_SDK_DIR = join(output, 'sdk');
}
run('cargo', ['package', '--locked', '--manifest-path', join(source, 'Cargo.toml')], { env: environment });
const archive = join(output, 'target/package', `${name}-${version}.crate`);
const unpacked = join(output, 'unpacked');
mkdirSync(unpacked);
cpSync(archive, join(unpacked, 'package.crate'));
// Relative archive paths also work with Windows GNU tar.
run('tar', ['-xzf', 'package.crate'], { cwd: unpacked });
const directory = join(unpacked, `${name}-${version}`), inventory = [];
const collect = (directory, prefix = '') => {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) throw new Error('Crate inventory contains a symlink');
    if (entry.isDirectory()) collect(join(directory, entry.name), `${prefix}${entry.name}/`);
    else if (entry.isFile()) inventory.push(`${prefix}${entry.name}`);
    else throw new Error('Crate inventory contains a special file');
  }
};
collect(directory);
if (inventory.some(file => /\.(a|lib|dll|so|dylib|onnx|pt|safetensors|pdb|bc|ll)$/i.test(file))) throw new Error('Crate includes a native binary or model payload');
if (selection === 'sdk') {
  const allowed = new Set(['Cargo.toml', 'Cargo.toml.orig', 'Cargo.lock', '.cargo_vcs_info.json', 'LICENSE', 'README.md', 'build.rs', 'core-sdk.lock.json', 'prepare-sdk.mjs', 'src/lib.rs', 'src/env.rs', 'src/host.rs', 'src/host_winml.rs', 'host-winml-build.rs', 'notices/WinML-2.4.89-license.txt', 'src/business.rs', 'src/business/reports.rs', 'src/worker.rs', 'src/cpu_model.rs', 'src/resident.rs', 'src/host_tests.rs']);
  const unexpected = inventory.filter(file => !allowed.has(file));
  if (unexpected.length) throw new Error(`Unexpected thin SDK package files: ${unexpected.join(', ')}`);
  const before = readFileSync(join(source, 'core-sdk.lock.json'));
  if (!before.equals(readFileSync(join(directory, 'core-sdk.lock.json')))) throw new Error('Packaged SDK pins differ');
  const sdk = join(output, 'consumer-sdk');
  const consumerEnvironment = { ...environment };
  for (const name of ['RSRS_CORE_SDK_DIR', 'ONEMEMORY_CORE_SDK_DIR', 'RESPIRE_CORE_SDK_DIR']) delete consumerEnvironment[name];
  run(process.execPath, [join(directory, 'prepare-sdk.mjs'), target, sdk], { env: consumerEnvironment });
  const consumer = join(output, 'consumer');
  mkdirSync(join(consumer, 'src'), { recursive: true });
  writeFileSync(join(consumer, 'Cargo.toml'), `[package]\nname = "respire-sdk-package-check"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n[dependencies]\nanyhow = "1.0"\nrespire_core_sdk = { path = "${directory.replaceAll('\\', '/')}" }\n[workspace]\n`);
  writeFileSync(join(consumer, 'src/main.rs'), 'fn main() -> anyhow::Result<()> {\n    let mut core = respire_core_sdk::Core::new()?;\n    let capabilities = core.capabilities()?;\n    anyhow::ensure!(capabilities["abi_version"].as_u64() == Some(0x0001_0002), "unexpected ABI");\n    println!("Extracted SDK package linked and initialized successfully");\n    Ok(())\n}\n');
  run('cargo', ['run', '--manifest-path', join(consumer, 'Cargo.toml')], { env: { ...environment, RSRS_CORE_SDK_DIR: sdk, CARGO_TARGET_DIR: join(output, 'consumer-target') } });
  const lock = readFileSync(join(consumer, 'Cargo.lock'), 'utf8');
  if (!/name = "respire_protocol"\r?\nversion = "[^"]+"\r?\nsource = "registry\+https:\/\/github.com\/rust-lang\/crates.io-index"/.test(lock)) throw new Error('Consumer protocol did not resolve from crates.io');
}
const report = { name, version, target, sha256: createHash('sha256').update(readFileSync(archive)).digest('hex'), files: inventory.sort() };
writeFileSync(join(output, 'PACKAGE.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
