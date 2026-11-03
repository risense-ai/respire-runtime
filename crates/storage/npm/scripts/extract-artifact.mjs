import {createHash} from 'node:crypto';
import {chmodSync, copyFileSync, mkdirSync, readFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {verifyBinary} from './verify-binary.mjs';

const [source, destination] = process.argv.slice(2);
if (!source || !destination) throw new Error('Pass artifact source and destination');
const target = process.env.CLI_TARGET, sha = process.env.CLI_SHA, version = process.env.CLI_VERSION;
const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json', 'utf8'));
if (!manifest.targets.some(item => item.triple === target) || !/^[a-f0-9]{40}$/.test(sha || '') || manifest.cliVersion !== version) {
  throw new Error('CLI target, source or version mismatch');
}
const metadata = JSON.parse(readFileSync(join(source, `cli-build-${target}.json`), 'utf8'));
const extension = target.includes('windows') ? '.exe' : '';
const binary = `${manifest.binaryName}-${target}${extension}`, runtime = `${manifest.binaryName}-${target}-runtime.tar.gz`;
const hash = file => createHash('sha256').update(readFileSync(join(source, file))).digest('hex');
if (metadata.schema_version !== 1 || metadata.git_sha !== sha || metadata.version !== version
    || metadata.target !== target || metadata.binary_file !== binary || metadata.runtime_file !== runtime
    || hash(binary) !== metadata.binary_sha256 || hash(runtime) !== metadata.runtime_sha256) {
  throw new Error('CLI artifact metadata or checksum mismatch');
}
mkdirSync(destination, {recursive:true});
verifyBinary(join(source, binary), target);
copyFileSync(join(source, binary), join(destination, manifest.binaryName+extension));
if (!extension) chmodSync(join(destination, manifest.binaryName), 0o755);
const tar = process.platform === 'win32' ? join(process.env.SystemRoot, 'System32', 'tar.exe') : 'tar';
execFileSync(tar, ['-xzf', resolve(source, runtime), '-C', resolve(destination)]);
console.log(`Extracted verified ${target}@${version} from ${sha}`);
