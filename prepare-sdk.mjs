import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';

const root = dirname(fileURLToPath(import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const relativePath = path => {
  if (typeof path !== 'string' || !path || path.includes('\\') || path.split('/').some(part => !part || part === '.' || part === '..' || /[<>:"|?*\x00-\x1f]/.test(part) || /[. ]$/.test(part) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) {
    throw new Error('Invalid SDK relative path');
  }
  return path;
};
const checkedPath = (directory, path) => {
  if (existsSync(directory) && lstatSync(directory).isSymbolicLink()) throw new Error('SDK directory symlink is not allowed');
  const full = resolve(directory, relativePath(path));
  if (!full.startsWith(directory + sep)) throw new Error('SDK file escapes destination');
  let current = directory;
  for (const part of path.split('/')) {
    current = join(current, part);
    if (existsSync(current) && lstatSync(current).isSymbolicLink()) throw new Error('SDK symlink is not allowed');
  }
  return full;
};
const download = async value => {
  const url = new URL(value);
  if (url.protocol !== 'https:') throw new Error('SDK downloads require HTTPS');
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) throw new Error(`SDK download failed: HTTP ${response.status}`);
  if (new URL(response.url).protocol !== 'https:') throw new Error('SDK redirect downgraded HTTPS');
  return Buffer.from(await response.arrayBuffer());
};
const verify = (directory, bytes, entry, target) => {
  if (hash(bytes) !== entry.manifest_sha256) throw new Error('SDK manifest does not match the pinned SHA-256');
  const manifest = JSON.parse(bytes);
  if (manifest.target !== target || manifest.abi_version !== 0x00010002 || !Array.isArray(manifest.files)) throw new Error('SDK target, ABI or file manifest mismatch');
  const seen = new Set();
  for (const file of manifest.files) {
    const full = checkedPath(directory, file.path);
    if (seen.has(file.path)) throw new Error('Duplicate SDK manifest file');
    seen.add(file.path);
    if (!lstatSync(full).isFile() || hash(readFileSync(full)) !== file.sha256) throw new Error(`SDK file SHA-256 mismatch: ${file.path}`);
  }
};

// Accept only ordinary ustar files/directories; inspect before extraction.
export function inspectArchive(archive) {
  const bytes = gunzipSync(archive), entries = new Set();
  const text = data => data.toString('utf8').split('\0')[0];
  const octal = data => {
    const value = text(data).trim();
    if (!/^[0-7]+$/.test(value)) throw new Error('Invalid tar numeric field');
    const number = Number.parseInt(value, 8);
    if (!Number.isSafeInteger(number)) throw new Error('Tar numeric field too large');
    return number;
  };
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      if (bytes.subarray(offset).some(byte => byte !== 0)) throw new Error('Unexpected data after tar terminator');
      return entries;
    }
    const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (checksum !== octal(header.subarray(148, 156))) throw new Error('Tar header checksum mismatch');
    if (text(header.subarray(257, 263)) !== 'ustar') throw new Error('SDK archive must use ustar format');
    const type = header[156];
    if (![0, 48, 53].includes(type)) throw new Error('Tar links and special entries are not allowed');
    const prefix = text(header.subarray(345, 500));
    let name = [prefix, text(header.subarray(0, 100))].filter(Boolean).join('/');
    if (name.startsWith('./')) name = name.slice(2);
    if (type === 53) name = name.replace(/\/$/, '');
    if (!(type === 53 && (name === '.' || name === ''))) {
      relativePath(name);
      if (entries.has(name)) throw new Error('Duplicate tar entry');
      entries.add(name);
    }
    const size = octal(header.subarray(124, 136));
    if (type === 53 && size !== 0) throw new Error('Tar directory contains data');
    offset += 512 + Math.ceil(size / 512) * 512;
    if (offset > bytes.length) throw new Error('Truncated tar entry');
  }
  throw new Error('Missing tar terminator');
}

export async function prepareSdk(target, destination, lockPath = join(root, 'core-sdk.lock.json')) {
  if (!target) throw new Error('Usage: node prepare-sdk.mjs <target> [output-directory]');
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  const entry = lock.targets[target];
  if (!entry) throw new Error(`No validated Core SDK is pinned for ${target}`);
  const configured = process.env.RSRS_CORE_SDK_DIR ?? process.env.ONEMEMORY_CORE_SDK_DIR ?? process.env.RESPIRE_CORE_SDK_DIR;
  const output = resolve(configured ?? destination ?? join(dirname(lockPath), '.sdk', target));
  const manifestPath = join(output, 'manifest.json');
  if (existsSync(manifestPath)) {
    verify(output, readFileSync(manifestPath), entry, target);
  } else {
    if (existsSync(output)) throw new Error('SDK destination already exists without a manifest; use a fresh directory');
    if (!entry.url) throw new Error(`No approved SDK download URL for ${target}; provide a validated local RSRS_CORE_SDK_DIR`);
    const bytes = await download(entry.url);
    if (hash(bytes) !== entry.manifest_sha256) throw new Error('SDK manifest does not match the pinned SHA-256');
    mkdirSync(dirname(output), { recursive: true });
    const temporary = mkdtempSync(join(dirname(output), '.sdk-prepare-'));
    const staged = join(temporary, 'sdk');
    mkdirSync(staged);
    try {
      if (entry.archive_url) {
        if (!/^[a-f0-9]{64}$/.test(entry.archive_sha256 || '')) throw new Error('Missing pinned SDK archive SHA-256');
        const archive = await download(entry.archive_url);
        if (hash(archive) !== entry.archive_sha256) throw new Error('SDK archive SHA-256 mismatch');
        inspectArchive(archive);
        const archivePath = join(temporary, 'sdk.tar.gz');
        writeFileSync(archivePath, archive);
        // A Windows drive colon in -f can be mistaken for a remote host by GNU tar.
        const extraction = spawnSync('tar', ['-xzf', 'sdk.tar.gz', '-C', 'sdk'], { cwd: temporary, encoding: 'utf8' });
        if (extraction.error) throw extraction.error;
        if (extraction.status !== 0) throw new Error(`SDK extraction failed: ${extraction.stderr}`);
        if (!readFileSync(join(staged, 'manifest.json')).equals(bytes)) throw new Error('Archive manifest differs from pinned standalone manifest');
      } else {
        const manifest = JSON.parse(bytes);
        if (!Array.isArray(manifest.files)) throw new Error('Missing SDK files');
        for (const file of manifest.files) {
          const full = checkedPath(staged, file.path);
          mkdirSync(dirname(full), { recursive: true });
          writeFileSync(full, await download(new URL(file.path, entry.url)));
        }
        writeFileSync(join(staged, 'manifest.json'), bytes);
      }
      verify(staged, bytes, entry, target);
      renameSync(staged, output);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  }
  if (process.env.GITHUB_ENV) appendFileSync(process.env.GITHUB_ENV, `RSRS_CORE_SDK_DIR=${output}\n`, 'utf8');
  console.log(`Validated Core SDK: ${output}`);
  return output;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await prepareSdk(...process.argv.slice(2));
