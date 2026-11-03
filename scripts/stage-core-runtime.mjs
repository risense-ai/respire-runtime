import {createHash, randomUUID} from 'node:crypto';
import {chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {basename, dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
// Compact Mach-O/PE/ELF header verifier (adapted from the CLI release tooling,
// which pulled it from npm/scripts/verify-binary.mjs; this repository has no
// npm layer). Execution alone accepts x64 under Windows ARM emulation, so the
// image header is inspected too.
function verifyBinary(file, target) {
  const bytes = readFileSync(file);
  const arm = target.startsWith('aarch64-');
  if (!arm && !target.startsWith('x86_64-')) throw new Error(`Unsupported binary target: ${target}`);
  let matches = false;
  if (target.endsWith('-pc-windows-msvc') && bytes.subarray(0, 2).toString() === 'MZ') {
    const offset = bytes.readUInt32LE(0x3c);
    matches = bytes.subarray(offset, offset + 4).equals(Buffer.from('PE\0\0'))
      && bytes.readUInt16LE(offset + 4) === (arm ? 0xaa64 : 0x8664)
      && bytes.readUInt16LE(offset + 24) === 0x20b;
  } else if (target.endsWith('-apple-darwin')) {
    matches = bytes.readUInt32LE(0) === 0xfeedfacf
      && bytes.readUInt32LE(4) === (arm ? 0x100000c : 0x1000007);
  } else if (/^\w+-unknown-linux-(gnu|musl)$/.test(target)) {
    matches = bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
      && bytes[4] === 2 && bytes[5] === 1
      && bytes.readUInt16LE(18) === (arm ? 183 : 62);
  }
  if (!matches) throw new Error(`Binary header does not match ${target}: ${file}`);
}
const [destination] = process.argv.slice(2);
const configured = process.env.RSRS_CORE_SDK_DIR ?? process.env.ONEMEMORY_CORE_SDK_DIR ?? process.env.RESPIRE_CORE_SDK_DIR;
if (!destination || !configured) throw new Error('Set RSRS_CORE_SDK_DIR and pass the binary directory');
const sdk = resolve(configured), output = resolve(destination);
const manifest = JSON.parse(readFileSync(join(sdk,'manifest.json'),'utf8'));
if (manifest.test_only) throw new Error('Test-only Core SDK cannot be staged for a runtime release');
function stage(path, bytes, mode) {
  const digest = value => createHash('sha256').update(value).digest('hex');
  if (existsSync(path) && digest(readFileSync(path)) === digest(bytes) &&
      (mode === undefined || (statSync(path).mode & 0o777) === mode)) return;
  mkdirSync(dirname(path), {recursive:true});
  // Preserve mappings held by concurrent native processes; never truncate them.
  const temporary = join(dirname(path), `.${basename(path)}.${randomUUID()}`);
  try {
    writeFileSync(temporary, bytes, {mode: mode ?? 0o666});
    // Atomic replacement must preserve the SDK file mode regardless of umask.
    if (mode !== undefined) chmodSync(temporary, mode);
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, {force:true});
  }
}
const files = [];
for (const file of manifest.files) {
  let path;
  if (file.path.startsWith('runtime/')) path = file.path.slice(8);
  else if (file.path.startsWith('notices/')) path = `core-notices/${file.path.slice(8)}`;
  else if (file.path === 'LICENSE.txt') path = 'core-notices/CORE-SDK-LICENSE.txt';
  else continue;
  if (path.includes('\\') || path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Unsafe runtime path');
  const source = join(sdk,file.path);
  const bytes = readFileSync(source);
  if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) throw new Error(`SDK checksum mismatch: ${file.path}`);
  // mlx.metallib is a data resource, not a Mach-O/PE/ELF image.
  if (file.path.startsWith('runtime/') && !file.path.endsWith('.metallib')) verifyBinary(join(sdk,file.path), manifest.target);
  mkdirSync(dirname(join(output,path)),{recursive:true});
  stage(join(output,path),bytes,
    path.startsWith('core-notices/') ? 0o644 : statSync(source).mode & 0o777);
  files.push({path,sha256:file.sha256});
}
if (manifest.redistribution === 'permitted-under-included-license' && !files.some(file => file.path === 'core-notices/CORE-SDK-LICENSE.txt')) {
  throw new Error('Released Core SDK is missing its redistribution license');
}
const modelNotices = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'model-notices');
for (const entry of readdirSync(modelNotices, {withFileTypes:true})) {
  if (!entry.isFile()) continue;
  const bytes = readFileSync(join(modelNotices, entry.name));
  const path = `core-notices/models/${entry.name}`;
  mkdirSync(dirname(join(output,path)), {recursive:true});
  stage(join(output,path), bytes, 0o644);
  files.push({path,sha256:createHash('sha256').update(bytes).digest('hex')});
}
const dependencyNotices = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'dependency-notices');
for (const entry of readdirSync(dependencyNotices, {withFileTypes:true})) {
  if (!entry.isFile()) continue;
  const bytes = readFileSync(join(dependencyNotices, entry.name));
  const path = `core-notices/consumer/${entry.name}`;
  mkdirSync(dirname(join(output,path)), {recursive:true});
  stage(join(output,path), bytes, 0o644);
  files.push({path,sha256:createHash('sha256').update(bytes).digest('hex')});
}
if (manifest.target.includes('windows')) {
  // The public host embeds this pinned catalog; Core no longer distributes it.
  const source = join(dirname(fileURLToPath(import.meta.url)), '..', 'crates', 'core-sdk', 'notices', 'WinML-2.4.89-license.txt');
  const bytes = readFileSync(source);
  const path = 'core-notices/consumer/WinML-2.4.89-license.txt';
  mkdirSync(dirname(join(output,path)), {recursive:true});
  stage(join(output,path), bytes, 0o644);
  files.push({path,sha256:createHash('sha256').update(bytes).digest('hex')});
}
stage(join(output,'core-runtime.json'),JSON.stringify({schema_version:1,target:manifest.target,
  sdk_version:manifest.sdk_version,redistribution:manifest.redistribution,files},null,2)+'\n');
console.log(`Staged ${files.length} runtime/notice files next to the runtime binary`);
