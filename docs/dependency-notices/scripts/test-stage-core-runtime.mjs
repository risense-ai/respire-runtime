import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve, sep} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import test from 'node:test';

const stage = join(dirname(fileURLToPath(import.meta.url)), 'stage-core-runtime.mjs');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const cases = [
  {path: 'notices/rust/tokenizers-0.23.2/LICENSE', mode: 0o600, output: 'core-notices/rust/tokenizers-0.23.2/LICENSE'},
  {path: 'notices/native/onnxruntime-LICENSE.txt', mode: 0o600, output: 'core-notices/native/onnxruntime-LICENSE.txt'},
  {path: 'notices/rust/fnv-1.0.7/LICENSE-APACHE', mode: 0o640, output: 'core-notices/rust/fnv-1.0.7/LICENSE-APACHE'},
  {path: 'LICENSE.txt', mode: 0o600, output: 'core-notices/CORE-SDK-LICENSE.txt'},
  {path: 'runtime/libfixture.so', mode: 0o600, output: 'libfixture.so'},
  {path: 'runtime/libfixture640.so', mode: 0o640, output: 'libfixture640.so'},
];

for (const umask of [0o022, 0o077]) {
for (const overwrite of [false, true]) {
  test(`staged notices are readable and hash-preserving (${overwrite ? 'existing outputs' : 'fresh outputs'}, umask ${umask.toString(8)})`, () => {
    const temporary = resolve(mkdtempSync(join(tmpdir(), 'rsrs-staged-notices-')));
    const sdk = join(temporary, 'sdk'), output = join(temporary, 'output');
    try {
      const files = cases.map(entry => {
        const bytes = Buffer.from(`Synthetic SDK fixture: ${entry.path}\n`);
        if (entry.path.startsWith('runtime/')) {
          bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]);
          bytes.writeUInt16LE(62, 18);
        }
        const source = join(sdk, entry.path);
        mkdirSync(dirname(source), {recursive: true});
        writeFileSync(source, bytes); chmodSync(source, entry.mode);
        if (overwrite) {
          const destination = join(output, entry.output);
          mkdirSync(dirname(destination), {recursive: true});
          writeFileSync(destination, 'Old staged bytes'); chmodSync(destination, entry.mode);
        }
        return {path: entry.path, sha256: hash(bytes)};
      });
      writeFileSync(join(sdk, 'manifest.json'), JSON.stringify({target: 'x86_64-unknown-linux-musl',
        sdk_version: 'synthetic-test', redistribution: 'permitted-under-included-license', files}));
      // Set only the child process mask; the caller's default must not hide mode loss.
      const run = `process.umask(${umask}); await import(${JSON.stringify(pathToFileURL(stage).href)});`;
      const staged = spawnSync(process.execPath, ['--input-type=module', '--eval', run, stage, output], {encoding: 'utf8',
        env: {...process.env, RSRS_CORE_SDK_DIR: sdk}});
      assert.equal(staged.status, 0, staged.stderr);
      const runtime = JSON.parse(readFileSync(join(output, 'core-runtime.json'), 'utf8'));
      for (const entry of cases) {
        const original = files.find(file => file.path === entry.path);
        assert.equal(hash(readFileSync(join(sdk, entry.path))), original.sha256);
        assert.equal(hash(readFileSync(join(output, entry.output))), original.sha256);
        assert.equal(runtime.files.find(file => file.path === entry.output)?.sha256, original.sha256);
        // Windows does not expose POSIX mode bits; exact CI enforces these on Linux.
        if (process.platform !== 'win32') {
          assert.equal(statSync(join(sdk, entry.path)).mode & 0o777, entry.mode);
          assert.equal(statSync(join(output, entry.output)).mode & 0o777,
            entry.output.startsWith('core-notices/') ? 0o644 : entry.mode);
        }
      }
      if (process.platform !== 'win32') {
        for (const file of runtime.files.filter(file => file.path.startsWith('core-notices/'))) {
          assert.equal(statSync(join(output, file.path)).mode & 0o777, 0o644);
        }
      }
    } finally {
      assert(temporary.startsWith(resolve(tmpdir()) + sep));
      rmSync(temporary, {recursive: true, force: true});
    }
  });
}
}
