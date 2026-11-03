import {readFileSync} from 'node:fs';

// Execution alone accepts x64 under Windows ARM emulation; inspect the image too.
export function verifyBinary(file, target) {
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
