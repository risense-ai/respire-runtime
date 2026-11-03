import {readFileSync, writeFileSync} from 'node:fs';

const [version] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+(?:-dev\.\d+)?$/.test(version || '')) throw new Error('Invalid CLI build version');
const cargoPath = 'cli/Cargo.toml', manifestPath = 'npm/artifact-manifest.json', lockPath = 'Cargo.lock';
const cargo = readFileSync(cargoPath, 'utf8');
const previous = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const manifest = readFileSync(manifestPath, 'utf8');
if (!previous || JSON.parse(manifest).cliVersion !== previous) throw new Error('CLI Cargo/npm versions differ');
const lock = readFileSync(lockPath, 'utf8');
const packageVersion = /(\[\[package\]\]\r?\nname = "respire"\r?\nversion = ")([^"]+)(")/;
if (lock.match(packageVersion)?.[2] !== previous) throw new Error('CLI Cargo.lock version differs');
writeFileSync(cargoPath, cargo.replace(/^(version\s*=\s*")[^"]+(".*)$/m, (_, prefix, suffix) => prefix+version+suffix));
writeFileSync(manifestPath, manifest.replace(/("cliVersion"\s*:\s*")[^"]+(".*)/, (_, prefix, suffix) => prefix+version+suffix));
writeFileSync(lockPath, lock.replace(packageVersion, (_, prefix, _previous, suffix) => prefix+version+suffix));
console.log(`Prepared ephemeral CLI build version ${previous} -> ${version}; no Git commit or tag created`);
