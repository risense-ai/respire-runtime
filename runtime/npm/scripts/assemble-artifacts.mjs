import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';

const [source, destination] = process.argv.slice(2);
if (!source || !destination) throw new Error('Pass artifact source and package binary root');
const manifest = JSON.parse(readFileSync('npm/artifact-manifest.json', 'utf8'));
const sha = execFileSync('git', ['rev-parse', 'HEAD'], {encoding:'utf8'}).trim();
for (const target of manifest.targets) {
  execFileSync(process.execPath, ['npm/scripts/extract-artifact.mjs', source, join(destination, target.triple, 'release')], {
    env:{...process.env, CLI_TARGET:target.triple, CLI_SHA:sha, CLI_VERSION:manifest.cliVersion}, stdio:'inherit',
  });
}
