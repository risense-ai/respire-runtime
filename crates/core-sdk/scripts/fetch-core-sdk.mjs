import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareSdk } from '../crates/core-sdk/prepare-sdk.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const [target, destination] = process.argv.slice(2);
await prepareSdk(target, destination || join(root, '.sdk', target), join(root, 'sdk/core-sdk.lock.json'));
