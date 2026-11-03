import {publishPackage, publishAcceptedPackage} from './registry-publication.mjs';

export const acceptScopedPackages = (expected, umbrellaName, tag, options = {}) =>
  publishScopedPackages(expected, umbrellaName, tag, {...options, publishImpl: options.publishImpl || publishAcceptedPackage});

// Independent platform operations use bounded workers. Legacy propagation may
// overlap; accepted mode returns on each ACK. The umbrella always follows the
// complete platform barrier under the workflow's existing publication lock.
export async function publishScopedPackages(expected, umbrellaName, tag, options = {}) {
  const names = expected.map(receipt => receipt.name);
  if (new Set(names).size !== names.length) throw new Error('Duplicate publication package');
  const umbrella = expected.find(receipt => receipt.name === umbrellaName);
  const platforms = expected.filter(receipt => receipt.name !== umbrellaName);
  if ((umbrellaName === 'rsrs-cli' && umbrella) || (!umbrella && umbrellaName !== 'rsrs-cli') || !platforms.length || expected.some(receipt => receipt.version !== expected[0].version)) {
    throw new Error('Incomplete or mixed-version scoped publication batch');
  }
  const {publishImpl: publish = publishPackage, ...publicationOptions} = options;
  const results = new Map();
  let next = 0;
  let failed = false;
  const errors = [];
  const worker = async () => {
    while (!failed && next < platforms.length) {
      const receipt = platforms[next++];
      try {
        const result = await publish(receipt.dir, receipt, tag, publicationOptions);
        results.set(receipt.name, result);
        await options.onResult?.({...result, name: receipt.name});
      } catch (error) {
        failed = true;
        errors.push(error);
      }
    }
  };
  // Wait for every in-flight operation even on failure: no orphaned publication
  // or temporary-file cleanup after the job reports completion. No retries here.
  await Promise.all(Array.from({length: Math.min(4, platforms.length)}, worker));
  if (errors.length) throw new AggregateError(errors, 'Platform publication failed; umbrella was not published');
  if (umbrella) {
    const result = await publish(umbrella.dir, umbrella, tag, publicationOptions);
    results.set(umbrella.name, result);
    await options.onResult?.({...result, name: umbrella.name});
  }
  return expected.map(receipt => ({...results.get(receipt.name), name: receipt.name}));
}
