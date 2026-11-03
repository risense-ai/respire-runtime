// Explicitly restricted publication recovery; never selects an arbitrary product.
export const DEV6 = Object.freeze({repository: 'risense-ai/respire-cli',
  sha: 'f0002c41454a71c30e067e44c8b1db7be0229e1a', version: '1.0.15-dev.6',
  run: 38251121403, attempt: 3, release: 410566755, ci: 38250212252,
  workflow: '.github/workflows/release.yml', sdk: '1.0.2-dev.8'});
export const TARGETS = ['x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl', 'aarch64-apple-darwin', 'x86_64-pc-windows-msvc'];
export const PACKAGES = ['@rsrsai/linux-x64-gnu', '@rsrsai/linux-x64', '@rsrsai/macos-arm64', '@rsrsai/win-x64'];
const shaPattern = /^[a-f0-9]{40}$/;
export function validateRecoverySource(source) {
  const r = source?.recovery;
  if (!r || r.kind !== 'dev6-publication-only' || Number(r.validation_run) !== DEV6.run ||
      Number(r.validation_attempt) !== DEV6.attempt || source.repository !== DEV6.repository ||
      source.workflow !== DEV6.workflow || source.sha !== DEV6.sha || source.version !== DEV6.version ||
      source.channel !== 'dev' || Number(source.release_id) !== DEV6.release ||
      !shaPattern.test(source.tooling_sha || '') || source.tooling_sha === DEV6.sha ||
      Number(source.run_id) === DEV6.run) throw new Error('Invalid restricted DEV6 recovery binding');
  return source;
}
export function validateRecoveryInputs(env) {
  if (env.GITHUB_REPOSITORY !== DEV6.repository || env.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
      env.GITHUB_REF !== 'refs/heads/main' ||
      env.RECOVERY_REF !== DEV6.sha || env.RECOVERY_VERSION !== DEV6.version ||
      env.RECOVERY_PUBLISH !== 'true' || env.RECOVERY_FULL !== 'true' ||
      [env.RECOVERY_REUSE, env.RECOVERY_REPAIR12, env.RECOVERY_REPAIR14].some(v => v !== 'false')) {
    throw new Error('Recovery is restricted to the approved DEV6 product and complete original validation');
  }
}
export function validateRecoveryAuthority(source, run, mainSha, comparison) {
  validateRecoverySource(source);
  // Compare main...tooling: an approved tooling commit is behind or identical to main.
  if (run.head_branch !== 'main' || run.event !== 'workflow_dispatch' || run.head_sha !== source.tooling_sha ||
      !shaPattern.test(mainSha || '') || comparison.base_commit?.sha !== mainSha ||
      comparison.merge_base_commit?.sha !== source.tooling_sha ||
      !['behind', 'identical'].includes(comparison.status)) throw new Error('Recovery tooling is not from trusted main ancestry');
}
export function validateOriginalValidation(run, jobs, ci) {
  if (run.id !== DEV6.run || run.run_attempt !== DEV6.attempt || run.head_sha !== DEV6.sha ||
      run.path !== DEV6.workflow || run.head_repository?.full_name !== DEV6.repository ||
      run.event !== 'workflow_dispatch' || run.status !== 'completed' || run.conclusion !== 'failure' ||
      ci.id !== DEV6.ci || ci.run_attempt !== 2 || ci.head_sha !== DEV6.sha || ci.path !== '.github/workflows/ci.yml' ||
      ci.event !== 'push' || ci.status !== 'completed' || ci.conclusion !== 'success') {
    throw new Error('Original DEV6 run/source/CI is not the approved completed validation');
  }
  const required = ['plan', 'validate / resolve', 'validate / npm-dry-run', 'api-smoke',
    ...TARGETS.flatMap(t => [`validate / Release (${t})`, `native-regression / Native (${t})`]),
    'cloud-sweep (ubuntu-latest, x86_64-unknown-linux-musl)',
    'cloud-sweep (macos-latest, aarch64-apple-darwin)', 'cloud-sweep (windows-latest, x86_64-pc-windows-msvc)'];
  for (const name of required) {
    const match = jobs.filter(j => j.name === name);
    if (match.length !== 1 || match[0].run_id !== DEV6.run || match[0].head_sha !== DEV6.sha ||
        match[0].status !== 'completed' || match[0].conclusion !== 'success') throw new Error(`Missing original validation: ${name}`);
  }
  const publisher = jobs.filter(j => j.name === 'publish');
  if (publisher.length !== 1 || publisher[0].run_id !== DEV6.run || publisher[0].head_sha !== DEV6.sha ||
      publisher[0].status !== 'completed' || publisher[0].conclusion !== 'failure' ||
      !publisher[0].steps?.some(s => s.name === 'Publish npm using Trusted Publishing' && s.conclusion === 'success') ||
      !publisher[0].steps?.some(s => s.name === 'Verify scoped registry propagation and bind the draft receipt' && s.conclusion === 'failure')) {
    throw new Error('Original failure is not the approved post-scoped-publication barrier failure');
  }
}
export function validateOriginalArtifact(artifacts, name) {
  const matches = artifacts.filter(a => a.name === name);
  if (matches.length !== 1 || matches[0].expired || matches[0].workflow_run?.id !== DEV6.run ||
      matches[0].workflow_run?.head_sha !== DEV6.sha) throw new Error(`Unbound original artifact: ${name}`);
  return matches[0];
}
