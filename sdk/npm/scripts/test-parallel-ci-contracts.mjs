import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,mkdirSync,writeFileSync,utimesSync,statSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {runInNewContext} from 'node:vm';
import {cacheKey,releaseKey} from '../../scripts/rust-ci-cache.mjs';
const ci=readFileSync(new URL('../../.github/workflows/ci.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
const section=name=>ci.split(`\n  ${name}:\n`)[1]?.split(/\n  [a-z][\w-]*:\n/)[0];
test('independent contract checks do not wait for Rust coverage or receive SDK/publish credentials',()=>{
  const contracts=section('contract-checks'),source=section('coverage-tests'),workspace=section('workspace-tests');
  assert(contracts && source);assert.doesNotMatch(contracts,/\n    needs:|id-token:|actions: write|secrets\.|fetch-core-sdk|cargo /);
  assert.match(contracts,/persist-credentials: false/);assert.match(contracts,/contents: read/);
  assert.match(workspace,/cargo test --workspace --exclude respire --locked/);assert.doesNotMatch(source,/cargo test --workspace --exclude respire/);assert.doesNotMatch(workspace,/llvm-cov|needs:/);assert.match(workspace,/Require the exact SDK cache match/);assert.match(workspace,/RSRS_CORE_TEST_MODE: '1'/);
  assert(workspace.indexOf('cargo test --workspace --exclude respire --locked')<workspace.indexOf('python3 scripts/test-core-payload-lifetime.py'));assert(workspace.includes('python3 scripts/test-core-payload-lifetime.py'));assert.doesNotMatch(contracts,/test-core-payload-lifetime.py/);assert(workspace.includes('python3 scripts/test-ci-source-profile.py'));
  assert.match(source,/group: \[core, runtime_smoke, runtime_autostart\]/);
  assert.match(source,/fail-fast: false/);assert.match(source,/RSRS_CORE_TEST_MODE: '1'/);
  assert.match(source,/targets.filter\(t => t.kind.includes\('test'\)\)/);
  assert.match(source,/tests.filter\(name => !isolated.includes\(name\)\)/);
  assert.match(source,/args.push\('--lib', '--bins', '--examples'\)/);
  assert.match(source,/process.exit\(result.status \?\? 1\)/);
  const program=source.split("node --input-type=module <<'NODE'\n")[1].split('\n          NODE')[0]
    .replace("import {execFileSync, spawnSync} from 'node:child_process';",'');
  const metadata=JSON.parse(execFileSync('cargo',['metadata','--locked','--no-deps','--format-version','1'],{encoding:'utf8'}));
  const targets=metadata.packages.find(p=>p.name==='respire').targets;
  const allTests=targets.filter(t=>t.kind.includes('test')).map(t=>t.name);
  const selected=[];
  for(const group of ['core','runtime_smoke','runtime_autostart']){
    const calls=[],exits=[];
    runInNewContext(program,{
      execFileSync:()=>JSON.stringify(metadata),
      spawnSync:(_command,args)=>{calls.push(args);return {status:0};},
      process:{env:{COVERAGE_GROUP:group},exit:status=>exits.push(status)},
    });
    assert.deepEqual(exits,[0]);assert.equal(calls.length,1);
    for(let i=0;i<calls[0].length;i++)if(calls[0][i]==='--test')selected.push(calls[0][i+1]);
    if(group==='core')for(const flag of ['--lib','--bins','--examples'])assert(calls[0].includes(flag));
  }
  assert.deepEqual(selected.sort(),allTests.sort(),'every integration target must run exactly once');
  const exits=[];
  runInNewContext(program,{
    execFileSync:()=>JSON.stringify(metadata),spawnSync:()=>({status:23}),
    process:{env:{COVERAGE_GROUP:'runtime_smoke'},exit:status=>exits.push(status)},
  });
  assert.deepEqual(exits,[23],'test failures must fail the coverage group');

  const report=section('check-complete');assert.match(report,/needs: \[coverage-tests, workspace-tests, contract-checks\]/);
  assert.match(report,/for group in core runtime_smoke runtime_autostart/);
  assert.match(report,/cargo llvm-cov report -p respire --fail-under-lines 90/);
  assert.match(report,/exit "\$result"/);
  for(const script of ['test-publication-fence','test-publication-acceptance','test-cleanup-release-artifacts','test-registry-publication','test-release-publication','test-dev6-publication-recovery','test-parallel-publication']) {
    assert(contracts.includes(`npm/scripts/${script}.mjs`),script);assert(!source.includes(`npm/scripts/${script}.mjs`),`not serialized: ${script}`);
  }
  for(const script of ['test-private-sdk-download.mjs','test-sdk-ci-cache.mjs','test-stage-core-runtime.mjs','test-dev-smoke-gate.py','test-dev-api-contract.py','test-dev-model-fixture.py','test-dev-fixture-tty.py','test-dev-witness-fixture.py','test-reembed-progress-contract.ps1'])assert(contracts.includes(script),script);
  assert(readFileSync(new URL('../../scripts/test-dev-model-fixture.py',import.meta.url),'utf8').includes('from test_native_psutil_wheel_cache import NativePsutilWheelCacheTest'));
});
test('fail-closed aggregate requires both successful lanes, including failure and unexpected skips',()=>{
  const complete=section('check-complete');assert.match(complete,/always\(\)/);assert.match(complete,/needs: \[coverage-tests, workspace-tests, contract-checks\]/);
  assert.match(complete,/test "\$SOURCE_RESULT" = success && test "\$WORKSPACE_RESULT" = success && test "\$CONTRACT_RESULT" = success/);
  assert.match(complete,/contents: read/);assert.match(complete,/actions: read/);assert.doesNotMatch(complete,/id-token:|actions: write|secrets\./);
  assert.match(complete,/SOURCE_RESULT: \$\{\{ needs.coverage-tests.result \}\}/);
  for(const name of ['coverage-tests','check-complete','workspace-tests','contract-checks'])assert.match(section(name),/!inputs.research_feedback_only && !inputs.native_published_only && !inputs.artifact_run && !inputs.version_upgrade_only/);
});


test('explicit manual source checks omit only the optional compile matrix and cannot replace Release push-CI proof',()=>{
  assert.match(ci,/source_checks_only:\n        description: Run all source tests, coverage and contracts/);
  assert.match(section('platform-build'),/!inputs.source_checks_only/);
  for(const name of ['workspace-tests','coverage-tests','contract-checks','check-complete'])assert.doesNotMatch(section(name),/!inputs.source_checks_only/);
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8');
  assert.match(release,/run.head_sha===sha&&run.event==='push'/);
});


test('source metadata optimization retains debug safety and only the CLI test-stack exception',()=>{
  for(const name of ['workspace-tests','coverage-tests']){
    const text=section(name);
    for(const profile of ['DEV','TEST']){
      assert(text.includes(`CARGO_PROFILE_${profile}_DEBUG: line-tables-only`));
      assert(text.includes(`CARGO_PROFILE_${profile}_DEBUG_ASSERTIONS: 'true'`));
      assert(text.includes(`CARGO_PROFILE_${profile}_OVERFLOW_CHECKS: 'true'`));
      assert(text.includes(`CARGO_PROFILE_${profile}_OPT_LEVEL: '0'`));
    }
  }
  assert.match(section('check-complete'),/--fail-under-lines 90/);
  assert.doesNotMatch(section('platform-build'),/CARGO_PROFILE_/);
  const manifest=readFileSync(new URL('../../Cargo.toml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(manifest,/\[profile.dev.package.sha2\]\nopt-level = 3/);
  assert.doesNotMatch(manifest,/\[profile\.(?:dev|test)\]\n[^[]*opt-level\s*=\s*[1-3]/);
  // Clap's Windows debug builder exceeds 2 MiB; only this test package uses opt-level=1.
  // See docs/ci-source-profile.md for measured frames and default-stack validation.
  // The runtime split moved the clap derive into respire_commands, so both
  // test packages carry the stack guard.
  const assertProfiles=value=>assert.deepEqual(value.split(/(?=^\[)/m)
    .filter(block=>block.startsWith('[profile.'))
    .map(block=>block.split('\n').map(line=>line.trim()).filter(line=>line&&!line.startsWith('#')).join('\n')),[
      '[profile.dev.package.sha2]\nopt-level = 3',
      '[profile.release]\nstrip = "debuginfo"\nlto = false\ncodegen-units = 1\npanic = "unwind"',
      '[profile.test.package.respire]\nopt-level = 1',
      '[profile.test.package.respire_commands]\nopt-level = 1',
    ]);
  assertProfiles(manifest);
  for(const changed of [
    manifest.replace('[profile.test.package.respire]','[profile.dev.package.respire]'),
    manifest.replace('[profile.test.package.respire]\nopt-level = 1','[profile.test.package.respire]\nopt-level = 2'),
    manifest+'\n[profile.test.package.other]\nopt-level = 1\n',
    manifest+'\n[profile.test]\nopt-level = 1\n',
    manifest.replace('[profile.test.package.respire]','[profile.test.package.respire]\ndebug-assertions = false'),
    manifest.replace('panic = "unwind"','panic = "abort"'),
  ])assert.throws(()=>assertProfiles(changed));
  assert.deepEqual([...ci.matchAll(/^\s*RUST_MIN_STACK: (.+)$/gm)].map(match=>match[1]),
    ["'16777216'","'16777216'"],'retain the two existing CI stack settings without adding or raising a global override');
  const archive=section('coverage-tests');
  assert.match(archive,/set -euo pipefail/);
  assert.match(archive,/tar -cf -[^\n]+\| gzip -1/);
  assert.match(archive,/compression-level: 0/);
  assert.match(archive,/cargo llvm-cov clean --profraw-only/);
  const identity={rust:'pinned compiler',locks:['dependencies','sdk'],flags:['coverage']};
  const key=cacheKey('coverage',identity);assert.match(key,/^rust-ci-v1-coverage-[a-f0-9]{64}$/);
  assert.equal(key,cacheKey('coverage',structuredClone(identity)));
  assert.notEqual(key,cacheKey('workspace',identity));
  for(const field of Object.keys(identity))assert.notEqual(key,cacheKey('coverage',{...identity,[field]:'changed'}));
  assert.throws(()=>cacheKey('sdk',identity));
  const releaseIdentity={...identity,target:'x86_64-unknown-linux-musl',container:'sha256:exact-container',sdk:'exact-sdk',profile:'release'};
  const releaseCacheKey=releaseKey(releaseIdentity.target,releaseIdentity);
  assert.match(releaseCacheKey,/^rust-release-v1-x86_64-unknown-linux-musl-[a-f0-9]{64}$/);
  assert.equal(releaseCacheKey,releaseKey(releaseIdentity.target,structuredClone(releaseIdentity)));
  for(const field of Object.keys(releaseIdentity))assert.notEqual(releaseCacheKey,releaseKey(releaseIdentity.target,{...releaseIdentity,[field]:'changed'}));
  assert.notEqual(releaseCacheKey,releaseKey('aarch64-unknown-linux-musl',releaseIdentity));
  assert.throws(()=>releaseKey('../other',releaseIdentity));
  const release=readFileSync(new URL('../../.github/workflows/release-validation.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const binaries=release.split('\n  binaries:\n')[1].split('\n  native-regression:\n')[0];
  assert(binaries.indexOf('id: release-key')<binaries.indexOf('name: Prepare ephemeral build version'));
  assert.match(binaries,/key: \$\{\{ steps.release-key.outputs.key \}\}\n          enableCrossOsArchive: true/);
  const cachePack=binaries.split('      - name: Stage only release compilation dependencies')[1].split('      - uses: actions/upload-artifact@v4')[0];
  const cacheUpload=binaries.split('          name: release-dependency-cache-')[0].split('      - uses: actions/upload-artifact@v4').at(-1);
  assert.match(cachePack,/id: release-cache-pack/);assert.match(cachePack,/continue-on-error: true/);
  assert.match(cacheUpload,/continue-on-error: true/);assert.match(cacheUpload,/steps.release-cache-pack.outcome == 'success'/);
  for(const step of [cachePack,cacheUpload]){
    assert.match(step,/github.event_name == 'workflow_dispatch' \|\| github.event_name == 'push'/);
    assert.match(step,/github.ref == 'refs\/heads\/main'/);assert.match(step,/needs.resolve.outputs.sha == github.sha/);
  }
  assert.equal((binaries.match(/continue-on-error: true/g)||[]).length,2,'only optional cache maintenance may tolerate failure');
  assert.doesNotMatch(binaries,/restore-keys:|musl-\$\{\{ matrix.target \}\}-ort/);
  assert(binaries.indexOf('name: cli-release-')<binaries.indexOf('name: Stage only release compilation dependencies'));
  assert.match(binaries,/RELEASE_DEPENDENCY_CACHE: '1'/);
  assert.doesNotMatch(release,/\n  release-cache-save:|actions\/cache\/save/);
  assert.equal((binaries.match(/steps.release-cache.outputs.cache-hit != 'true'/g)||[]).length,2,'hot caches skip pack and artifact upload');
  const releaseWriter=readFileSync(new URL('../../.github/workflows/release-dependency-cache.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert.match(releaseWriter,/workflow_run:/);assert.match(releaseWriter,/types: \[completed\]/);
  assert.match(releaseWriter,/cache-mode: write-only/);
  assert.match(releaseWriter,/workflow_run.head_branch == 'main'/);
  assert.match(releaseWriter,/workflow_run.head_repository.full_name == github.repository/);
  assert.match(releaseWriter,/workflow_run.event == 'workflow_dispatch' \|\| github.event.workflow_run.event == 'push'/);
  assert.match(releaseWriter,/run\['event'\] not in \['workflow_dispatch','push'\]/);
  assert.match(releaseWriter,/enableCrossOsArchive: true/);
  assert.match(releaseWriter,/SOURCE_ATTEMPT/);assert.match(releaseWriter,/Foreign compilation cache source or attempt/);
  assert.match(releaseWriter,/if: needs.plan.outputs.available == 'true'/);
  assert.match(releaseWriter,/member.issym\(\).*member.islnk\(\)/);
  assert.match(releaseWriter,/filter='data'/);
  assert.doesNotMatch(releaseWriter,/actions\/checkout|secrets\.|cache\/restore|run: node|cargo /);
  const directory=mkdtempSync(path.join(tmpdir(),'rust-cache-timestamps-'));
  try {
    const cached=path.join(directory,'.rust-ci-cache/target/debug/deps/dependency.rlib');
    mkdirSync(path.dirname(cached),{recursive:true});writeFileSync(cached,'compiled dependency');
    const stamp=new Date('2001-01-01T00:00:00Z');utimesSync(cached,stamp,stamp);
    execFileSync(process.execPath,[fileURLToPath(new URL('../../scripts/rust-ci-cache.mjs',import.meta.url)),'restore','workspace'],{cwd:directory});
    const restored=path.join(directory,'target/debug/deps/dependency.rlib');
    assert.equal(readFileSync(restored,'utf8'),'compiled dependency');
    assert(Math.abs(statSync(restored).mtimeMs-stamp.getTime())<1,'Cargo dependency timestamps must survive restore');
    const target=execFileSync('rustc',['-Vv'],{encoding:'utf8'}).match(/^host: (.+)$/m)[1];
    const script=fileURLToPath(new URL('../../scripts/rust-ci-cache.mjs',import.meta.url));
    const virtual=path.join(directory,'virtual');mkdirSync(path.join(virtual,'member/src'),{recursive:true});
    const rootManifest='[workspace]\nmembers=["member"]\nresolver="2"\n[profile.release]\ncodegen-units=1\n';
    writeFileSync(path.join(virtual,'Cargo.toml'),rootManifest);
    writeFileSync(path.join(virtual,'member/Cargo.toml'),'[package]\nname="virtual_member"\nversion="0.1.0"\nedition="2021"\n');
    writeFileSync(path.join(virtual,'member/src/lib.rs'),'pub fn example() {}\n');
    writeFileSync(path.join(virtual,'Cargo.lock'),'version = 4\n[[package]]\nname = "virtual_member"\nversion = "0.1.0"\n');
    const keyEnv={...process.env,CARGO_HOME:path.join(virtual,'cargo-home'),GITHUB_OUTPUT:path.join(virtual,'output')};
    const virtualMetadata=JSON.parse(execFileSync('cargo',['metadata','--locked','--offline','--no-deps','--format-version','1'],{cwd:virtual,env:keyEnv,encoding:'utf8'}));
    assert(virtualMetadata.packages.every(pkg=>path.resolve(pkg.manifest_path)!==path.join(virtual,'Cargo.toml')));
    execFileSync(process.execPath,[script,'key','release',target],{cwd:virtual,env:keyEnv,stdio:'pipe'});
    const beforeRootProfileChange=readFileSync(path.join(virtual,'.rust-release-key'),'utf8');
    writeFileSync(path.join(virtual,'Cargo.toml'),rootManifest.replace('codegen-units=1','codegen-units=2'));
    execFileSync(process.execPath,[script,'key','release',target],{cwd:virtual,env:keyEnv,stdio:'pipe'});
    assert.notEqual(readFileSync(path.join(virtual,'.rust-release-key'),'utf8'),beforeRootProfileChange,'actual virtual-root release profile changes must invalidate the collected key');
    writeFileSync(path.join(directory,'Cargo.toml'),'[package]\nname="cache_fixture"\nversion="0.1.0"\nedition="2021"\n');
    writeFileSync(path.join(directory,'Cargo.lock'),'version = 4\n[[package]]\nname = "cache_fixture"\nversion = "0.1.0"\n');
    mkdirSync(path.join(directory,'src'));writeFileSync(path.join(directory,'src/main.rs'),'fn main() {}\n');
    // Let Cargo establish target ownership before restoring cached dependencies.
    execFileSync('cargo',['build','--release','--locked','--target',target,'--target-dir','target/ci'],{cwd:directory,stdio:'pipe'});
    assert(readFileSync(path.join(directory,'target/ci/CACHEDIR.TAG'),'utf8').startsWith('Signature: 8a477f597d28d172789f06886806bc55'));
    const key=releaseKey(target,releaseIdentity);
    writeFileSync(path.join(directory,'.rust-release-key'),key+'\n');
    mkdirSync(path.join(directory,'.rust-release-cache/target/release/deps'),{recursive:true});
    writeFileSync(path.join(directory,'.rust-release-cache/key'),key+'\n');
    const releaseDependency=path.join(directory,'.rust-release-cache/target/release/deps/dependency.rlib');
    writeFileSync(releaseDependency,'dependency-only');utimesSync(releaseDependency,stamp,stamp);
    execFileSync(process.execPath,[script,'restore','release',target],{cwd:directory});
    const releaseRestored=path.join(directory,'target/ci',target,'release/deps/dependency.rlib');
    assert.equal(readFileSync(releaseRestored,'utf8'),'dependency-only');
    assert(Math.abs(statSync(releaseRestored).mtimeMs-stamp.getTime())<1);
    writeFileSync(path.join(directory,'.rust-release-cache/key'),'wrong');
    assert.throws(()=>execFileSync(process.execPath,[script,'restore','release',target],{cwd:directory,stdio:'pipe'}));
    const cargoHome=path.join(directory,'cargo-home');
    mkdirSync(path.join(cargoHome,'registry/cache'),{recursive:true});
    writeFileSync(path.join(cargoHome,'credentials.toml'),'never-cache-this');
    const producer={...process.env,CARGO_HOME:cargoHome,GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1'};
    execFileSync(process.execPath,[script,'pack','release',target],{cwd:directory,env:producer,stdio:'pipe'});
    const listing=execFileSync('tar',['-tzf','.rust-release-save.tar.gz'],{cwd:directory,encoding:'utf8'});
    assert.match(listing,/target\/release\/deps\/dependency.rlib/);
    assert.doesNotMatch(listing,/cache_fixture|credentials|profraw|profdata/);
    const source=JSON.parse(readFileSync(path.join(directory,'.rust-release-save/source.json'),'utf8'));
    assert.deepEqual(source,{target,sha:'a'.repeat(40),run_id:'123',run_attempt:'1'});
    assert.throws(()=>execFileSync(process.execPath,[script,'pack','release',target],{cwd:directory,env:{...producer,GITHUB_RUN_ATTEMPT:''},stdio:'pipe'}));
  } finally {rmSync(directory,{recursive:true});}
  const writer=section('rust-build-save');
  assert.match(writer,/cache-mode: write-only/);assert.match(writer,/filter='data'/);
  assert.match(writer,/\^rust-ci-v1-/);
  assert.doesNotMatch(writer,/actions\/checkout|secrets\.|cache\/restore|cargo |run: node/);
  for(const name of ['workspace-tests','coverage-tests']){
    const lane=section(name);assert.match(lane,/actions\/cache\/restore/);assert.doesNotMatch(lane,/cache-mode: write|cache\/save/);
    assert.match(lane,/steps.rust-build.outputs.cache-hit != 'true'/);
  }
});
