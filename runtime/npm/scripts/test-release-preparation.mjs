import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,readFileSync,mkdirSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createPreparation,validatePreparation,preparedAssets,preparedPacks,validatePreparationRun} from './release-preparation.mjs';

const sha='a'.repeat(40),hash='b'.repeat(64),version='1.2.3-dev.4';
const targets=[['x86_64-unknown-linux-gnu','linux-x64-gnu'],['x86_64-unknown-linux-musl','linux-x64'],['aarch64-apple-darwin','macos-arm64'],['x86_64-pc-windows-msvc','win-x64']];
const manifest={cliVersion:version,npmScope:'@rsrsai/cli',targets:targets.map(([triple,name])=>({triple,pkg:`@rsrsai/${name}`}))};
const source={repository:'risense-ai/respire-cli',workflow:'.github/workflows/release.yml',run_id:'700',run_attempt:1,sha,version};
const identity={hashes:{'Cargo.lock':hash,'rust-toolchain.toml':hash},sdk:targets.map(([target])=>({target,version:'1.0.2-dev.12',manifest_sha256:hash,archive_sha256:hash}))};
const time=minute=>`2026-10-27T00:${String(minute).padStart(2,'0')}:00Z`;
const job=name=>({name,status:'completed',conclusion:'success',started_at:time(0),completed_at:time(3)});
function fixture(){
  const jobs=[...targets.map(([t])=>job(`validate / Release (${t})`)),job('validate / npm-dry-run'),
    ...targets.map(([t])=>job(`native-regression / Native (${t})`)),
    ...targets.slice(1).map(([t])=>job(`cloud-sweep (runner, ${t})`)),
    ...targets.slice(2).flatMap(([t])=>[job(`Native migration (${t})`),job(`Migration gate (${t})`)]),job('api-smoke')];
  const run={id:700,run_attempt:1,path:source.workflow,head_repository:{full_name:source.repository},head_sha:sha,
    head_branch:'main',event:'workflow_dispatch',status:'in_progress',updated_at:time(5)};
  const ci={id:600,run_attempt:1,path:'.github/workflows/ci.yml',head_repository:{full_name:source.repository},head_sha:sha,
    head_branch:'main',event:'push',status:'completed',conclusion:'success',run_started_at:time(0),updated_at:time(2)};
  const artifacts=[...targets.map(([t])=>`cli-release-${t}`),'npm-release-validation','npm-release-packages'].map((name,i)=>({
    name,id:i+1,size_in_bytes:100,digest:`sha256:${hash}`,expired:false,workflow_run:{id:700,head_sha:sha}}));
  const assets=targets.flatMap(([t])=>[`rsrs-${t}${t.includes('windows')?'.exe':''}`,`rsrs-${t}-runtime.tar.gz`,`cli-build-${t}.json`]).map(file=>({file,size:100,sha256:hash}));
  const packs=[...targets.map(([,n])=>`@rsrsai/${n}`),'@rsrsai/cli'].map((name,i)=>({name,version,file:`pack-${i}.tgz`,size:100,sha256:hash}));
  jobs.push({id:900,name:'preparation-receipt',status:'in_progress',started_at:time(3)});
  const context={source,identity,manifest,run,jobs,ci,artifacts,assets,packs,now:time(4)};
  const receipt=createPreparation(context);
  Object.assign(jobs.at(-1),{status:'completed',conclusion:'success',completed_at:time(4)});
  context.run={...context.run,status:'completed',conclusion:'success'};
  return {receipt,context};
}

test('exact successful main preparation proves all builds, packaging, CI and regression lanes',()=>{
  const {receipt,context}=fixture();
  assert.equal(validatePreparation(receipt,context),receipt);
  assert.equal(receipt.validation.completed_at,new Date(time(3)).toISOString());
  assert.equal(receipt.state,'validated-unpublished');
  assert.equal(receipt.accepted_at,undefined);assert.equal(receipt.install,undefined);
});
test('different source, attempt, repository, workflow, PR, fork and incomplete run cannot authorize reuse',()=>{
  const mutations=[r=>r.head_sha='f'.repeat(40),r=>r.run_attempt=2,r=>r.id=701,r=>r.head_branch='feature',
    r=>r.event='pull_request',r=>r.head_repository.full_name='fork/respire-cli',r=>r.path='.github/workflows/ci.yml',
    r=>r.status='in_progress',r=>r.conclusion='failure'];
  for(const mutate of mutations){const {receipt,context}=fixture();mutate(context.run);assert.throws(()=>validatePreparation(receipt,context));}
  assert.throws(()=>validatePreparationRun({...fixture().context.run,status:'in_progress'},source));
});
test('every required build, package validation, regression and exact push CI remains fail closed',()=>{
  const {context:sample}=fixture();
  for(let i=0;i<sample.jobs.length;i++)for(const mode of ['failure','cancelled','skipped','missing','duplicate']){
    const {receipt,context}=fixture();
    if(mode==='missing')context.jobs.splice(i,1);
    else if(mode==='duplicate')context.jobs.push({...context.jobs[i]});
    else context.jobs[i].conclusion=mode;
    assert.throws(()=>validatePreparation(receipt,context),`${i} ${mode}`);
  }
  for(const [key,value] of [['head_sha','f'.repeat(40)],['event','workflow_dispatch'],['run_attempt',2],['conclusion','cancelled']]){
    const {receipt,context}=fixture();context.ci[key]=value;assert.throws(()=>validatePreparation(receipt,context));
  }
});
test('SDK/toolchain changes, missing clocks, expired or substituted artifacts and different bytes are refused',()=>{
  const mutations=[
    ({identity})=>identity.hashes['rust-toolchain.toml']='c'.repeat(64),
    ({identity})=>identity.sdk[0].version='1.0.2-dev.13',
    ({jobs})=>delete jobs[0].completed_at,
    ({jobs})=>jobs[0].completed_at='invalid',
    ({artifacts})=>artifacts[0].expired=true,
    ({artifacts})=>artifacts[0].id=999,
    ({artifacts})=>artifacts[0].workflow_run.id=701,
    ({artifacts})=>artifacts[0].workflow_run.head_sha='f'.repeat(40),
    ({artifacts})=>artifacts[0].digest='sha256:'+'f'.repeat(64),
    ({assets})=>assets[0].sha256='f'.repeat(64),
    ({packs})=>packs[0].sha256='f'.repeat(64),
  ];
  for(const mutate of mutations){const {receipt,context}=structuredClone(fixture());mutate(context);assert.throws(()=>validatePreparation(receipt,context));}
});
test('receipt cannot change version/inventory or claim validation before work completes',()=>{
  for(const mutate of [r=>r.source.version='1.2.3-dev.5',r=>r.assets[0]=r.assets[1],r=>r.packs.pop(),
    r=>r.prepared_at='2026-02-30T00:00:00Z']){
    const {receipt,context}=structuredClone(fixture());mutate(receipt);assert.throws(()=>validatePreparation(receipt,context));
  }
});
test('preparation uses completed API gates and its successful producer despite runner clock skew',()=>{
  for(const now of ['2026-10-26T23:04:00Z','2026-10-27T01:04:00Z']){
    const {context}=structuredClone(fixture());
    context.run.status='in_progress';context.jobs.at(-1).status='in_progress';
    const receipt=createPreparation({...context,now});
    context.run.status='completed';context.jobs.at(-1).status='completed';
    assert.equal(validatePreparation(receipt,context),receipt);
  }
  for(const mutate of [c=>c.jobs.pop(),c=>c.jobs.push({...c.jobs.at(-1)}),
    c=>c.jobs.at(-1).id='invalid',c=>c.jobs.at(-1).started_at='invalid',
    c=>c.jobs.at(-1).completed_at=time(2),c=>c.jobs.at(-1).completed_at=time(6),
    c=>c.jobs.at(-1).conclusion='failure',c=>c.jobs.at(-1).status='in_progress']){
    const {receipt,context}=structuredClone(fixture());mutate(context);
    assert.throws(()=>validatePreparation(receipt,context));
  }
});

test('source CI may finish during producer setup before the attester reads its successful result',()=>{
  const {context}=structuredClone(fixture());
  context.jobs.at(-1).started_at=time(1);context.run.status='in_progress';context.jobs.at(-1).status='in_progress';
  const receipt=createPreparation(context);
  context.run.status='completed';context.jobs.at(-1).status='completed';
  assert.equal(validatePreparation(receipt,context),receipt);
});

test('actual synthetic asset files bind source, version, platform and binary/runtime hashes',()=>{
  const folder=mkdtempSync(join(tmpdir(),'prepared-assets-'));
  try{
    for(const t of manifest.targets){
      const binary=`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,runtime=`rsrs-${t.triple}-runtime.tar.gz`;
      const content=Buffer.from(t.triple),sha256=createHash('sha256').update(content).digest('hex');
      writeFileSync(join(folder,binary),content);writeFileSync(join(folder,runtime),content);
      writeFileSync(join(folder,`cli-build-${t.triple}.json`),JSON.stringify({schema_version:1,git_sha:sha,version,target:t.triple,
        binary_file:binary,runtime_file:runtime,binary_sha256:sha256,runtime_sha256:sha256}));
    }
    assert.equal(preparedAssets(folder,source,manifest).length,12);
    writeFileSync(join(folder,`rsrs-${targets[0][0]}`),'tampered');assert.throws(()=>preparedAssets(folder,source,manifest));
  }finally{rmSync(folder,{recursive:true,force:true});}
});
test('actual synthetic npm packs must match the full exact-version local pack index',()=>{
  const folder=mkdtempSync(join(tmpdir(),'prepared-packs-'));
  try{
    const packages=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].map((name,i)=>{
      const file=`pack-${i}.tgz`,bytes=Buffer.from(name);writeFileSync(join(folder,file),bytes);
      return {name,version,file,sha256:createHash('sha256').update(bytes).digest('hex')};
    });
    writeFileSync(join(folder,'source-version.json'),JSON.stringify({schema_version:1,git_sha:sha,version,packages}));
    assert.equal(preparedPacks(folder,source,manifest).length,5);
    writeFileSync(join(folder,packages[0].file),'tampered');assert.throws(()=>preparedPacks(folder,source,manifest));
  }finally{rmSync(folder,{recursive:true,force:true});}
});

test('unpublished preparation proof remains read-only and waits for every original producer',()=>{
  const release=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  const job=release.split('\n  preparation-receipt:\n')[1].split(/\n  [a-z][\w-]*:\n/)[0];
  assert.match(job,/needs: \[plan, validate, native-regression, native-regression-critical, native-regression-critical-readonly, cloud-sweep, native-migration, migration-gate, api-smoke\]/);
  assert.match(job,/needs.native-regression-critical-readonly.result == 'skipped'/);
  assert.match(job,/needs.plan.outputs.publish == 'false'/);assert.match(job,/needs.plan.outputs.validation_profile == 'full'/);assert.match(job,/needs.plan.outputs.validation_profile == 'critical'/);assert.match(job,/always\(\)/);
  assert.match(job,/github.ref == 'refs\/heads\/main'/);assert.match(job,/needs.plan.outputs.sha == github.sha/);
  assert.match(job,/contents: read/);assert.match(job,/actions: read/);assert.match(job,/persist-credentials: false/);
  assert.doesNotMatch(job,/contents: write|actions: write|id-token:|secrets\.|npm publish|npm install|fetch-core-sdk|concurrency:/);
  assert.match(job,/retention-days: 1/);assert.match(job,/if-no-files-found: error/);
  const publisher=release.split('\n  publish:\n')[1].split(/\n  [a-z][\w-]*:\n/)[0];
  assert.match(publisher,/needs.validate.result == 'success'/);
  assert.match(publisher,/needs.publication-ready.result == 'success'/);
  assert.doesNotMatch(publisher,/needs.preparation-receipt.result/);
  assert.match(publisher,/needs.prepared-import.result == 'success'/);
  assert.match(publisher,/needs.validate.result == 'skipped'/);
});

test('actual attester subprocess reads only main-bound mock APIs and rejects stale/foreign proofs before writing',()=>{
  const directory=mkdtempSync(join(tmpdir(),'preparation-process-'));
  try{
    const bin=join(directory,'bin'),assets=join(directory,'assets'),packs=join(directory,'packs');
    for(const folder of [bin,assets,packs])mkdirSync(folder);
    for(const t of manifest.targets){
      const binary=`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,runtime=`rsrs-${t.triple}-runtime.tar.gz`;
      const bytes=Buffer.from(t.triple),sha256=createHash('sha256').update(bytes).digest('hex');
      writeFileSync(join(assets,binary),bytes);writeFileSync(join(assets,runtime),bytes);
      writeFileSync(join(assets,`cli-build-${t.triple}.json`),JSON.stringify({schema_version:1,git_sha:sha,version,target:t.triple,
        binary_file:binary,runtime_file:runtime,binary_sha256:sha256,runtime_sha256:sha256}));
    }
    const packages=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].map((name,i)=>{
      const file=`pack-${i}.tgz`,bytes=Buffer.from(name);writeFileSync(join(packs,file),bytes);
      return {name,version,file,sha256:createHash('sha256').update(bytes).digest('hex')};
    });
    writeFileSync(join(packs,'source-version.json'),JSON.stringify({schema_version:1,git_sha:sha,version,packages}));
    const lock={targets:Object.fromEntries(targets.map(([target])=>[target,{sdk_version:'1.0.2-dev.12',manifest_sha256:hash,archive_sha256:hash}]))};
    const inputs={'Cargo.lock':'synthetic locked dependencies','rust-toolchain.toml':'[toolchain]\nchannel="1.95.0"',
      'sdk/core-sdk.lock.json':JSON.stringify(lock),'crates/core-sdk/core-sdk.lock.json':JSON.stringify(lock),
      '.github/workflows/release.yml':'synthetic trusted Release',
      '.github/workflows/release-validation.yml':'synthetic trusted build and package validation',
      '.github/workflows/release-native-validation.yml':'synthetic trusted native validation',
      'npm/artifact-manifest.json':JSON.stringify({...manifest,cliVersion:'1.0.16'})};
    writeFileSync(join(bin,'git'),`#!${process.execPath}\nconst fs=require('fs'),s=JSON.parse(fs.readFileSync(process.env.MOCK_PREPARATION)),a=process.argv.slice(2);if(a.join(' ')==='rev-parse HEAD')console.log(s.source.sha);else if(a[0]==='show'&&a[1].startsWith(s.source.sha+':')){const x=s.inputs[a[1].slice(41)];if(x===undefined)throw Error('Unknown source input');process.stdout.write(x);}else throw Error('Unexpected git action');\n`,{mode:0o755});
    writeFileSync(join(bin,'gh'),`#!${process.execPath}\nconst fs=require('fs'),s=JSON.parse(fs.readFileSync(process.env.MOCK_PREPARATION)),a=process.argv.slice(2),p=a.at(-1),base='repos/risense-ai/respire-cli/actions/';if(a[0]!=='api'||a.some(x=>['--method','-X','POST','PATCH','PUT','DELETE'].includes(x)))throw Error('Non-read API action');fs.appendFileSync(process.env.MOCK_READS,p+'\\n');let r;if(p===base+'runs/700')r=s.run;else if(p===base+'runs/600')r=s.ci;else if(p===base+'runs/700/attempts/1/jobs?per_page=10')r=[{jobs:s.jobs}];else if(p===base+'runs/700/artifacts?per_page=100')r=[{artifacts:s.artifacts}];else if(p===base+'workflows/ci.yml/runs?head_sha='+s.source.sha+'&per_page=100')r=[{workflow_runs:[s.ci]}];else throw Error('Unexpected API scope');console.log(JSON.stringify(r));\n`,{mode:0o755});
    const state=join(directory,'state.json'),reads=join(directory,'reads'),output=join(directory,'proof.json');
    const env={PATH:bin+':'+process.env.PATH,HOME:directory,TMPDIR:directory,MOCK_PREPARATION:state,MOCK_READS:reads,
      GITHUB_REPOSITORY:source.repository,GITHUB_RUN_ID:'700',GITHUB_RUN_ATTEMPT:'1',GITHUB_EVENT_NAME:'workflow_dispatch',
      GITHUB_REF:'refs/heads/main',GITHUB_SHA:sha,CLI_SHA:sha,CLI_VERSION:version};
    for(const [index,mutate] of [()=>{},s=>s.run.head_sha='f'.repeat(40),s=>s.ci.event='workflow_dispatch',s=>s.jobs[0].conclusion='skipped',s=>s.run.run_attempt=2].entries()){
      const {context}=fixture(),value={...context,run:{...context.run,status:'in_progress'},inputs};
      value.jobs.at(-1).status='in_progress';mutate(value);
      writeFileSync(state,JSON.stringify(value));rmSync(output,{force:true});
      const result=spawnSync(process.execPath,[fileURLToPath(new URL('./release-preparation.mjs',import.meta.url)),'attest',assets,packs,output],{env,encoding:'utf8',timeout:15000});
      if(index===0){
        assert.equal(result.status,0,result.stderr);const proof=JSON.parse(readFileSync(output));
        assert.deepEqual(proof.source,source);assert.equal(Object.keys(proof.identity.hashes).length,8);
        assert.equal(proof.assets.length,12);assert.equal(proof.packs.length,5);assert.equal(proof.state,'validated-unpublished');
      }else{assert.notEqual(result.status,0);assert.equal(existsSync(output),false);}
    }
    assert(readFileSync(reads,'utf8').trim().split('\n').every(p=>p.startsWith('repos/risense-ai/respire-cli/actions/')));
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test('preparation profiles preserve old full proofs and reject critical as full authority',()=>{
  const old=fixture();delete old.receipt.validation_profile;validatePreparation(old.receipt,old.context);
  const f=fixture(),c=f.context;
  c.jobs=c.jobs.filter(j=>!j.name.startsWith('cloud-sweep (')&&!j.name.startsWith('Native migration (')&&!j.name.startsWith('Migration gate ('));
  c.jobs.at(-1).status='in_progress';delete c.jobs.at(-1).conclusion;delete c.jobs.at(-1).completed_at;c.run.status='in_progress';
  const receipt=createPreparation({...c,profile:'critical'});
  Object.assign(c.jobs.at(-1),{status:'completed',conclusion:'success',completed_at:time(4)});c.run.status='completed';
  assert.equal(receipt.validation_profile,'critical');validatePreparation(receipt,{...c,validation_profile:'critical'});
  assert.throws(()=>validatePreparation(receipt,{...c,validation_profile:'full'}));
  for(const profile of [undefined,'full','invalid']){const r=structuredClone(receipt);if(profile===undefined)delete r.validation_profile;else r.validation_profile=profile;assert.throws(()=>validatePreparation(r,c))}
  const skipped=structuredClone(c);skipped.jobs.find(j=>j.name.startsWith('native-regression / Native')).conclusion='skipped';assert.throws(()=>validatePreparation(receipt,skipped));
});
