// Real Node helper processes and real ZIP bytes; all GitHub responses and
// payloads are synthetic. No npm submission, profile, model or remote API.
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,existsSync,cpSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {importedAnchor} from '../prepared-import.mjs';

const sha='a'.repeat(40),workflowSha='c'.repeat(40),hash='b'.repeat(64),version='1.2.3-dev.4';
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const script=name=>fileURLToPath(new URL('../'+name,import.meta.url));
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
export function preparedConsumerFlow({arm64=false}={}){
  const root=mkdtempSync(join(tmpdir(),'prepared-consumer-flow-'));
  try{
    const bin=join(root,'bin'),assets=join(root,'assets'),packs=join(root,'packs'),stateFile=join(root,'state.json');
    for(const folder of [bin,assets,packs])mkdirSync(folder);
    const triples=['x86_64-unknown-linux-gnu','x86_64-unknown-linux-musl','aarch64-apple-darwin','x86_64-pc-windows-msvc'];
    if(arm64)triples.push('aarch64-unknown-linux-gnu','aarch64-unknown-linux-musl');
    const migration=triples.filter(t=>t.includes('windows')||t.includes('apple-darwin'));
    const manifest={cliVersion:'1.0.16',npmScope:'@rsrsai/cli',targets:triples.map((triple,i)=>({triple,pkg:`@rsrsai/platform-${i}`}))};
    for(const t of manifest.targets){
      const binary=`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`,runtime=`rsrs-${t.triple}-runtime.tar.gz`;
      const b=Buffer.from('binary '+t.triple),r=Buffer.from('runtime '+t.triple);
      writeFileSync(join(assets,binary),b);writeFileSync(join(assets,runtime),r);
      writeFileSync(join(assets,`cli-build-${t.triple}.json`),JSON.stringify({schema_version:1,git_sha:sha,version,target:t.triple,
        binary_file:binary,runtime_file:runtime,binary_sha256:digest(b),runtime_sha256:digest(r)}));
    }
    const packages=[...manifest.targets.map(t=>t.pkg),manifest.npmScope].map((name,i)=>{
      const file=`pack-${i}.tgz`,bytes=Buffer.from('synthetic pack '+name);writeFileSync(join(packs,file),bytes);
      return {name,version,file,sha256:digest(bytes)};
    });
    writeFileSync(join(packs,'source-version.json'),JSON.stringify({schema_version:1,git_sha:sha,version,packages}));
    const lock={targets:Object.fromEntries(triples.map(target=>[target,{sdk_version:'1.0.2-dev.12',manifest_sha256:hash,archive_sha256:hash}]))};
    const old=n=>new Date(Date.now()-n*60000).toISOString();
    const base={path:'.github/workflows/release.yml',event:'workflow_dispatch',head_branch:'main',head_repository:{full_name:'risense-ai/respire-cli'}};
    const job=name=>({name,status:'completed',conclusion:'success',started_at:old(5),completed_at:old(3)});
    const state={sha,version,inputs:{'Cargo.lock':'synthetic locked inputs','rust-toolchain.toml':'[toolchain]\nchannel="1.95.0"',
      'sdk/core-sdk.lock.json':JSON.stringify(lock),'crates/core-sdk/core-sdk.lock.json':JSON.stringify(lock),
      '.github/workflows/release.yml':'synthetic trusted Release',
      '.github/workflows/release-validation.yml':'synthetic trusted builds and packaging',
      '.github/workflows/release-native-validation.yml':'synthetic trusted native models',
      'npm/artifact-manifest.json':JSON.stringify(manifest)},
      original:{...base,id:700,run_attempt:1,head_sha:sha,status:'in_progress',created_at:old(8),updated_at:old(2)},
      current:{...base,id:701,run_attempt:1,head_sha:workflowSha,status:'in_progress',created_at:old(1)},
      ci:{...base,id:600,run_attempt:1,path:'.github/workflows/ci.yml',event:'push',head_sha:sha,status:'completed',conclusion:'success',run_started_at:old(7),updated_at:old(4)},
      originalJobs:[...triples.map(t=>job(`validate / Release (${t})`)),job('validate / npm-dry-run'),
        ...triples.map(t=>job(`native-regression / Native (${t})`)),...triples.slice(1).map(t=>job(`cloud-sweep (runner, ${t})`)),
        ...migration.flatMap(t=>[job(`Native migration (${t})`),job(`Migration gate (${t})`)]),job('api-smoke')],
      originalArtifacts:[...triples.map(t=>`cli-release-${t}`),'npm-release-validation','npm-release-packages'].map((name,i)=>({id:i+1,name,
        expired:false,size_in_bytes:100,digest:'sha256:'+hash,workflow_run:{id:700,head_sha:sha}})),currentArtifacts:[],currentJobs:[]};
    const env={PATH:bin+':'+process.env.PATH,HOME:root,TMPDIR:root,MOCK_STATE:stateFile,
      GITHUB_REPOSITORY:'risense-ai/respire-cli',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/main',
      GITHUB_RUN_ID:'700',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:sha,CLI_SHA:sha,CLI_VERSION:version,GH_TOKEN:'synthetic-artifact-read',GITHUB_OUTPUT:join(root,'outputs')};
    const save=()=>writeFileSync(stateFile,JSON.stringify(state));
    writeFileSync(join(bin,'git'),`#!${process.execPath}\nconst fs=require('fs'),s=JSON.parse(fs.readFileSync(process.env.MOCK_STATE)),a=process.argv.slice(2);if(a.join(' ')==='rev-parse HEAD')console.log(s.sha);else if(a.join(' ')==='merge-base --is-ancestor '+s.sha+' origin/main'){}else if(a[0]==='show'&&a[1].startsWith(s.sha+':')){const v=s.inputs[a[1].slice(41)];if(v===undefined)throw Error('Unknown source input');process.stdout.write(v);}else throw Error('Unexpected git action');\n`,{mode:0o755});
    writeFileSync(join(bin,'gh'),`#!${process.execPath}
const fs=require('fs'),s=JSON.parse(fs.readFileSync(process.env.MOCK_STATE)),a=process.argv.slice(2),p=a.at(-1),base='repos/risense-ai/respire-cli/actions/';
if(s.allowFinalization&&a[0]==='release'&&a[1]==='edit'){
 if(fs.existsSync('edited-release'))throw Error('Publication must never replay');
 fs.writeFileSync('edited-release','synthetic confirmed edit');process.exit(0);
}
if(a[0]!=='api'||a.some(x=>['--method','-X','POST','PATCH','PUT','DELETE'].includes(x)))throw Error('Only read APIs permitted');
if(p.endsWith('/jobs?per_page=10')&&!fs.existsSync('jobs-read-fault')){
 fs.writeFileSync('jobs-read-fault','one transient read');console.error('gh: Server Error (HTTP 502)');process.exit(1);
}
let r;
if(p===base+'runs/700')r=s.original;else if(p===base+'runs/701')r=s.current;else if(p===base+'runs/600')r=s.ci;
else if(p===base+'runs/700/attempts/1/jobs?per_page=10')r=[{jobs:s.originalJobs.slice(0,10)},{jobs:s.originalJobs.slice(10)}];
else if(p===base+'runs/701/attempts/1/jobs?per_page=10')r=[{jobs:s.currentJobs.slice(0,10)},{jobs:s.currentJobs.slice(10)}];
else if(p===base+'runs/700/artifacts?per_page=100')r=[{artifacts:s.originalArtifacts}];
else if(p===base+'runs/701/artifacts?per_page=100')r=[{artifacts:s.currentArtifacts}];
else if(p===base+'workflows/ci.yml/runs?head_sha='+s.sha+'&per_page=100')r=[{workflow_runs:[s.ci]}];
else if(s.allowFinalization&&p==='repos/risense-ai/respire-cli/releases/300')r=fs.existsSync('edited-release')?{...s.release,draft:false,published_at:s.acceptedAt}:s.release;
else if(s.allowFinalization&&p==='repos/risense-ai/respire-cli/git/ref/tags/v'+s.version)r={object:{type:'commit',sha:s.sha}};
else if(s.allowFinalization&&p==='repos/risense-ai/respire-cli/commits/'+s.sha)r={sha:s.sha,commit:{committer:{date:s.original.created_at}}};
else if(s.allowFinalization&&p===base+'runs/702/attempts/1')r=s.aliasRun;
else if(s.allowFinalization&&p===base+'runs/702/attempts/1/jobs?per_page=10')r=[{jobs:[{name:'publish-integrated',status:'completed',conclusion:'success'}]}];
else if(p.startsWith(base+'artifacts/')&&p.endsWith('/zip')){const id=Number(p.slice((base+'artifacts/').length,-4)),x=[...s.originalArtifacts,...s.currentArtifacts].find(x=>x.id===id);if(!x?._zip)throw Error('Missing bound ZIP');process.stdout.write(fs.readFileSync(x._zip));process.exit(0);}
else throw Error('Unexpected API scope');process.stdout.write(JSON.stringify(r));
`,{mode:0o755});
    function run(name,args=[],extra={}){
      save();const result=spawnSync(process.execPath,[script(name),...args],{cwd:root,env:{...env,...extra},encoding:'utf8',timeout:20000});
      return result;
    }
    function success(result){requireValue(result.status===0,result.stderr||'process failed');}
    function zipReceipt(id,name,file,owner,payload){
      const output=join(root,`artifact-${id}.zip`);
      const result=spawnSync('python3',['-c','import sys,zipfile\nwith zipfile.ZipFile(sys.argv[1],"w",compression=zipfile.ZIP_DEFLATED) as z: z.writestr(sys.argv[2],sys.stdin.read())',output,file],
        {input:JSON.stringify(payload),env:{PATH:process.env.PATH,HOME:root,TMPDIR:root},encoding:'utf8',timeout:10000});success(result);
      const bytes=readFileSync(output);return {id,name,created_at:new Date().toISOString(),expired:false,size_in_bytes:bytes.length,digest:'sha256:'+digest(bytes),workflow_run:{id:owner.id,head_sha:owner.head_sha},_zip:output};
    }
    const producer={id:900,name:'preparation-receipt',status:'in_progress',started_at:new Date().toISOString()};
    state.originalJobs.push(producer);
    const proofFile=join(root,'release-prepared.json');success(run('release-preparation.mjs',['attest',assets,packs,proofFile]));
    const proof=JSON.parse(readFileSync(proofFile));
    state.originalArtifacts.push(zipReceipt(90,'release-prepared-700-1','release-prepared.json',state.original,proof));
    Object.assign(producer,{status:'completed',conclusion:'success',completed_at:new Date().toISOString()});
    state.original={...state.original,status:'completed',conclusion:'success',updated_at:producer.completed_at};
    state.current.created_at=new Date().toISOString();
    env.GITHUB_RUN_ID='701';env.GITHUB_SHA=workflowSha;env.PREPARED_RUN='700';
    success(run('release-preparation.mjs',['inspect']));
    const selected=Object.fromEntries(readFileSync(env.GITHUB_OUTPUT,'utf8').trim().split('\n').map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)];}));
    Object.assign(env,{PREPARED_ATTEMPT:selected.prepared_attempt,PREPARED_ARTIFACT_ID:selected.prepared_artifact_id,
      PREPARED_ARTIFACT_DIGEST:selected.prepared_artifact_digest,PREPARED_RECEIPT_SHA256:selected.prepared_receipt_sha256});
    const intent=JSON.parse(readFileSync(join(root,'prepared-consumer.json')));
    state.currentArtifacts.push(zipReceipt(91,'prepared-consumer-701-1','prepared-consumer.json',state.current,intent));
    state.currentJobs=[{id:1000,name:'prepared-import',status:'in_progress',started_at:new Date().toISOString()}];env.GITHUB_JOB='prepared-import';
    success(run('prepared-import.mjs',['consumer']));
    const importFile=join(root,'prepared-import.json');success(run('prepared-import.mjs',['record',assets,packs,importFile]));
    const imported=JSON.parse(readFileSync(importFile));
    state.currentArtifacts.push(zipReceipt(92,'prepared-import-701-1','prepared-import.json',state.current,imported));
    state.currentJobs[0]={...state.currentJobs[0],status:'completed',conclusion:'success',completed_at:new Date().toISOString()};
    env.GITHUB_JOB='publication-ready';success(run('prepared-import.mjs',['readiness']));
    const baseline=structuredClone(state),negative=[];
    for(const [name,mutate] of [
      ['original-gate-failed',s=>s.originalJobs[0].conclusion='skipped'],
      ['import-job-failed',s=>s.currentJobs[0].conclusion='failure'],
      ['foreign-workflow-owner',s=>s.current.head_repository.full_name='fork/respire-cli'],
      ['source-attempt-stale',s=>s.original.run_attempt=2],
      ['consumer-not-registered',s=>s.currentArtifacts=s.currentArtifacts.filter(a=>a.id!==91)],
      ['current-proof-expired',s=>s.currentArtifacts.find(a=>a.id===92).expired=true],
      ['current-proof-digest-drift',s=>s.currentArtifacts.find(a=>a.id===92).digest='sha256:'+'f'.repeat(64)]]){
      Object.assign(state,structuredClone(baseline));mutate(state);
      const result=run('prepared-import.mjs',['readiness']);requireValue(result.status!==0,`Unsafe case accepted: ${name}`);negative.push(name);
    }
    Object.assign(state,structuredClone(baseline));
    // Guard the actual irreversible-write authorization helper, not only shape checks.
    const writeGuard=join(root,'write-guard.mjs');
    const source={repository:'risense-ai/respire-cli',workflow:'.github/workflows/release.yml',run_id:'701',run_attempt:1,sha,version,channel:'dev',release_id:300};
    const finalOutputs=Object.fromEntries(readFileSync(env.GITHUB_OUTPUT,'utf8').trim().split('\n').map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)];}));
    Object.assign(env,{IMPORTED_ARTIFACT_ID:finalOutputs.imported_artifact_id,IMPORTED_ARTIFACT_DIGEST:finalOutputs.imported_artifact_digest,
      IMPORTED_RECEIPT_SHA256:finalOutputs.imported_receipt_sha256});
    writeFileSync(writeGuard,`import {assertImportedContents,importPinFromEnv} from ${JSON.stringify(new URL('../prepared-import.mjs',import.meta.url).href)};assertImportedContents(${JSON.stringify(source)},${JSON.stringify({...manifest,cliVersion:version})},${JSON.stringify(assets)},${JSON.stringify(packs)},importPinFromEnv());`);
    function authorize(){save();return spawnSync(process.execPath,[writeGuard],{cwd:root,env,encoding:'utf8',timeout:20000});}
    success(authorize());
    const binary=join(assets,'rsrs-'+triples[0]),originalBinary=readFileSync(binary);writeFileSync(binary,'tampered binary');
    requireValue(authorize().status!==0,'Tampered current binary authorized');writeFileSync(binary,originalBinary);
    const pack=join(packs,packages[0].file),originalPack=readFileSync(pack);writeFileSync(pack,'tampered tarball');
    requireValue(authorize().status!==0,'Tampered current tarball authorized');writeFileSync(pack,originalPack);
    requireValue(authorize().status===0,'Restored exact current copies did not authorize');

    // Execute the real final coordinator against a synthetic Release edit.
    // The complete validation clock must precede this publication trigger;
    // source/preparation/import/acceptance metrics remain separate.
    mkdirSync(join(root,'npm'));writeFileSync(join(root,'npm/artifact-manifest.json'),JSON.stringify({...manifest,cliVersion:version}));
    const identity=name=>({name,version,integrity:'sha512-'+createHash('sha512').update(name).digest('base64'),shasum:'e'.repeat(40)});
    const ack=p=>({...p,schema:1,state:'accepted',evidence:'npm-exit-zero',exit_code:0,signal:null,accepted_at:new Date(Date.now()+3600_000).toISOString()});
    const scoped={schema:2,kind:'scoped-accepted',state:'accepted',source,packages:packages.map(p=>identity(p.name)),
      acceptances:packages.map(p=>ack(identity(p.name))),assets:proof.assets.map(a=>({name:a.file,size:a.size,sha256:a.sha256})),
      binaries:manifest.targets.map(t=>{const a=proof.assets.find(a=>a.file===`rsrs-${t.triple}${t.triple.includes('windows')?'.exe':''}`);return {package:t.pkg,target:t.triple,file:a.file,sha256:a.sha256};}),
      validation_origin:importedAnchor(imported,state.currentArtifacts.find(a=>a.id===92),state.current)};
    state.aliasRun={...state.current,id:702,path:'.github/workflows/npm-alias.yml',event:'workflow_run'};
    const alias={schema:2,kind:'alias-accepted',state:'accepted',source,scoped_packages:scoped.packages,alias:identity('rsrs-cli'),
      dependencies:{'@rsrsai/cli':version},publisher:{workflow:state.aliasRun.path,run_id:702,run_attempt:1},acceptance:ack(identity('rsrs-cli'))};
    const complete={schema:2,state:'accepted',source,packages:[...scoped.packages,alias.alias],alias_run:702,alias_attempt:1,alias_receipt:alias};
    state.allowFinalization=true;state.acceptedAt=new Date(Date.now()+10000).toISOString();
    state.release={id:300,draft:true,prerelease:true,tag_name:'v'+version,target_commitish:sha,assets:scoped.assets.map(a=>({...a,state:'uploaded',digest:'sha256:'+a.sha256}))};
    state.currentJobs.push({name:'publication-ready',status:'completed',conclusion:'success',completed_at:new Date().toISOString()});
    // Exercise the actual current workflow snippets against both older four-
    // platform sources and the new six-platform manifest, not current-main assumptions.
    const workflow=readFileSync(new URL('../../../.github/workflows/release.yml',import.meta.url),'utf8');
    const selector=workflow.split('id: platforms\n')[1].match(/node --input-type=module - <<'NODE'\n([\s\S]*?)          NODE/)[1].replace(/^          /gm,'');
    const select=()=>spawnSync(process.execPath,['--input-type=module','-e',selector],{cwd:root,env,encoding:'utf8',timeout:5000});
    success(select());requireValue(readFileSync(env.GITHUB_OUTPUT,'utf8').includes(`arm64=${arm64}\n`),'Copied platforms came from the workflow head rather than selected source');
    const validManifest=readFileSync(join(root,'npm/artifact-manifest.json'));
    const partial=JSON.parse(validManifest);partial.targets=partial.targets.filter(t=>t.triple!=='aarch64-unknown-linux-musl');
    if(!arm64)partial.targets.push({triple:'aarch64-unknown-linux-gnu'});
    writeFileSync(join(root,'npm/artifact-manifest.json'),JSON.stringify(partial));requireValue(select().status!==0,'Partial ARM platform inventory accepted');
    writeFileSync(join(root,'npm/artifact-manifest.json'),validManifest);
    cpSync(assets,join(root,'release-assets'),{recursive:true});
    const assetList=join(root,'release-assets.json');writeFileSync(assetList,JSON.stringify({assets:scoped.assets}));
    const assetCode="const fs=require('fs'),path=require('path');\n"+workflow.match(/const expected=fs.readdirSync\('release-assets'\)\.sort\(\);([\s\S]*?)          NODE/)[0].replace(/          NODE$/,'').replace(/^          /gm,'');
    const assetGate=()=>spawnSync(process.execPath,['-e',assetCode],{cwd:root,env:{...env,RUNNER_TEMP:root},encoding:'utf8',timeout:5000});
    success(assetGate());writeFileSync(assetList,JSON.stringify({assets:scoped.assets.slice(1)}));
    requireValue(assetGate().status!==0,'Missing public asset accepted by actual workflow gate');
    writeFileSync(join(root,'scoped-accepted.json'),JSON.stringify(scoped));writeFileSync(join(root,'publication-accepted.json'),JSON.stringify(complete));
    env.FULL_REGRESSION_REQUIRED='true';
    const originalGate=state.originalJobs[0].conclusion;state.originalJobs[0].conclusion='failure';
    requireValue(run('release-publication.mjs',['finalize-accepted']).status!==0&&!existsSync(join(root,'edited-release')),'Failed original gates published a Release');
    state.originalJobs[0].conclusion=originalGate;
    success(run('release-publication.mjs',['finalize-accepted']));
    const report=JSON.parse(readFileSync(join(root,'publication-accepted.json')));
    const lastAck=new Date(Math.max(...[...scoped.acceptances,alias.acceptance].map(p=>Date.parse(p.accepted_at)))).toISOString();
    requireValue(report.full_validation==='verified'&&report.public_verification==='pending'&&report.preparation_run_id==='700'&&
      report.accepted_at===state.acceptedAt&&report.accepted_at_source==='github-release-published-at'&&report.all_npm_accepted_at===lastAck&&report.all_npm_accepted_at_source==='max-original-package-acceptance-times'&&
      report.trigger_to_all_npm_accepted_seconds===null&&
      report.source_to_complete_validation_seconds===null&&
      report.full_validation_completed_at===proof.validation.completed_at&&report.import_verified_at===state.currentArtifacts.find(a=>a.id===92).created_at&&
      report.full_validation_completed_at<report.source_run_created_at&&
      report.preparation_duration_seconds===(Date.parse(producer.completed_at)-Date.parse(state.original.created_at))/1000&&
      report.trigger_to_accepted_seconds===(Date.parse(state.acceptedAt)-Date.parse(state.current.created_at))/1000,
      'Preparation/publication timing conflated or fabricated public verification');
    return {positive:['original-attest','selected-proof','registered-consumer','verified-import','completed-import-readiness','mandatory-write-byte-check'],
      rejected:[...negative,'tampered-current-binary','tampered-current-tarball'],source_sha:sha,workflow_sha:workflowSha,
      finalized:true,platform_count:triples.length,scope:'synthetic GitHub/git and local Release edit; actual Node/ZIP/file checks; no remote writes, npm writes or real native acceptance'};
  }finally{rmSync(root,{recursive:true,force:true});}
}
