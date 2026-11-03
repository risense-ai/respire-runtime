import {mkdtempSync,mkdirSync,cpSync,writeFileSync,readFileSync,chmodSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const source=process.argv[2],root=mkdtempSync(path.join(tmpdir(),'rsrs-cross-run-'));
mkdirSync(path.join(root,'npm'),{recursive:true});mkdirSync(path.join(root,'bin'));
cpSync(path.join(source,'npm/scripts'),path.join(root,'npm/scripts'),{recursive:true});
const m=JSON.parse(readFileSync(path.join(source,'npm/artifact-manifest.json')));m.cliVersion='1.2.3';m.npmScope='@rsrsai/cli'; // Historical fence layout.
writeFileSync(path.join(root,'npm/artifact-manifest.json'),JSON.stringify(m));
const bytes=Buffer.from('synthetic immutable stable package'),version=m.cliVersion,sha='a'.repeat(40);
const expected=[...m.targets.map(t=>t.pkg),m.npmScope].map(name=>({name,version,filename:name.replace(/[^a-zA-Z0-9.-]/g,'-')+'.tgz',integrity:'sha512-'+createHash('sha512').update(bytes).digest('base64'),shasum:createHash('sha1').update(bytes).digest('hex')}));
for(const p of expected){const d=path.join(root,'npm/dist',p.name);mkdirSync(d,{recursive:true});writeFileSync(path.join(d,'package.json'),JSON.stringify({name:p.name,version}));writeFileSync(path.join(d,'release.pack.json'),JSON.stringify([p]));}
const fence={schema:1,kind:'npm-version-fence',repository:'risense-ai/respire-cli',version,source_sha:sha,run_id:'700',first_attempt:'1',phase:'prepared',package_names:[...expected.map(p=>p.name),'rsrs-cli'].sort(),scoped_packages:null,created_at:'2026-10-27T00:00:00Z'};
const body='Synthetic release notes\n<!-- rsrs-npm-write-fence:'+Buffer.from(JSON.stringify(fence)).toString('base64url')+' -->';
writeFileSync(path.join(root,'fixture.json'),JSON.stringify({expected,bytes:bytes.toString('base64'),release:{id:300,draft:true,prerelease:false,tag_name:'v'+version,target_commitish:sha,body,assets:[]}}));
const executable=(name,code)=>{const p=path.join(root,'bin',name);writeFileSync(p,`#!${process.execPath}\n`+code);chmodSync(p,0o755);};
executable('gh',`const fs=require('fs'),args=process.argv.slice(2),endpoint=args.find(a=>a.startsWith('repos/')),f=JSON.parse(fs.readFileSync('fixture.json'));
let result;
if(endpoint.includes('/actions/runs/'))result={id:Number(process.env.GITHUB_RUN_ID),run_attempt:1,path:'.github/workflows/release.yml',head_repository:{full_name:'risense-ai/respire-cli'},event:'workflow_dispatch',status:'in_progress'};
else if(endpoint.includes('/releases?'))result=[f.release,...(f.extra||[])];
else if(endpoint.endsWith('/releases/300')||endpoint.endsWith('/releases/301')){const release=endpoint.endsWith('/300')?f.release:f.extra[0];if(args.includes('PATCH')){const p=JSON.parse(fs.readFileSync(args[args.indexOf('--input')+1]));release.body=p.body;release.tag_name=p.tag_name||'untagged-observed-draft-shape';fs.writeFileSync('fixture.json',JSON.stringify(f));}result=release;}
else throw Error('Unexpected fake API '+endpoint);
process.stdout.write(JSON.stringify(args.includes('--slurp')?[result]:result));`);
executable('npm',`const fs=require('fs'),path=require('path'),args=process.argv.slice(2),f=JSON.parse(fs.readFileSync(path.join(process.env.FIXTURE_ROOT,'fixture.json')));
fs.appendFileSync(path.join(process.env.FIXTURE_ROOT,'npm-all.log'),process.env.GITHUB_RUN_ID+' '+args[0]+'\\n');
if(args[0]==='pack'){const pkg=JSON.parse(fs.readFileSync('package.json')),p=f.expected.find(p=>p.name===pkg.name),dest=args[args.indexOf('--pack-destination')+1];fs.writeFileSync(path.join(dest,p.filename),Buffer.from(f.bytes,'base64'));process.stdout.write(JSON.stringify([p]));}
else if(args[0]==='publish'){fs.appendFileSync(path.join(process.env.FIXTURE_ROOT,'npm-writes.log'),process.env.GITHUB_RUN_ID+'\\n');process.stderr.write('synthetic submission outcome unknown\\n');process.exitCode=1;}
else throw Error('Unexpected npm operation');`);
writeFileSync(path.join(root,'run.mjs'),`import {main} from './npm/scripts/release-publication.mjs';import {publishAcceptedPackage} from './npm/scripts/registry-publication.mjs';import fs from 'node:fs';
let elapsed=0;const options={timeoutMs:30,pollMs:10,now:()=>elapsed,sleep:async ms=>{elapsed+=ms;},fetchImpl:async()=>new Response('',{status:404})};
try{await main('guard-accepted');const f=JSON.parse(fs.readFileSync('fixture.json'));const p=f.expected[0];await publishAcceptedPackage('npm/dist/'+p.name,p,'latest',options);}catch(error){console.error(error.message);process.exitCode=1;}`);
const env={...process.env};for(const key of Object.keys(env))if(/TOKEN|SECRET|PASSWORD/i.test(key))delete env[key];
Object.assign(env,{PATH:path.join(root,'bin')+path.delimiter+process.env.PATH,GITHUB_REPOSITORY:'risense-ai/respire-cli',GITHUB_RUN_ATTEMPT:'1',CLI_SHA:sha,CLI_VERSION:version,FIXTURE_ROOT:root});
const runs=[];for(const runId of ['700','701']){if(runId==='701'&&['untagged','duplicate-untagged'].includes(process.argv[3])){const f=JSON.parse(readFileSync(path.join(root,'fixture.json')));f.release.tag_name='untagged-observed-draft-shape';f.release.name='v'+version;if(process.argv[3]==='duplicate-untagged'){const next={...fence,run_id:'701'};f.extra=[{...f.release,id:301,tag_name:'v'+version,body:'<!-- rsrs-npm-write-fence:'+Buffer.from(JSON.stringify(next)).toString('base64url')+' -->'}];}writeFileSync(path.join(root,'fixture.json'),JSON.stringify(f));}const r=spawnSync(process.execPath,[path.join(root,'run.mjs')],{cwd:root,env:{...env,GITHUB_RUN_ID:runId},encoding:'utf8',timeout:10000});runs.push({run:runId,status:r.status,error:r.error?.message,stderr:r.stderr.trim()});}
const writes=existsSync(path.join(root,'npm-writes.log'))?readFileSync(path.join(root,'npm-writes.log'),'utf8').trim().split('\n'):[];
const allCalls=existsSync(path.join(root,'npm-all.log'))?readFileSync(path.join(root,'npm-all.log'),'utf8').trim().split('\n'):[];
const finalBody=JSON.parse(readFileSync(path.join(root,'fixture.json'))).release.body;
const savedFence=JSON.parse(Buffer.from(finalBody.match(/rsrs-npm-write-fence:([A-Za-z0-9_-]+)/)[1],'base64url').toString());
console.log(JSON.stringify({root,runs,publish_calls:writes.length,write_runs:writes,all_npm_calls:allCalls,fence_phase:savedFence.phase,fence_owner:savedFence.run_id},null,2));
