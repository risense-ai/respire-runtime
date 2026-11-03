import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {TARGETS,cacheKey,planCaches,auditSdkDirectory,canonicalEntry} from './sdk-ci-cache.mjs';
const version='1.0.2-dev.11';
function lock(){return {schema_version:1,targets:Object.fromEntries(TARGETS.map(t=>{const base=`https://github.com/risense-ai/respire-core/releases/download/sdk-v${version}/respire-core-sdk-${t}`;return [t,{sdk_version:version,private_repository:'risense-ai/respire-core',release_tag:'sdk-v'+version,url:base+'.manifest.json',archive_url:base+'.tar.gz',manifest_sha256:'a'.repeat(64),archive_sha256:'b'.repeat(64),redistribution:'approved'}];}))};}
test('plan emits all canonical SDK identities with immutable target-specific keys',()=>{const a=lock(),b=lock();for(const e of Object.values(a.targets))e.unknown_secret='do-not-forward';const result=planCaches(a,b);assert.equal(result.include.length,TARGETS.length);assert(!JSON.stringify(result).includes('do-not-forward'));assert.equal(new Set(result.include.map(x=>x.key)).size,TARGETS.length);});
test('foreign repos, URLs, tags, unknown targets, missing hashes and differing locks are rejected',()=>{for(const [field,value] of [['private_repository','risense-ai/other'],['url','https://evil.invalid'],['release_tag','bad'],['archive_sha256','']]){const a=lock();a.targets[TARGETS[0]][field]=value;assert.throws(()=>planCaches(a,lock()));}const a=lock();a.targets.extra=a.targets[TARGETS[0]];assert.throws(()=>planCaches(a,lock()));const b=lock();b.targets[TARGETS[0]].archive_sha256='c'.repeat(64);assert.throws(()=>planCaches(lock(),b),/differ/);});
test('any pinned hash change gets a different key; no prefix fallback',()=>{const a=lock().targets[TARGETS[0]],b={...a,manifest_sha256:'c'.repeat(64)};assert.notEqual(cacheKey(TARGETS[0],a),cacheKey(TARGETS[0],b));});
test('SDK directory audit permits only exact manifest-listed bytes, never credentials/source extras',()=>{const dir=mkdtempSync(join(tmpdir(),'sdk-cache-audit-'));try{mkdirSync(join(dir,'lib'));const payload=Buffer.from('native fixture'),file={path:'lib/core.a',sha256:createHash('sha256').update(payload).digest('hex')};writeFileSync(join(dir,'lib/core.a'),payload);const m={target:TARGETS[0],sdk_version:version,abi_version:0x10002,inference_thread_contract:1,association_contract:1,models_bundled:false,redistribution:'permitted-under-included-license',files:[file]};const raw=Buffer.from(JSON.stringify(m));writeFileSync(join(dir,'manifest.json'),raw);const e={...lock().targets[TARGETS[0]],manifest_sha256:createHash('sha256').update(raw).digest('hex')};auditSdkDirectory(dir,TARGETS[0],e);writeFileSync(join(dir,'credential.env'),'fake-sensitive-data');assert.throws(()=>auditSdkDirectory(dir,TARGETS[0],e),/Unexpected/);rmSync(join(dir,'credential.env'));writeFileSync(join(dir,'lib/core.a'),'corrupt');assert.throws(()=>auditSdkDirectory(dir,TARGETS[0],e),/corrupt/);}finally{rmSync(dir,{recursive:true});}});
test('cache audit rejects links and unsafe manifest paths',()=>{const dir=mkdtempSync(join(tmpdir(),'sdk-cache-link-'));try{const m={target:TARGETS[0],sdk_version:version,abi_version:0x10002,inference_thread_contract:1,association_contract:1,models_bundled:false,redistribution:'permitted-under-included-license',files:[{path:'../outside',sha256:'a'.repeat(64)}]};const raw=Buffer.from(JSON.stringify(m));writeFileSync(join(dir,'manifest.json'),raw);const e={...lock().targets[TARGETS[0]],manifest_sha256:createHash('sha256').update(raw).digest('hex')};assert.throws(()=>auditSdkDirectory(dir,TARGETS[0],e),/Unsafe/);}finally{rmSync(dir,{recursive:true});}});
test('credential-bearing workflow uses only main tools; native receiver has no secret contract',()=>{const warm=readFileSync(new URL('../.github/workflows/private-sdk-cache.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');const native=readFileSync(new URL('../.github/workflows/token-free-sdk-check.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');assert(warm.includes("github.ref == 'refs/heads/main'"));assert.equal((warm.match(/secrets\.CORE_SDK_READ_TOKEN/g)||[]).length,1);const download=warm.split('\n  download:\n')[1].split('\n  native:\n')[0];assert(download.includes('ref: ${{ github.sha }}'));assert(!download.includes('inputs.reviewed_source_sha'));const receiver=warm.split('\n  native:\n')[1];assert(receiver.includes('uses: ./.github/workflows/token-free-sdk-check.yml'));assert(!/\n\s*secrets:/.test(receiver));assert(!/\n\s*secrets:/.test(native));assert(!native.includes('${{ secrets.'));assert(!warm.includes('upload-artifact'));assert(!native.includes('upload-artifact'));for(const file of ['ci.yml','release-validation.yml','accelerator.yml'])assert(!readFileSync(new URL('../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n').includes('secrets.CORE_SDK_READ_TOKEN'));});
test('native consumers require exact cache keys without prefix fallback',()=>{for(const file of ['ci.yml','release-validation.yml','accelerator.yml','token-free-sdk-check.yml']){const text=readFileSync(new URL('../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');assert(text.includes('enableCrossOsArchive: true'));assert(text.includes('fail-on-cache-miss: true'));for(const section of text.split('- uses: actions/cache/restore@v4').slice(1)){const block=section.split(/\n      - (?:name:|uses:)/)[0];if(block.includes('path: .sdk/'))assert(!block.includes('restore-keys:'));}}});

test('real model probe does not inherit the unit-test Core mode',()=>{const text=readFileSync(new URL('../.github/workflows/token-free-sdk-check.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');const global=text.split('    env:')[1].split('    steps:')[0];assert(!global.includes('RSRS_CORE_TEST_MODE'));assert(text.includes('model install-m3'));assert(text.includes('model probe'));});

test('trusted producer refuses pre-existing SDK directory before any credential request',()=>{
 const dir=mkdtempSync(join(tmpdir(),'sdk-fresh-producer-'));
 try{
  mkdirSync(join(dir,'.sdk',TARGETS[0]),{recursive:true});
  const result=spawnSync(process.execPath,[fileURLToPath(new URL('./sdk-ci-cache.mjs',import.meta.url)),'prepare',TARGETS[0],JSON.stringify(lock().targets[TARGETS[0]])],{cwd:dir,encoding:'utf8',env:{PATH:process.env.PATH,GITHUB_REPOSITORY:'risense-ai/respire-cli',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch'}});
  assert.notEqual(result.status,0);assert.match(result.stderr,/requires a fresh SDK directory/);
 }finally{rmSync(dir,{recursive:true});}
});
test('cache tokens cap selected-source jobs at read and credential producer at write-only',()=>{
 const warm=readFileSync(new URL('../.github/workflows/private-sdk-cache.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
 const plan=warm.split('\n  plan:\n')[1].split('\n  download:\n')[0],producer=warm.split('\n  download:\n')[1].split('\n  native:\n')[0],caller=warm.split('\n  native:\n')[1];
 assert.match(plan,/cache-mode: none/);assert.match(producer,/cache-mode: write-only/);assert.match(producer,/package-manager-cache: false/);assert(!/cache\/restore|uses: actions\/cache@/.test(producer));assert.match(producer,/cache\/save@v4/);assert.match(caller,/cache-mode: read/);
 const reusable=readFileSync(new URL('../.github/workflows/token-free-sdk-check.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');assert.match(reusable,/native-source:\n    cache-mode: read/);
 for(const file of ['ci.yml','release-validation.yml','accelerator.yml']){const text=readFileSync(new URL('../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');assert.match(text,/^cache-mode: read$/m);const consumers=text.replace(/\n  rust-build-save:\n[\s\S]*?(?=\n  [a-z][\w-]*:\n)/g,'');assert(!/uses: actions\/cache(?:@|\/save)/.test(consumers));}
});
test('every SDK cache consumer rejects primary-key prefix matches before source execution',()=>{
 for(const file of ['ci.yml','release-validation.yml','accelerator.yml','token-free-sdk-check.yml']){
  const text=readFileSync(new URL('../.github/workflows/'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');
  for(const match of text.matchAll(/      - uses: actions\/cache\/restore@v4\n([\s\S]*?)(?=      - (?:name:|uses:))/g)){
   if(!match[1].includes('path: .sdk/'))continue;
   const id=match[1].match(/id: ([a-z0-9-]+)/)[1],following=text.slice(match.index+match[0].length).split(/\n      - (?:name:|uses:)/)[0];
   assert(following.includes('steps.'+id+'.outputs.cache-matched-key'));
   const run=following.match(/        run: (.+)/)[1];
   for(const [matched,status] of [['expected',0],['expected-suffix',1],['',1]]){
    const result=spawnSync('bash',['-c',run],{encoding:'utf8',env:{EXPECTED_KEY:'expected',MATCHED_KEY:matched}});assert.equal(result.status,status);
   }
  }
 }
});
