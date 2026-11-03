import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,rmSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {readFence,fenceBody,assertFenceOwner,assertFencePackages,assertReusableRelease,releaseVersionClaims} from './publication-fence.mjs';
const m=JSON.parse(readFileSync(new URL('../artifact-manifest.json',import.meta.url))); m.npmScope = '@rsrsai/cli'; // Historical receipt layout.
const c={repository:'risense-ai/respire-cli',version:'1.2.3',source_sha:'a'.repeat(40),run_id:'700',first_attempt:'1'};
const packages=[...m.targets.map(t=>t.pkg),m.npmScope].map(name=>({name,version:c.version,integrity:'sha512-'+'a'.repeat(86)+'==',shasum:'b'.repeat(40)}));
const prepared={schema:1,kind:'npm-version-fence',...c,phase:'prepared',package_names:[...packages.map(p=>p.name),'rsrs-cli'].sort(),scoped_packages:null,created_at:'2026-10-27T00:00:00Z'};
const fenced={...prepared,phase:'fenced',scoped_packages:packages};
const release=f=>({draft:true,tag_name:'v'+c.version,target_commitish:c.source_sha,prerelease:false,assets:[],body:fenceBody('Synthetic release notes',f)});

test('durable owner binds repository, package inventory, source and version across all attempts',()=>{
  const body=fenceBody('Synthetic release notes',fenced);assert.deepEqual(readFence(body),fenced);
  assert.equal(assertFenceOwner(fenced,c,m),fenced);assert.equal(assertFenceOwner(fenced,{...c,first_attempt:'2'},m),fenced);
  for(const change of [{run_id:'701'},{repository:'other/repo'},{version:'1.2.4'},{source_sha:'f'.repeat(40)}])assert.throws(()=>assertFenceOwner(fenced,{...c,...change},m));
  assertFencePackages(fenced,packages);
  const direct = {...m,npmScope:'rsrs-cli'};
  const directPackages = [...packages.filter(p=>p.name!==m.npmScope),{...packages.at(-1),name:'rsrs-cli'}];
  const directFence = {...fenced,schema:2,package_names:directPackages.map(p=>p.name).sort(),scoped_packages:directPackages};
  assertFenceOwner(directFence,c,direct);assertFencePackages(directFence,directPackages);
  assert.deepEqual(readFence(fenceBody('Direct publication',directFence)),directFence);
  assert.throws(()=>assertFencePackages(directFence,directPackages.filter(p=>p.name!=='rsrs-cli')));
  assert.throws(()=>fenceBody(fenceBody('Direct publication',directFence),{...directFence,schema:1}));
  assert.throws(()=>assertFencePackages(fenced,[...packages.slice(1)]));
  assert.throws(()=>assertFencePackages(fenced,[{...packages[0],shasum:'c'.repeat(40)},...packages.slice(1)]));
  assert.throws(()=>assertFencePackages(prepared,packages.map(p=>({...p,version:'1.2.4'}))));
  assert.throws(()=>fenceBody('notes',{...fenced,scoped_packages:packages.map(p=>({...p,version:'1.2.4'}))}));
});
test('regenerating notes cannot erase, downgrade or replace earlier unknown-write evidence',()=>{
  const body=fenceBody('Human notes',fenced);
  assert.throws(()=>fenceBody(body,prepared));
  assert.throws(()=>fenceBody(body,{...fenced,run_id:'701'}));
  assert.throws(()=>fenceBody(body,{...fenced,scoped_packages:[]}));
  assert.deepEqual(readFence(fenceBody(body,fenced)),fenced);
  assert.throws(()=>readFence(body+'\n'+body));
  assert.throws(()=>readFence('<!-- rsrs-npm-write-fence:truncated'));
});
test('unbound existing stable drafts and public versions cannot be inferred safe from registry absence',()=>{
  const r=release(fenced);assert.equal(assertReusableRelease(r,c,m).run_id,'700');
  assert.throws(()=>assertReusableRelease({...r,body:'legacy stable draft'},c,m),/no bound npm intent/);
  assert.throws(()=>assertReusableRelease({...r,draft:false},c,m));
  const dev={...c,version:'1.2.3-dev.1'};
  const reservation={...r,tag_name:'v'+dev.version,prerelease:true,body:'Release workflow run: 700'};
  assert.equal(assertReusableRelease(reservation,dev,m),null);
  assert.throws(()=>assertReusableRelease({...reservation,body:'Release workflow run: 699'},dev,m));
  assert.throws(()=>assertReusableRelease({...reservation,assets:[{id:1}]},dev,m));
});
test('two real Release-run processes: old unknown + continuous registry 404 never causes another npm publish',t=>{
  const script=fileURLToPath(new URL('./fixtures/publication-crossrun.mjs',import.meta.url));
  const root=fileURLToPath(new URL('../../',import.meta.url));
  const result=spawnSync(process.execPath,[script,root],{encoding:'utf8',timeout:20000});
  assert.equal(result.error,undefined);assert.equal(result.status,0,result.stderr);
  const report=JSON.parse(result.stdout);t.after(()=>rmSync(report.root,{recursive:true,force:true}));
  assert.equal(report.runs[0].status,1);assert.match(report.runs[0].stderr,/uncertain/);
  assert.equal(report.runs[1].status,1);assert.match(report.runs[1].stderr,/fenced by previous Release run 700/);
  assert.equal(report.publish_calls,1);assert.deepEqual(report.write_runs,['700']);
  assert.deepEqual(report.all_npm_calls,['700 pack','700 publish']);assert.equal(report.fence_phase,'fenced');assert.equal(report.fence_owner,'700');
});
test('observed untagged draft shape reserves its intent and cannot relax canonical-tag or owner checks',()=>{
  const untagged={...release(fenced),name:'v'+c.version,tag_name:'untagged-4eefed3edfaad61e6aa3',assets:Array.from({length:12},(_,id)=>({id}))};
  assert.deepEqual(releaseVersionClaims(untagged),[c.version]);
  assert.throws(()=>assertReusableRelease(untagged,c,m),/Existing Release source\/version\/draft differs/);
  assert.throws(()=>assertReusableRelease(untagged,{...c,run_id:'701'},m),/fenced by previous Release run 700/);
});
test('full guard PATCH/GET preserves explicit tag; later untagged intent still refuses another run with registry404',t=>{
  const script=fileURLToPath(new URL('./fixtures/publication-crossrun.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script,fileURLToPath(new URL('../../',import.meta.url)),'untagged'],{encoding:'utf8',timeout:20000});
  assert.equal(result.error,undefined);assert.equal(result.status,0,result.stderr);
  const report=JSON.parse(result.stdout);t.after(()=>rmSync(report.root,{recursive:true,force:true}));
  assert.match(report.runs[0].stderr,/uncertain/);assert.match(report.runs[1].stderr,/fenced by previous Release run 700/);
  assert.equal(report.publish_calls,1);assert.deepEqual(report.write_runs,['700']);
  assert.deepEqual(report.all_npm_calls,['700 pack','700 publish']);assert.equal(report.fence_phase,'fenced');assert.equal(report.fence_owner,'700');
});
test('a second canonical draft cannot conceal the original untagged unknown-write owner',t=>{
  const script=fileURLToPath(new URL('./fixtures/publication-crossrun.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script,fileURLToPath(new URL('../../',import.meta.url)),'duplicate-untagged'],{encoding:'utf8',timeout:20000});
  assert.equal(result.status,0,result.stderr);const report=JSON.parse(result.stdout);
  t.after(()=>rmSync(report.root,{recursive:true,force:true}));
  assert.match(report.runs[0].stderr,/uncertain/);assert.match(report.runs[1].stderr,/Duplicate version Release/);
  assert.equal(report.publish_calls,1);assert.deepEqual(report.write_runs,['700']);assert.equal(report.fence_owner,'700');
});
test('workflow guards a previous owner before replacing draft notes or clobbering assets',()=>{
  const w=readFileSync(new URL('../../.github/workflows/release.yml',import.meta.url),'utf8').replace(/\r\n/g,'\n');
  assert(w.indexOf('guard-reservation-accepted')<w.indexOf("gh',['release','edit',`v${version}`"));
  const publisher=w.split('\n  publish:\n')[1].split('\n  dev6-publication-resume:')[0];
  assert(publisher.indexOf('check-fence-accepted')<publisher.indexOf('npm install --global'));
  assert(publisher.indexOf('bind-fence-notes-accepted')<publisher.indexOf('gh release upload'));
  assert(publisher.indexOf('guard-accepted')<publisher.indexOf('--publish --accepted-only'));
});
