import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {canonicalEntry, cacheKey, TARGETS} from './sdk-ci-cache.mjs';
import {downloadPrivateSdk as standalone} from './private-sdk-download.mjs';
import {downloadPrivateSdk as packaged} from '../crates/core-sdk/private-sdk-download.mjs';
const target='x86_64-unknown-linux-gnu', bytes=Buffer.from('synthetic SDK bytes');
const digest=createHash('sha256').update(bytes).digest('hex');
function entry(version,t=target) {
 const base=`https://github.com/risense-ai/respire-core/releases/download/sdk-v${version}/respire-core-sdk-${t}`;
 return {sdk_version:version,private_repository:'risense-ai/respire-core',release_tag:`sdk-v${version}`,url:base+'.manifest.json',archive_url:base+'.tar.gz',manifest_sha256:digest,archive_sha256:digest,redistribution:'approved'};
}
for (const version of ['1.0.2-dev.24','1.1.0-dev.1']) {
 test(`${version} keeps distinct canonical cache keys for all targets`,()=>{
  const keys=TARGETS.map(t=>cacheKey(t,canonicalEntry(t,entry(version,t))));
  assert.equal(new Set(keys).size,TARGETS.length);
  assert.notEqual(cacheKey(target,entry(version)),cacheKey(target,entry('1.0.2-dev.11')));
 });
 for(const [name,download] of [['standalone',standalone],['packaged',packaged]]) {
  test(`${name} accepts ${version} only with pinned bytes and trusted context`,async()=>{
   for(const kind of ['manifest','archive']) {
    let calls=0;
    const transport=async(url)=>{calls++; return url.includes('/releases/tags/')
     ? new Response(JSON.stringify({id:1,tag_name:`sdk-v${version}`,draft:false,prerelease:true,assets:[{id:123,name:`respire-core-sdk-${target}.${kind==='manifest'?'manifest.json':'tar.gz'}`,size:bytes.length,digest:`sha256:${digest}`}]}))
     : new Response(bytes);};
    const options={env:{CORE_SDK_READ_TOKEN:'synthetic-fixture-token'},transport};
    assert.deepEqual(await download(entry(version),target,kind,options),bytes);
    assert.equal(calls,2);
    const broken=entry(version);broken[kind==='manifest'?'manifest_sha256':'archive_sha256']='c'.repeat(64);
    await assert.rejects(download(broken,target,kind,options));
    calls=0;
    await assert.rejects(download(entry(version),target,kind,{...options,env:{...options.env,GITHUB_EVENT_NAME:'pull_request'}}),/forbidden in PR/);
    assert.equal(calls,0);
   }
  });
 }
}
for(const version of ['1.1.0','1.1.0-dev.0','1.1.0-dev.01','1.1.0-rc.1','1.1.0-dev.1+metadata','1.1.1-dev.1','2.0.0-dev.1']) {
 test(`unsupported SDK ${version} cannot reach cache or network`,async()=>{
  assert.throws(()=>canonicalEntry(target,entry(version)),/tag\/version/);
  for(const download of [standalone,packaged]) {
   let calls=0;
   await assert.rejects(download(entry(version),target,'manifest',{env:{},transport:async()=>{calls++;}}),/version/);
   assert.equal(calls,0);
  }
 });
}
