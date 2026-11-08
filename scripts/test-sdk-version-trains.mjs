import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {canonicalEntry, cacheKey, archiveCacheKey, observeSdkArchive, TARGETS} from './sdk-ci-cache.mjs';
import {gzipSync} from 'node:zlib';
import {downloadPrivateSdk as standalone} from './private-sdk-download.mjs';
import {downloadPrivateSdk as packaged} from '../crates/core-sdk/private-sdk-download.mjs';
const target='x86_64-unknown-linux-gnu', bytes=Buffer.from('synthetic SDK bytes');
const digest=createHash('sha256').update(bytes).digest('hex');
function entry(version,t=target) {
 const base=`https://github.com/risense-ai/respire-core/releases/download/sdk-v${version}/respire-core-sdk-${t}`;
 return {sdk_version:version,private_repository:'risense-ai/respire-core',release_tag:`sdk-v${version}`,url:base+'.manifest.json',archive_url:base+'.tar.gz',manifest_sha256:digest,archive_sha256:digest,redistribution:'approved'};
}
for (const version of ['1.0.2-dev.24','1.1.0-dev.1','2.0.0-dev.1']) {
 test(`${version} keeps distinct canonical cache keys for all targets`,()=>{
  const keys=TARGETS.map(t=>cacheKey(t,canonicalEntry(t,entry(version,t))));
  assert.equal(new Set(keys).size,TARGETS.length);
  assert.notEqual(cacheKey(target,entry(version)),cacheKey(target,entry('1.0.2-dev.11')));
  assert.notEqual(archiveCacheKey(target,entry(version)),cacheKey(target,entry(version)));
  assert.equal(new Set(TARGETS.map(t=>archiveCacheKey(t,entry(version,t)))).size,TARGETS.length);
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
function archiveFixture(manifest={target,sdk_version:'1.1.0-dev.1'},name='manifest.json') {
 const manifestBytes=Buffer.from(JSON.stringify(manifest)),header=Buffer.alloc(512);
 header.write(name);header.write(manifestBytes.length.toString(8).padStart(11,'0')+'\0',124);
 header.fill(32,148,156);header[156]=48;header.write('ustar\0',257);
 header.write(header.reduce((sum,byte)=>sum+byte,0).toString(8).padStart(6,'0')+'\0 ',148);
 const archive=gzipSync(Buffer.concat([header,manifestBytes,Buffer.alloc((512-manifestBytes.length%512)%512+1024)]));
 const pinned={...entry('1.1.0-dev.1'),archive_sha256:createHash('sha256').update(archive).digest('hex'),
  manifest_sha256:createHash('sha256').update(manifestBytes).digest('hex')};
 return {archive,pinned};
}
test('SDK evidence observes compressed bytes and embedded manifest identity',()=>{
 const {archive,pinned}=archiveFixture();
 assert.deepEqual(observeSdkArchive(archive,target,pinned),{version:'1.1.0-dev.1',
  manifest_sha256:pinned.manifest_sha256,archive_sha256:pinned.archive_sha256});
 assert.throws(()=>observeSdkArchive(Buffer.concat([archive,Buffer.from('changed')]),target,pinned),/archive hash/);
 assert.throws(()=>observeSdkArchive(archive,target,{...pinned,manifest_sha256:'0'.repeat(64)}),/manifest identity/);
});
test('SDK evidence cannot substitute lock values for different embedded SDK bytes',()=>{
 for(const manifest of [{target,sdk_version:'1.0.2-dev.23'},{target:'foreign-target',sdk_version:'1.1.0-dev.1'}]) {
  const {archive,pinned}=archiveFixture(manifest);
  assert.throws(()=>observeSdkArchive(archive,target,pinned),/manifest identity/);
 }
 const {archive,pinned}=archiveFixture(undefined,'other.json');
 assert.throws(()=>observeSdkArchive(archive,target,pinned),/no manifest/);
});
for(const version of ['1.1.0','1.1.0-dev.0','1.1.0-dev.01','1.1.0-rc.1','1.1.0-dev.1+metadata','1.1.1-dev.1','2.0.0','2.0.0-dev.0','2.0.0-dev.01','2.0.0-rc.1','2.0.0-dev.1+metadata','2.0.1-dev.1']) {
 test(`unsupported SDK ${version} cannot reach cache or network`,async()=>{
  assert.throws(()=>canonicalEntry(target,entry(version)),/tag\/version/);
  for(const download of [standalone,packaged]) {
   let calls=0;
   await assert.rejects(download(entry(version),target,'manifest',{env:{},transport:async()=>{calls++;}}),/version/);
   assert.equal(calls,0);
  }
 });
}
