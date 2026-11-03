// Offline only: no real registry, accounts, models, or npm publication.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {publishScopedPackages} from './parallel-publication.mjs';
import {publishPackage} from './registry-publication.mjs';

const umbrella = '@rsrsai/cli';
const batch = Array.from({length: 5}, (_, i) => ({name: i === 4 ? umbrella : `@rsrsai/platform-${i}`,
  version: '1.0.12-dev.7', dir: `fixture-${i}`}));
const deferred = () => { let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve}; };

test('four bounded workers overlap; umbrella waits for the last verified platform', async () => {
  const gates = batch.slice(0, 4).map(deferred), started = [], finished = [];
  const run = publishScopedPackages(batch, umbrella, 'dev', {publishImpl: async (_, receipt) => {
    started.push(receipt.name);
    if (receipt.name !== umbrella) await gates[batch.indexOf(receipt)].promise;
    else assert.equal(finished.length, 4);
    finished.push(receipt.name);
    return {status: 'published'};
  }});
  assert.deepEqual(started, batch.slice(0, 4).map(r => r.name));
  for (const gate of gates.slice(0, 3)) gate.resolve();
  await new Promise(setImmediate);
  assert(!started.includes(umbrella));
  gates[3].resolve();
  assert.equal((await run).length, 5);
  assert.equal(started.at(-1), umbrella);
  const direct = batch.slice(0,4), directWrites=[];
  assert.equal((await publishScopedPackages(direct,'rsrs-cli','dev',{publishImpl:async(_,p)=>{directWrites.push(p.name);return {status:'published'};}})).length,4);
  assert.deepEqual(directWrites,direct.map(p=>p.name));
  await assert.rejects(publishScopedPackages([...direct,{...batch[4],name:'rsrs-cli'}],'rsrs-cli','dev',{publishImpl:()=>assert.fail('launcher cannot use the parent publisher')}));
});

test('failure drains in-flight work and blocks umbrella; no queued publication starts', async () => {
  const gate = deferred(), started = [];
  const larger = [...batch.slice(0, 4), {name: '@rsrsai/extra', version: batch[0].version}, batch[4]];
  const run = publishScopedPackages(larger, umbrella, 'dev', {publishImpl: async (_, receipt) => {
    started.push(receipt.name);
    if (receipt.name === batch[0].name) throw new Error('hash mismatch');
    await gate.promise;
    return {status: 'existing'};
  }});
  let settled = false;
  const checked = assert.rejects(run, error => error instanceof AggregateError && error.errors[0].message === 'hash mismatch').then(() => {settled = true;});
  await new Promise(setImmediate);
  assert.equal(settled, false);
  gate.resolve(); await checked;
  assert.equal(started.length, 4);
  assert(!started.includes(umbrella));
});

test('duplicate, missing umbrella, empty platforms and mixed version fail before side effects', async () => {
  for (const receipts of [[...batch, batch[0]], batch.slice(0, 4), [batch[4]],
    batch.map((r, i) => i === 0 ? {...r, version: '1.0.12-dev.6'} : r),
    batch.map(r => r.name === umbrella ? {...r, version: '1.0.12-dev.6'} : r)]) {
    await assert.rejects(publishScopedPackages(receipts, umbrella, 'dev', {publishImpl: () => assert.fail('must not publish')}));
  }
});

test('real helper preserves immutable receipts, unique temp files, existing skip and uncertain single submission', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'rsrs-parallel-test-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const receipts = batch.map((r, i) => {
    const dir = path.join(root, String(i)), bytes = Buffer.from(`synthetic artifact source ${i}`);
    mkdirSync(dir); writeFileSync(path.join(dir, 'package.json'), JSON.stringify(r));
    return {...r, dir, bytes, filename: 'same-name.tgz',
      integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
      shasum: createHash('sha1').update(bytes).digest('hex')};
  });
  const tempPaths = [], submissions = new Map(), visible = new Set([receipts[0].name]);
  const verified = new Set(), barrier = deferred(); let active = 0, maxActive = 0;
  const publishImpl = async (dir, receipt, tag) => publishPackage(dir, receipt, tag, {
    timeoutMs: 1000, pollMs: 1,
    spawnImpl: (_, args) => {
      if (args[0] === 'pack') {
        const dest = args[args.indexOf('--pack-destination') + 1];
        const file = path.join(dest, receipt.filename); tempPaths.push(file);
        writeFileSync(file, receipt.bytes);
        return {status: 0, stdout: JSON.stringify([receipt])};
      }
      assert.deepEqual(readFileSync(args[1]), receipt.bytes);
      submissions.set(receipt.name, (submissions.get(receipt.name) || 0) + 1);
      visible.add(receipt.name);
      return {status: receipt === receipts[2] ? null : 0};
    },
    fetchImpl: async url => {
      if (url.includes('dist-tags')) return new Response('{}');
      if (!visible.has(receipt.name)) return new Response('', {status: 404});
      if (url.endsWith('.tgz')) {
        if (receipt.name !== umbrella) {
          active++; maxActive = Math.max(maxActive, active);
          if (active === 4) barrier.resolve();
          await barrier.promise; active--;
          verified.add(receipt.name);
        } else assert.equal(verified.size, 4);
        return new Response(receipt.bytes);
      }
      return new Response(JSON.stringify({name: receipt.name, version: receipt.version,
        dist: {integrity: receipt.integrity, shasum: receipt.shasum,
          tarball: `https://registry.npmjs.org/${receipt.name}/-/fixture.tgz`}}));
    },
  });
  const results = await publishScopedPackages(receipts, umbrella, 'dev', {publishImpl});
  assert.equal(maxActive, 4);
  assert.equal(results[0].status, 'existing');
  assert.equal(results[2].status, 'recovered');
  assert(!submissions.has(receipts[0].name));
  assert.deepEqual([...submissions.values()], [1, 1, 1, 1]);
  assert.equal(new Set(tempPaths).size, 5);
  assert(tempPaths.every(file => !existsSync(file)));
  // Rerun verifies every exact package and never submits again.
  await publishScopedPackages(receipts, umbrella, 'dev', {publishImpl});
  assert.deepEqual([...submissions.values()], [1, 1, 1, 1]);
});


test('configured propagation options reach every platform and umbrella publisher', async () => {
  const forwarded = {timeoutMs: 30 * 60 * 1000, pollMs: 10, requestTimeoutMs: 100};
  const calls = [];
  await publishScopedPackages(batch, umbrella, 'dev', {
    ...forwarded,
    publishImpl: async (dir, receipt, tag, options) => {
      assert.equal(dir, receipt.dir);
      assert.equal(tag, 'dev');
      assert.deepEqual(options, forwarded);
      calls.push(receipt.name);
      return {status: 'existing'};
    },
  });
  assert.deepEqual(calls, batch.map(r => r.name));
});

test('default npm children overlap, retain tarballs until close, and drain failure before cleanup', {timeout:60000}, async t => {
  for(const fail of [false,true]) {
    const root=mkdtempSync(path.join(tmpdir(),'rsrs-npm-children-'));
    const bin=path.join(root,'bin');mkdirSync(bin);
    const names=Array.from({length:7},(_,i)=>`@rsrsai/platform-${i}`).concat(umbrella);
    const id=name=>name.replace(/\W/g,'_');
    const version='1.0.12-dev.7';
    for(const name of names) {
      const dir=path.join(root,id(name));mkdirSync(dir);
      writeFileSync(path.join(dir,'package.json'),JSON.stringify({name,version}));
    }
    // The default helper resolves only these local fake npm executables in a separate Node process.
    writeFileSync(path.join(bin,'npm.cjs'),String.raw`
      const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
      const args=process.argv.slice(2),root=process.env.FIXTURE_ROOT,id=name=>name.replace(/\W/g,'_');
      if(args[0]==='pack') {
        const pkg=JSON.parse(fs.readFileSync('package.json','utf8')),bytes=Buffer.from(pkg.name),filename='package.tgz';
        fs.writeFileSync(path.join(args[args.indexOf('--pack-destination')+1],filename),bytes);
        console.log(JSON.stringify([{...pkg,filename,integrity:'sha512-'+crypto.createHash('sha512').update(bytes).digest('base64'),shasum:crypto.createHash('sha1').update(bytes).digest('hex')}]));
      } else {
        assert.equal(args[0],'publish');const tarball=args[1],name=fs.readFileSync(tarball,'utf8'),key=id(name);
        assert(fs.existsSync(path.join(root,'intent-'+key)),'submission intent must precede child startup');
        if(name==='@rsrsai/cli')for(let i=0;i<7;i++)assert(fs.existsSync(path.join(root,'finished-'+id('@rsrsai/platform-'+i))),'umbrella started before platform completion');
        fs.writeFileSync(path.join(root,'started-'+key),JSON.stringify({tarball,pid:process.pid}));
        const timer=setInterval(()=>{
          if(!fs.existsSync(path.join(root,'release-all'))&&!fs.existsSync(path.join(root,'release-'+key)))return;
          clearInterval(timer);assert.equal(fs.readFileSync(tarball,'utf8'),name,'tarball removed while child was running');
          fs.writeFileSync(path.join(root,'finished-'+key),'done');
          process.exit(process.env.FAIL_FIRST==='true'&&name==='@rsrsai/platform-0'?1:0);
        },10);
      }
    `);
    writeFileSync(path.join(bin,'npm.cmd'),'@"'+process.execPath+'" "%~dp0npm.cjs" %*\r\n');
    writeFileSync(path.join(bin,'npm'),'#!/bin/sh\nexec "'+process.execPath+'" "'+path.join(bin,'npm.cjs')+'" "$@"\n',{mode:0o755});
    const harness=String.raw`
      import assert from 'node:assert/strict';
      import fs from 'node:fs';import path from 'node:path';import {createHash} from 'node:crypto';
      const {acceptScopedPackages}=await import(process.env.PUBLICATION_MODULE);
      const names=JSON.parse(process.env.PACKAGE_NAMES),root=process.env.FIXTURE_ROOT,id=name=>name.replace(/\W/g,'_');
      const packs=names.map(name=>({name,version:'1.0.12-dev.7',dir:path.join(root,id(name)),filename:'package.tgz',integrity:'sha512-'+createHash('sha512').update(name).digest('base64'),shasum:createHash('sha1').update(name).digest('hex')}));
      let clock=0;
      try {
        const result=await acceptScopedPackages(packs,'@rsrsai/cli','dev',{
          timeoutMs:30,pollMs:10,now:()=>clock,sleep:async ms=>{clock+=ms;},
          fetchImpl:async url=>url.includes('/dist-tags')?new Response('{}'):new Response('',{status:404}),
          onSubmission:event=>{assert.equal(event.state,'unknown');fs.writeFileSync(path.join(root,'intent-'+id(event.package.name)),'unknown');},
        });
        assert.equal(process.env.FAIL_FIRST,'false');
        assert(result.every(p=>p.acceptance.evidence==='npm-exit-zero'));
      } catch(error) {
        if(process.env.FAIL_FIRST!=='true')throw error;
        assert(error instanceof AggregateError);assert.match(error.errors[0].message,/failed or was uncertain/);
      }
      fs.writeFileSync(path.join(root,'settled'),'done');
    `;
    let output='';
    const child=spawn(process.execPath,['--input-type=module','-e',harness],{env:{...process.env,
      PATH:bin+path.delimiter+process.env.PATH,FIXTURE_ROOT:root,FAIL_FIRST:String(fail),PACKAGE_NAMES:JSON.stringify(names),
      PUBLICATION_MODULE:new URL('./parallel-publication.mjs',import.meta.url).href},stdio:['ignore','pipe','pipe']});
    child.stdout.on('data',chunk=>{output+=chunk;});child.stderr.on('data',chunk=>{output+=chunk;});
    const closed=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',code=>resolve(code));});
    const wait=async predicate=>{
      const deadline=Date.now()+10000;
      while(!predicate()) {
        assert(Date.now()<deadline,'child barrier timed out: '+output);
        assert.equal(child.exitCode,null,'harness exited before barrier: '+output);
        await new Promise(resolve=>setTimeout(resolve,20));
      }
    };
    try {
      const started=()=>readdirSync(root).filter(name=>name.startsWith('started-'));
      await wait(()=>started().length===4);
      assert.equal(readdirSync(root).filter(name=>name.startsWith('finished-')).length,0,'four real npm children must overlap');
      if(fail) {
        writeFileSync(path.join(root,'release-'+id(names[0])),'go');
        await wait(()=>existsSync(path.join(root,'finished-'+id(names[0]))));
        await new Promise(resolve=>setTimeout(resolve,100));
        assert(!existsSync(path.join(root,'settled')),'failure must drain blocked siblings');
        assert.equal(started().length,4,'failure must not start queued packages or umbrella');
      }
      for(const file of started().filter(file=>!existsSync(path.join(root,file.replace('started-','finished-'))))) {
        assert(existsSync(JSON.parse(readFileSync(path.join(root,file),'utf8')).tarball));
      }
      writeFileSync(path.join(root,'release-all'),'go');
      assert.equal(await closed,0,output);
      assert(existsSync(path.join(root,'settled')));
      assert.equal(started().length,fail?4:8);
      for(const file of started())assert(!existsSync(JSON.parse(readFileSync(path.join(root,file),'utf8')).tarball),'cleanup follows child close');
    } finally {
      writeFileSync(path.join(root,'release-all'),'go');
      await closed;
      rmSync(root,{recursive:true,force:true});
    }
  }
});
