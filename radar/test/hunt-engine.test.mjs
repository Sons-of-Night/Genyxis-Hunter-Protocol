import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {parseKev,inspectFile,createHunt} from '../hunt-engine.mjs';
const fixture={catalogVersion:'fixture',dateReleased:'2026-01-01T00:00:00Z',count:1,vulnerabilities:[{cveID:'CVE-2026-1234'}]};
test('catalog rejects invalid count, duplicate IDs and malformed identifiers',()=>{
  assert.equal(parseKev(fixture).ids.size,1);
  assert.throws(()=>parseKev({...fixture,count:2}));
  assert.throws(()=>parseKev({...fixture,count:2,vulnerabilities:[...fixture.vulnerabilities,...fixture.vulnerabilities]}));
  assert.throws(()=>parseKev({...fixture,vulnerabilities:[{cveID:'bad'}]}));
});
test('approved file checks detect drift, refuse symlinks and omit paths',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'huntxr-'));
  try{
    const path=join(dir,'asset'), link=join(dir,'link');
    await writeFile(path,'baseline');await symlink(path,link);
    const asset={id:'approved',path,sha256:createHash('sha256').update('baseline').digest('hex')};
    assert.deepEqual(await inspectFile(asset),{id:'approved',status:'match'});
    assert.deepEqual(await inspectFile({...asset,path:link}),{id:'approved',status:'unverified'});
    await writeFile(path,'changed');assert.deepEqual(await inspectFile(asset),{id:'approved',status:'drift'});
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('disabled hunter does not fetch and malformed manifests fail closed',()=>{
  let calls=0;const h=createHunt({env:{},fetchImpl:()=>{calls++;}});
  h.start();assert.equal(calls,0);assert.equal(h.snapshot().feed.status,'disabled');h.stop();
  assert.throws(()=>createHunt({env:{HUNTER_RADAR_HUNT_FILES:'[{}]'}}));
});
test('known exploited catalog matches exact inventory, then expires; no network writes',async()=>{
  let clock=Date.parse('2026-01-02T00:00:00Z');
  const h=createHunt({env:{HUNTER_RADAR_HUNT_ENABLED:'1',HUNTER_RADAR_HUNT_CVES:'[{"id":"asset","cves":["CVE-2026-1234","CVE-2026-9999"]}]'},now:()=>clock,fetchImpl:async(url,options)=>{
    assert.equal(new URL(url).hostname,'www.cisa.gov');assert.equal(options.redirect,'error');assert.equal(options.method,undefined);
    return new Response(JSON.stringify(fixture));}});
  try{h.start();for(let i=0;i<100&&h.snapshot().feed.status==='pending';i++)await new Promise(r=>setTimeout(r,5));
    assert.equal(h.snapshot().feed.status,'fresh');assert.equal(h.snapshot().inventory.matchCount,1);
    clock+=24*3600_000;assert.equal(h.snapshot().feed.status,'stale');assert.equal(h.snapshot().inventory.matchCount,null);
  }finally{h.stop();}
});
test('unavailable feed cannot assert a zero-match result',async()=>{
  const h=createHunt({env:{HUNTER_RADAR_HUNT_ENABLED:'1'},fetchImpl:async()=>new Response('',{status:503})});
  try{h.start();for(let i=0;i<100&&h.snapshot().feed.status==='pending';i++)await new Promise(r=>setTimeout(r,5));
    assert.equal(h.snapshot().feed.status,'unavailable');assert.equal(h.snapshot().inventory.matchCount,null);
  }finally{h.stop();}
});
