import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {Worker} from 'node:worker_threads';
import {initializeState,openState} from '../hx-act-state.mjs';
import {createVerifier,keyFingerprint,capabilityBytes,holderProofBytes,approvalBytes} from '../hx-act.mjs';

const issuer=generateKeyPairSync('ed25519'),approver=generateKeyPairSync('ed25519'),holder=generateKeyPairSync('ed25519');
const start=1700000000000;
const random=()=>randomBytes(32).toString('hex');
function claims(overrides={}){
  return {version:1,mode:'RED',audience:'test-service',asset:'test-asset',action:'approve-response-plan',
    requestHash:random(),subjectKey:keyFingerprint(holder.publicKey),nonce:random(),
    issuedAt:start,expiresAt:start+30000,...overrides};
}
function fixture(t){
  const dir=mkdtempSync(join(tmpdir(),'hx-act-'));
  let time=start;
  const options={path:join(dir,'state.sqlite'),auditKey:randomBytes(32),now:()=>time};
  const genesis=initializeState(options);
  const handles=[];
  const open=extra=>{const state=openState({...options,...extra});handles.push(state);return state;};
  // Close all database handles before removing files (including on Windows).
  t.after(()=>{for(const h of handles)h.close();rmSync(dir,{recursive:true,force:true});});
  return {options,genesis,open,setTime:x=>{time=x;}};
}
function verifier(state){
  return createVerifier({issuerKey:issuer.publicKey,approverKey:approver.publicKey,audience:'test-service',
    allowedScopes:[{asset:'test-asset',action:'approve-response-plan'}],decisionStore:state,now:()=>start});
}
function presentation(c){
  const challenge=random();
  return {claims:c,issuerSignature:sign(null,capabilityBytes(c),issuer.privateKey).toString('base64url'),
    holderKey:holder.publicKey,holderSignature:sign(null,holderProofBytes(c,challenge),holder.privateKey).toString('base64url'),
    approvalSignature:sign(null,approvalBytes(c),approver.privateKey).toString('base64url'),
    expected:{audience:c.audience,asset:c.asset,action:c.action,requestHash:c.requestHash,challenge}};
}

test('Full signed authorization persists nonce through closing and reopening state',t=>{
  const f=fixture(t),a=f.open(),r=presentation(claims());
  assert.equal(verifier(a).authorize({...r,approvalSignature:undefined}).authorized,false);
  assert.deepEqual(a.verifyAudit(),f.genesis);
  assert.equal(verifier(a).authorize(r).authorized,true);
  const checkpoint=a.verifyAudit(f.genesis);
  a.close();
  const b=f.open({checkpoint});
  assert.equal(verifier(b).authorize(r).authorized,false);
  assert.equal(b.verifyAudit(checkpoint).seq,checkpoint.seq+1);
});
test('Revocations and halt are enforced across handles and persist through restart',t=>{
  const f=fixture(t),a=f.open(),b=f.open(),r=claims();
  a.revokeToken(r.nonce);
  assert.equal(b.commitVerified(r,start),false);
  a.revokeSubject(r.subjectKey);
  assert.equal(b.commitVerified(claims(),start),false);
  assert.equal(b.commitVerified(claims({subjectKey:random()}),start),true);
  a.emergencyHalt();
  a.close();b.close();
  const c=f.open();
  assert.equal(c.commitVerified(claims({subjectKey:random()}),start),false);
});
test('Expiry, clock rollback and closed state deny new decisions',t=>{
  const f=fixture(t),a=f.open();
  const r=claims();f.setTime(start+30000);
  assert.equal(a.commitVerified(r,start),false);
  f.setTime(start);
  assert.equal(a.commitVerified(claims(),start),false);
  a.close();
  assert.equal(a.commitVerified(claims(),start),false);
});
test('Two simultaneous worker connections cannot consume the same nonce',async t=>{
  const f=fixture(t),r=claims();
  const url=new URL('../hx-act-state.mjs',import.meta.url).href;
  const source=`
    const {parentPort,workerData}=require('node:worker_threads');
    (async()=>{
      const {openState}=await import(workerData.url);
      const store=openState({path:workerData.path,auditKey:Buffer.from(workerData.key,'hex'),now:()=>workerData.start});
      parentPort.postMessage('ready');
      parentPort.once('message',()=>{
        try{parentPort.postMessage(store.commitVerified(workerData.claims,workerData.start));}
        finally{store.close();}
      });
    })().catch(e=>{throw e;});
  `;
  const create=()=>{
    const w=new Worker(source,{eval:true,workerData:{url,path:f.options.path,key:f.options.auditKey.toString('hex'),start,claims:r}});
    t.after(()=>w.terminate());
    const ready=new Promise((resolve,reject)=>{w.once('message',resolve);w.once('error',reject);});
    const exited=new Promise((resolve,reject)=>{w.once('exit',code=>code===0?resolve():reject(Error('Worker exit '+code)));});
    return {w,ready,exited};
  };
  const workers=[create(),create()];
  assert.deepEqual(await Promise.all(workers.map(x=>x.ready)),['ready','ready']);
  const results=await Promise.all(workers.map(({w})=>new Promise((resolve,reject)=>{
    w.once('message',resolve);w.once('error',reject);w.postMessage('go');
  })));
  assert.deepEqual(results.sort(),[false,true]);
  await Promise.all(workers.map(x=>x.exited));
  const a=f.open();assert.equal(a.verifyAudit().seq,3);
});
test('Ledger edits and incorrect authentication key are detected',t=>{
  const f=fixture(t),a=f.open();
  assert.equal(a.commitVerified(claims(),start),true);
  assert.throws(()=>openState({...f.options,auditKey:randomBytes(32)}));
  a.close();
  const db=new DatabaseSync(f.options.path);
  try{db.exec("UPDATE ledger SET payload='{}' WHERE seq=2");}finally{db.close();}
  assert.throws(()=>f.open());
});
test('Independent checkpoint detects a truncated but otherwise valid ledger',t=>{
  const f=fixture(t),a=f.open();
  assert.equal(a.commitVerified(claims(),start),true);
  const checkpoint=a.verifyAudit();a.close();
  const db=new DatabaseSync(f.options.path);
  try{db.exec('DELETE FROM ledger WHERE seq=2');}finally{db.close();}
  assert.throws(()=>f.open({checkpoint}));
});
test('Missing state is never silently recreated and existing state cannot be reinitialized',t=>{
  const f=fixture(t);
  assert.throws(()=>initializeState(f.options));
  rmSync(f.options.path);
  assert.throws(()=>f.open());
});

test('Detected audit integrity failure latches the live handle closed to decisions',t=>{
  const f=fixture(t),a=f.open();
  assert.equal(a.commitVerified(claims(),start),true);
  const db=new DatabaseSync(f.options.path);
  try{db.exec("UPDATE ledger SET payload='{}' WHERE seq=2");}finally{db.close();}
  assert.throws(()=>a.verifyAudit());
  assert.equal(a.commitVerified(claims(),start),false);
  assert.throws(()=>a.emergencyHalt());
});
