import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {initializeEvidence,openEvidence} from '../intelligence-core.mjs';
import {createRadar} from '../server.mjs';

const at=1700000000000,program='11111111111111111111111111111111';
function fixture(t,maxRecords=100){
  const dir=mkdtempSync(join(tmpdir(),'huntxr-evidence-'));
  const config={path:join(dir,'evidence.sqlite'),key:randomBytes(32),maxRecords};
  const genesis=initializeEvidence({...config,now:()=>at}),handles=[];
  t.after(()=>{for(const handle of handles)handle.close();rmSync(dir,{recursive:true,force:true});});
  return {config,genesis,open(extra={}){const h=openEvidence({...config,...extra});handles.push(h);return h;}};
}
const solana=(extra={})=>({signature:'5'.repeat(88),slot:100,time:at,policyMatches:[program],outcome:'succeeded',...extra});
const sensor=()=>({type:'suricata-alert',observedAt:at,sourceTime:at,signature:'test rule',
  classification:'test category',severity:2,action:'sensor-reported-block',
  src_ip:'192.0.2.1',payload:'private packet contents'});

test('Selected evidence persists and Solana policy matches deduplicate across restarts',t=>{
  const f=fixture(t),a=f.open();
  assert.equal(a.recordSolana(solana({policyMatches:[]})),false);
  assert.equal(a.recordSolana(solana()),true);
  assert.equal(a.recordSolana(solana()),false);
  assert.equal(a.recordSensor(sensor()),true);
  assert.equal(a.recordGap('connection',at),true);
  const checkpoint=a.verifyAudit(f.genesis);a.close();
  const b=f.open({expectedCheckpoint:checkpoint});
  assert.equal(b.recordSolana(solana()),false);
  assert.deepEqual(b.summary().counts,{'policy-match':1,'sensor-alert':1,'coverage-gap':1});
  assert.equal(b.summary().gaps,'unresolved; no backfill performed');
  const db=new DatabaseSync(f.config.path);
  try{
    const rows=db.prepare('SELECT payload FROM evidence ORDER BY seq').all();
    const contents=JSON.stringify(rows);
    assert.ok(!contents.includes('192.0.2.1'));
    assert.ok(!contents.includes('private packet contents'));
    assert.ok(contents.includes('policy-match-not-confirmed-threat'));
    assert.ok(contents.includes('sensor-reported-not-confirmed-threat'));
  }finally{db.close();}
});
test('Archive saturation fails visibly without deleting earlier records',t=>{
  const f=fixture(t,1),a=f.open();
  assert.equal(a.recordGap('connection',at),true);
  assert.throws(()=>a.recordGap('stale-feed',at));
  assert.throws(()=>a.summary());
  a.close();
  assert.equal(f.open().summary().records,1);
});
test('Wrong keys, tampering and checkpoint truncation are detected',t=>{
  const f=fixture(t),a=f.open();
  a.recordGap('connection',at);const cp=a.verifyAudit();a.close();
  assert.throws(()=>openEvidence({...f.config,key:randomBytes(32)}));
  const db=new DatabaseSync(f.config.path);
  try{db.exec('DELETE FROM evidence WHERE seq=2');}finally{db.close();}
  assert.throws(()=>f.open({expectedCheckpoint:cp}));
  const b=f.open();b.recordGap('stale-feed',at);
  const tamper=new DatabaseSync(f.config.path);
  try{tamper.exec("UPDATE evidence SET payload='{}' WHERE seq=2");}finally{tamper.close();}
  assert.throws(()=>b.verifyAudit());
  assert.throws(()=>b.recordGap('connection',at));
});
test('Radar records policy matches and gaps, without claiming complete coverage',t=>{
  const f=fixture(t);
  class Socket extends EventTarget{
    send(){} close(){}
    emit(type,value){this.dispatchEvent(new MessageEvent(type,{data:JSON.stringify(value)}));}
  }
  const socket=new Socket();
  const radar=createRadar({env:{HUNTER_RADAR_EVIDENCE_PATH:f.config.path,
    HUNTER_RADAR_EVIDENCE_KEY:f.config.key.toString('hex'),HUNTER_RADAR_DENY_ADDRESSES:program},
    now:()=>at,webSocketFactory:()=>socket,fetchImpl:async()=>new Response(null,{status:503})});
  try{
    radar.start();socket.emit('open',{});socket.emit('message',{id:1,result:4});
    socket.emit('message',{method:'logsNotification',params:{subscription:4,result:{
      context:{slot:100},value:{signature:'5'.repeat(88),err:null,logs:['Program '+program+' invoke [1]']}
    }}});
    socket.emit('message',null);
    assert.equal(radar.snapshot().intelligence.status,'recording');
    assert.deepEqual(radar.snapshot().intelligence.counts,{'policy-match':1,'sensor-alert':0,'coverage-gap':1});
  }finally{radar.stop();}
  assert.equal(f.open().summary().records,2);
});
