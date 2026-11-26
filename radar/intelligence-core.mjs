/**
 * Huntxr evidence archive: selected, sanitized observations and explicit gaps.
 * Single-host development backend. No enforcement or threat attribution.
 */
import {DatabaseSync} from 'node:sqlite';
import {createHash,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {openSync,closeSync,lstatSync} from 'node:fs';
import {isAbsolute} from 'node:path';

const ZERO='0'.repeat(64),HEX=/^[a-f0-9]{64}$/;
const ADDRESS=/^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const SIGNATURE=/^[1-9A-HJ-NP-Za-km-z]{64,100}$/;
const GAP_REASONS=new Set(['connection','subscription','stale-feed','invalid-message','oversized-message','sensor-rotation-or-skip']);
const schema=`
CREATE TABLE evidence(
 seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
 observed_at INTEGER NOT NULL, payload TEXT NOT NULL, previous TEXT NOT NULL, mac TEXT NOT NULL
) STRICT;
PRAGMA user_version=1;`;
const digest=x=>createHash('sha256').update(x).digest('hex');
const validTime=x=>Number.isSafeInteger(x)&&x>=0;
const fail=()=>{throw Error('Evidence archive unavailable or invalid');};
function config(path,key,maxRecords){
  if(typeof path!=='string'||!isAbsolute(path)||!Buffer.isBuffer(key)||key.length!==32
    ||!Number.isSafeInteger(maxRecords)||maxRecords<1||maxRecords>10000000) fail();
}
function database(path){
  if(!lstatSync(path).isFile()) fail();
  const db=new DatabaseSync(path);
  try{db.exec('PRAGMA busy_timeout=1000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;');return db;}
  catch(e){db.close();throw e;}
}
function transaction(db,fn,write=true){
  db.exec(write?'BEGIN IMMEDIATE':'BEGIN');
  try{const result=fn();db.exec('COMMIT');return result;}
  catch(e){try{db.exec('ROLLBACK');}catch{}throw e;}
}
function codec(key){
  const secret=Buffer.from(key);
  return {mac:row=>createHmac('sha256',secret).update(JSON.stringify([
    'huntxr:evidence:v1',row.seq,row.id,row.kind,row.observed_at,row.payload,row.previous
  ])).digest('hex'),clear:()=>secret.fill(0)};
}
function checkpoint(db,mac,expected){
  if(expected!==undefined&&(!Number.isSafeInteger(expected?.seq)||expected.seq<1||!HEX.test(expected.mac))) fail();
  let seq=0,previous=ZERO,matched=expected===undefined;
  for(const row of db.prepare('SELECT * FROM evidence ORDER BY seq').iterate()){
    if(row.seq!==seq+1||row.previous!==previous||!HEX.test(row.mac)||!validTime(row.observed_at)
      ||!timingSafeEqual(Buffer.from(row.mac,'hex'),Buffer.from(mac(row),'hex'))
      ||(seq===0&&row.kind!=='init')) fail();
    seq=row.seq;previous=row.mac;
    if(expected?.seq===seq) matched=expected.mac===previous;
  }
  if(!seq||!matched) fail();
  return Object.freeze({seq,mac:previous});
}
function append(db,mac,kind,id,observedAt,payload,maxRecords){
  if(!validTime(observedAt)||!HEX.test(id)) fail();
  if(db.prepare('SELECT 1 FROM evidence WHERE id=?').get(id)) return false;
  const prev=db.prepare('SELECT seq,mac FROM evidence ORDER BY seq DESC LIMIT 1').get();
  if((prev?.seq??0)>=maxRecords+1) fail();
  const row={seq:(prev?.seq??0)+1,id,kind,observed_at:observedAt,payload:JSON.stringify(payload),previous:prev?.mac??ZERO};
  row.mac=mac(row);
  db.prepare('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)').run(row.seq,row.id,row.kind,row.observed_at,row.payload,row.previous,row.mac);
  return true;
}
export function initializeEvidence({path,key,maxRecords=100000,now=Date.now}={}){
  config(path,key,maxRecords);
  closeSync(openSync(path,'wx',0o600));
  const db=database(path),c=codec(key);
  try{return transaction(db,()=>{
    db.exec(schema);
    append(db,c.mac,'init',randomBytes(32).toString('hex'),now(),{},maxRecords);
    return checkpoint(db,c.mac);
  });}finally{c.clear();db.close();}
}
function solana(observation){
  const {signature,slot,time,policyMatches,outcome}=observation??{};
  if(typeof signature!=='string'||!SIGNATURE.test(signature)||!validTime(time)
    ||!Number.isSafeInteger(slot)||slot<0||!['failed','succeeded'].includes(outcome)
    ||!Array.isArray(policyMatches)||policyMatches.length>64
    ||policyMatches.some(x=>typeof x!=='string'||!ADDRESS.test(x))) fail();
  if(!policyMatches.length) return null;
  const matches=[...new Set(policyMatches)].sort();
  return {kind:'policy-match',id:digest(JSON.stringify(['solana-policy',signature,matches])),
    at:time,payload:{source:'solana-confirmed',signature,slot,outcome,matchedPrograms:matches,
      classification:'policy-match-not-confirmed-threat'}};
}
function sensor(event){
  if(!event||event.type!=='suricata-alert'||!validTime(event.observedAt)
    ||(event.sourceTime!==null&&!validTime(event.sourceTime))
    ||typeof event.signature!=='string'||!event.signature||event.signature.length>160
    ||typeof event.classification!=='string'||event.classification.length>100
    ||![null,1,2,3,4].includes(event.severity)
    ||!['sensor-alert','sensor-reported-block'].includes(event.action)) fail();
  return {kind:'sensor-alert',id:randomBytes(32).toString('hex'),at:event.observedAt,
    payload:{source:'local-suricata',sourceTime:event.sourceTime,signature:event.signature,
      category:event.classification,severity:event.severity,reportedAction:event.action,
      classification:'sensor-reported-not-confirmed-threat'}};
}
export function openEvidence({path,key,maxRecords=100000,expectedCheckpoint}={}){
  config(path,key,maxRecords);
  const db=database(path),c=codec(key);
  let closed=false,failed=false;
  try{
    if(db.prepare('PRAGMA user_version').get().user_version!==1) fail();
    transaction(db,()=>checkpoint(db,c.mac,expectedCheckpoint),false);
  }catch(e){c.clear();db.close();throw e;}
  function ensure(){if(closed||failed) fail();}
  function record(build){
    ensure();
    try{
      const row=build();
      if(!row) return false;
      return transaction(db,()=>append(db,c.mac,row.kind,row.id,row.at,row.payload,maxRecords));
    }catch(e){failed=true;throw e;}
  }
  return Object.freeze({
    recordSolana:event=>record(()=>solana(event)),
    recordSensor:event=>record(()=>sensor(event)),
    recordGap(reason,at){
      return record(()=>{
        if(!GAP_REASONS.has(reason)||!validTime(at)) fail();
        return {kind:'coverage-gap',id:randomBytes(32).toString('hex'),at,
          payload:{reason,classification:'unresolved-coverage-gap'}};
      });
    },
    summary(){
      ensure();
      const counts={'policy-match':0,'sensor-alert':0,'coverage-gap':0};
      for(const row of db.prepare("SELECT kind,COUNT(*) AS count FROM evidence WHERE kind!='init' GROUP BY kind").all()){
        if(!Object.hasOwn(counts,row.kind)) fail();counts[row.kind]=row.count;
      }
      return Object.freeze({counts,records:Object.values(counts).reduce((a,b)=>a+b,0),maxRecords,
        classification:'unverified observations; no confirmed attack attribution',gaps:'unresolved; no backfill performed'});
    },
    verifyAudit(expected){
      ensure();
      try{return transaction(db,()=>checkpoint(db,c.mac,expected),false);}
      catch(e){failed=true;throw e;}
    },
    close(){if(!closed){closed=true;c.clear();db.close();}}
  });
}
