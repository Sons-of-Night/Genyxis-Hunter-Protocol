/**
 * Single-host HX-ACT decision ledger. Trusted service-side use only.
 * No response execution or remote administration.
 */
import {DatabaseSync} from 'node:sqlite';
import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {closeSync,openSync,lstatSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {capabilityBytes} from './hx-act.mjs';

const ZERO='0'.repeat(64);
const HEX=/^[a-f0-9]{64}$/;
const hash=x=>typeof x==='string'&&HEX.test(x);
const clock=x=>Number.isSafeInteger(x)&&x>=0;
const deny=()=>{throw new Error('HX-ACT state unavailable or invalid');};
const schema=`
CREATE TABLE ledger (
 seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, kind TEXT NOT NULL,
 ref TEXT NOT NULL, payload TEXT NOT NULL, previous TEXT NOT NULL, mac TEXT NOT NULL
) STRICT;
CREATE INDEX ledger_lookup ON ledger(kind,ref);
CREATE UNIQUE INDEX ledger_once ON ledger(ref) WHERE kind='authorize';
PRAGMA user_version=1;`;

function validateOptions(path,auditKey,now){
  if(typeof path!=='string'||!isAbsolute(path)||!Buffer.isBuffer(auditKey)||auditKey.length!==32
    ||typeof now!=='function') deny();
}
function database(path){
  if(!lstatSync(path).isFile()) deny(); // protected directory required; no symlink traversal
  const db=new DatabaseSync(path);
  try{
    db.exec('PRAGMA busy_timeout=1000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;');
    return db;
  }catch(e){db.close();throw e;}
}
function transaction(db,work,write=true){
  db.exec(write?'BEGIN IMMEDIATE':'BEGIN');
  try{const result=work();db.exec('COMMIT');return result;}
  catch(e){try{db.exec('ROLLBACK');}catch{}throw e;}
}
function ledger(db,auditKey,now){
  const secret=Buffer.from(auditKey);
  const mac=row=>createHmac('sha256',secret).update(JSON.stringify([
    'huntxr:hx-act:ledger:v1',row.seq,row.at,row.kind,row.ref,row.payload,row.previous
  ])).digest('hex');
  const tail=()=>db.prepare('SELECT * FROM ledger ORDER BY seq DESC LIMIT 1').get();
  const exists=(kind,ref)=>!!db.prepare('SELECT 1 FROM ledger WHERE kind=? AND ref=? LIMIT 1').get(kind,ref);
  function append(kind,ref,payload,at){
    const prev=tail();
    if(!clock(at)||(prev&&at<prev.at)||(!prev&&kind!=='init')) deny();
    const row={seq:(prev?.seq??0)+1,at,kind,ref,payload:JSON.stringify(payload),previous:prev?.mac??ZERO};
    if(!Number.isSafeInteger(row.seq)) deny();
    row.mac=mac(row);
    db.prepare('INSERT INTO ledger(seq,at,kind,ref,payload,previous,mac) VALUES(?,?,?,?,?,?,?)')
      .run(row.seq,row.at,row.kind,row.ref,row.payload,row.previous,row.mac);
    return Object.freeze({seq:row.seq,mac:row.mac});
  }
  function verifyChain(checkpoint){
    if(checkpoint!==undefined&&(!Number.isSafeInteger(checkpoint?.seq)||checkpoint.seq<1||!hash(checkpoint.mac))) deny();
    let seq=0,previous=ZERO,at=0,matched=checkpoint===undefined;
    for(const row of db.prepare('SELECT * FROM ledger ORDER BY seq').iterate()){
      if(row.seq!==seq+1||!clock(row.at)||row.at<at||row.previous!==previous||!hash(row.mac)
        ||!timingSafeEqual(Buffer.from(row.mac,'hex'),Buffer.from(mac(row),'hex'))
        ||(seq===0&&row.kind!=='init')) deny();
      seq=row.seq;previous=row.mac;at=row.at;
      if(checkpoint?.seq===seq) matched=checkpoint.mac===previous;
    }
    if(!seq||!matched) deny();
    return Object.freeze({seq,mac:previous});
  }
  return {append,verifyChain,tail,exists,now,clear:()=>secret.fill(0)};
}

// Explicit first-time provisioning. Never silently recreate missing state.
export function initializeState({path,auditKey,now=Date.now}={}){
  validateOptions(path,auditKey,now);
  const fd=openSync(path,'wx',0o600);
  closeSync(fd);
  const db=database(path);
  const log=ledger(db,auditKey,now);
  try{
    return transaction(db,()=>{
      db.exec(schema);
      return log.append('init',randomBytes(32).toString('hex'),{},now());
    });
  }finally{log.clear();db.close();}
}

export function openState({path,auditKey,now=Date.now,checkpoint}={}){
  validateOptions(path,auditKey,now);
  const db=database(path);
  const log=ledger(db,auditKey,now);
  let closed=false,integrityFailed=false;
  try{
    if(db.prepare('PRAGMA user_version').get().user_version!==1) deny();
    transaction(db,()=>log.verifyChain(checkpoint),false);
  }catch(e){log.clear();db.close();throw e;}
  const ensure=()=>{if(closed||integrityFailed) deny();};
  function time(){
    const at=now(),last=log.tail();
    if(!clock(at)||!last||at<last.at) deny();
    return at;
  }
  function admin(kind,ref){
    ensure();
    if(!hash(ref)) deny();
    return transaction(db,()=>log.append(kind,ref,{},time()));
  }
  return Object.freeze({
    // Caller must have verified signatures and trusted request context first.
    // Check policy state, consume nonce and append success in one write transaction.
    commitVerified(claims,checkedAt){
      try{
        ensure();
        capabilityBytes(claims);
        return transaction(db,()=>{
          const at=time();
          let reason=null;
          if(!clock(checkedAt)||at<checkedAt||at<claims.issuedAt||at>=claims.expiresAt) reason='time';
          else if(log.exists('halt',ZERO)) reason='halted';
          else if(log.exists('revoke-subject',claims.subjectKey)||log.exists('revoke-token',claims.nonce)) reason='revoked';
          else if(log.exists('authorize',claims.nonce)) reason='replay';
          const details={mode:claims.mode,audience:claims.audience,asset:claims.asset,
            action:claims.action,requestHash:claims.requestHash,subjectKey:claims.subjectKey,
            issuedAt:claims.issuedAt,expiresAt:claims.expiresAt};
          log.append(reason?'deny':'authorize',claims.nonce,{...details,reason},at);
          return reason===null;
        });
      }catch{return false;}
    },
    revokeSubject(fingerprint){return admin('revoke-subject',fingerprint);},
    revokeToken(nonce){return admin('revoke-token',nonce);},
    emergencyHalt(){return admin('halt',ZERO);},
    // Save checkpoints independently of the database to detect rollback/truncation.
    verifyAudit(trustedCheckpoint){
      ensure();
      try{return transaction(db,()=>log.verifyChain(trustedCheckpoint),false);}
      catch(e){integrityFailed=true;throw e;}
    },
    close(){if(!closed){closed=true;log.clear();db.close();}}
  });
}
