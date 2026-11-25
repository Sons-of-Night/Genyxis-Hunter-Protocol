/**
 * HX-ACT v1: isolated authorization decision library.
 * No network access, response executor, private-key storage, or automatic escalation.
 */
import {createHash,createPublicKey,verify} from 'node:crypto';

const MODES=Object.freeze({
  'read-telemetry':'GREEN',
  'investigate-case':'AMBER',
  'approve-response-plan':'RED'
});
const TTL=Object.freeze({GREEN:300000,AMBER:120000,RED:30000});
const FIELDS=['version','mode','audience','asset','action','requestHash','subjectKey','nonce','issuedAt','expiresAt'];
const HEX=/^[a-f0-9]{64}$/;
const ID=/^[a-z0-9][a-z0-9._:-]{0,127}$/;
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
function fail(){throw new Error('HX-ACT authorization denied');}
function key(input){
  const publicKey=input?.type==='public'?input:createPublicKey(input);
  if(publicKey.asymmetricKeyType!=='ed25519') fail();
  return publicKey;
}
export function keyFingerprint(input){
  return sha256(key(input).export({format:'der',type:'spki'}));
}
function identifier(value){return typeof value==='string'&&ID.test(value);}
function hash(value){return typeof value==='string'&&HEX.test(value);}
function modeFor(action){return Object.hasOwn(MODES,action)?MODES[action]:null;}
function checkedClaims(c){
  if(!c||typeof c!=='object'||Array.isArray(c)||Object.keys(c).length!==FIELDS.length
    ||!FIELDS.every(f=>Object.hasOwn(c,f))) fail();
  if(c.version!==1||!identifier(c.audience)||!identifier(c.asset)||!identifier(c.action)
    ||c.mode!==modeFor(c.action)||!Object.hasOwn(TTL,c.mode)
    ||!hash(c.requestHash)||!hash(c.subjectKey)||!hash(c.nonce)
    ||!Number.isSafeInteger(c.issuedAt)||!Number.isSafeInteger(c.expiresAt)
    ||c.issuedAt<0||c.expiresAt<=c.issuedAt||c.expiresAt-c.issuedAt>TTL[c.mode]) fail();
  return Object.freeze(Object.fromEntries(FIELDS.map(f=>[f,c[f]])));
}
export function capabilityBytes(claims){
  const c=checkedClaims(claims);
  return Buffer.from(JSON.stringify(['huntxr:hx-act:capability:v1',...FIELDS.map(f=>c[f])]),'utf8');
}
export function holderProofBytes(claims,challenge){
  if(!hash(challenge)) fail();
  return Buffer.from('huntxr:hx-act:holder:v1:'+sha256(capabilityBytes(claims))+':'+challenge,'utf8');
}
export function approvalBytes(claims){
  return Buffer.from('huntxr:hx-act:approval:v1:'+sha256(capabilityBytes(claims)),'utf8');
}
function signature(value){
  if(typeof value!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(value)) fail();
  const bytes=Buffer.from(value,'base64url');
  if(bytes.length!==64||bytes.toString('base64url')!==value) fail();
  return bytes;
}
function validSignature(publicKey,bytes,sig){
  return verify(null,bytes,publicKey,signature(sig));
}
export function requestFingerprint(bytes){
  if(!Buffer.isBuffer(bytes)||bytes.length>65536) fail();
  return sha256(bytes);
}

// Deliberately process-local: tests and isolated fixtures only.
// Never evict an unexpired nonce to make space; saturation denies new requests.
export function createMemoryReplayStore({maxEntries=10000}={}){
  if(!Number.isSafeInteger(maxEntries)||maxEntries<1||maxEntries>100000) fail();
  const used=new Map();
  return Object.freeze({
    consume(nonce,expiresAt,now){
      if(!hash(nonce)||!Number.isSafeInteger(now)||!Number.isSafeInteger(expiresAt)||expiresAt<=now) return false;
      for(const [id,expiry] of used) if(expiry<=now) used.delete(id);
      if(used.has(nonce)||used.size>=maxEntries) return false;
      used.set(nonce,expiresAt);
      return true;
    }
  });
}

export function createVerifier({issuerKey,approverKey,audience,allowedScopes,replayStore,isRevoked,decisionStore,now=Date.now}={}){
  const issuer=key(issuerKey),approver=key(approverKey);
  const issuerId=keyFingerprint(issuer),approverId=keyFingerprint(approver);
  const persistent=decisionStore!==undefined;
  if(persistent ? (typeof decisionStore?.commitVerified!=='function'||replayStore!==undefined||isRevoked!==undefined)
    : (typeof replayStore?.consume!=='function'||typeof isRevoked!=='function')) fail();
  if(issuerId===approverId||!identifier(audience)||!Array.isArray(allowedScopes)
    ||allowedScopes.length<1||allowedScopes.length>10000||typeof now!=='function') fail();
  const scopes=new Set();
  for(const scope of allowedScopes){
    if(!identifier(scope?.asset)||!identifier(scope?.action)||!modeFor(scope.action)) fail();
    scopes.add(JSON.stringify([scope.asset,scope.action]));
  }
  return Object.freeze({
    authorize(input){
      try{
        const {claims,issuerSignature,holderKey,holderSignature,approvalSignature,expected}=input??{};
        const c=checkedClaims(claims),time=now();
        if(!Number.isSafeInteger(time)||time<c.issuedAt||time>=c.expiresAt
          ||c.audience!==audience||c.audience!==expected?.audience
          ||c.asset!==expected?.asset||c.action!==expected?.action||c.requestHash!==expected?.requestHash
          ||!hash(expected?.challenge)
          ||!scopes.has(JSON.stringify([c.asset,c.action]))) fail();
        const holder=key(holderKey),holderId=keyFingerprint(holder);
        if(holderId!==c.subjectKey||holderId===issuerId||holderId===approverId) fail();
        if(!validSignature(issuer,capabilityBytes(c),issuerSignature)
          ||!validSignature(holder,holderProofBytes(c,expected.challenge),holderSignature)) fail();
        if(c.mode==='RED'&&!validSignature(approver,approvalBytes(c),approvalSignature)) fail();
        if(persistent){
          // Revocation, halt, expiration, nonce and decision record share one transaction.
          if(decisionStore.commitVerified(c,time)!==true) fail();
        }else{
          // Legacy process-local fixtures only; never use this split path for enforcement.
          if(isRevoked(c)!==false||replayStore.consume(c.nonce,c.expiresAt,time)!==true) fail();
        }
        return Object.freeze({authorized:true,mode:c.mode,audience:c.audience,asset:c.asset,
          action:c.action,requestHash:c.requestHash,nonce:c.nonce,expiresAt:c.expiresAt});
      }catch{
        return Object.freeze({authorized:false,mode:'GREEN',reason:'authorization-denied'});
      }
    }
  });
}
