import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {createVerifier,createMemoryReplayStore,keyFingerprint,requestFingerprint,
  capabilityBytes,holderProofBytes,approvalBytes} from '../hx-act.mjs';

const pair=()=>generateKeyPairSync('ed25519');
const issuer=pair(),approver=pair(),holder=pair(),stranger=pair();
const start=1700000000000;
const requestHash=requestFingerprint(Buffer.from('isolated test incident record'));
const modes={'read-telemetry':'GREEN','investigate-case':'AMBER','approve-response-plan':'RED'};
const signature=(key,bytes)=>sign(null,bytes,key).toString('base64url');
function fixture(options={}){
  let time=start,revoked=false;
  const verifier=createVerifier({issuerKey:issuer.publicKey,approverKey:approver.publicKey,
    audience:'huntxr-test',allowedScopes:Object.keys(modes).map(action=>({asset:'owned-test-asset',action})),
    replayStore:createMemoryReplayStore(),isRevoked:()=>revoked,now:()=>time,...options});
  return {verifier,setTime:value=>{time=value;},revoke:()=>{revoked=true;}};
}
function request(action='investigate-case',overrides={},presenter=holder){
  const claims={version:1,mode:modes[action],audience:'huntxr-test',asset:'owned-test-asset',
    action,requestHash,subjectKey:keyFingerprint(presenter.publicKey),
    nonce:randomBytes(32).toString('hex'),issuedAt:start,expiresAt:start+20000,...overrides};
  const challenge=randomBytes(32).toString('hex');
  return {claims,issuerSignature:signature(issuer.privateKey,capabilityBytes(claims)),
    holderKey:presenter.publicKey,holderSignature:signature(presenter.privateKey,holderProofBytes(claims,challenge)),
    approvalSignature:signature(approver.privateKey,approvalBytes(claims)),
    expected:{audience:claims.audience,asset:claims.asset,action:claims.action,requestHash:claims.requestHash,challenge}};
}
const denied=(v,r)=>assert.deepEqual(v.authorize(r),{authorized:false,mode:'GREEN',reason:'authorization-denied'});

test('Each action maps to its permitted mode and consumes exactly one nonce',()=>{
  const {verifier}=fixture();
  for(const [action,mode] of Object.entries(modes)){
    const r=request(action);
    const result=verifier.authorize(r);
    assert.equal(result.authorized,true);
    assert.equal(result.mode,mode);
    assert.equal(result.requestHash,requestHash);
    assert.equal(result.nonce,r.claims.nonce);
    denied(verifier,r);
  }
});
test('A copied capability without its holder key and valid signature cannot authorize',()=>{
  const {verifier}=fixture(),r=request();
  denied(verifier,{...r,holderKey:stranger.publicKey});
  denied(verifier,{...r,holderSignature:signature(stranger.privateKey,holderProofBytes(r.claims,r.expected.challenge))});
  denied(verifier,{...r,holderSignature:undefined});
  denied(verifier,{...r,expected:{...r.expected,challenge:randomBytes(32).toString('hex')}});
  denied(verifier,{...r,expected:{...r.expected,challenge:undefined}});
  assert.equal(verifier.authorize(r).authorized,true);
});
test('RED requires separate approval for exactly the signed capability',()=>{
  const {verifier}=fixture(),r=request('approve-response-plan'),other=request('approve-response-plan');
  denied(verifier,{...r,approvalSignature:undefined});
  denied(verifier,{...r,approvalSignature:other.approvalSignature});
  denied(verifier,{...r,approvalSignature:signature(holder.privateKey,approvalBytes(r.claims))});
  denied(verifier,{...r,approvalSignature:signature(issuer.privateKey,approvalBytes(r.claims))});
  assert.equal(verifier.authorize(r).authorized,true);
});
test('Tampering and caller scope substitution cannot escalate authority',()=>{
  const {verifier}=fixture(),r=request();
  denied(verifier,{...r,claims:{...r.claims,mode:'RED'}});
  denied(verifier,{...r,claims:{...r.claims,nonce:'f'.repeat(64)}});
  denied(verifier,{...r,claims:{...r.claims,extra:true}});
  for(const [field,value] of Object.entries({audience:'other',asset:'other',action:'read-telemetry',requestHash:'f'.repeat(64)})){
    denied(verifier,{...r,expected:{...r.expected,[field]:value}});
  }
  denied(verifier,request('investigate-case',{asset:'unmanaged-asset'}));
  denied(verifier,request('investigate-case',{audience:'other-service'}));
  denied(verifier,{...r,issuerSignature:signature(stranger.privateKey,capabilityBytes(r.claims))});
});
test('Expiration, future issuance and TTL violations are fail-closed',()=>{
  const f=fixture(),r=request();
  f.setTime(start-1);denied(f.verifier,r);
  f.setTime(r.claims.expiresAt);denied(f.verifier,r);
  assert.throws(()=>request('approve-response-plan',{expiresAt:start+30001}),/denied/);
  assert.throws(()=>request('investigate-case',{expiresAt:start+120001}),/denied/);
  assert.throws(()=>request('read-telemetry',{expiresAt:start+300001}),/denied/);
});
test('Revocation, unknown status and provider failure deny authorization',()=>{
  const f=fixture();f.revoke();denied(f.verifier,request());
  denied(fixture({isRevoked:()=>undefined}).verifier,request());
  denied(fixture({isRevoked:()=>{throw Error('offline');}}).verifier,request());
});
test('Replay state is shared between verifiers and saturation denies without eviction',()=>{
  const replayStore=createMemoryReplayStore({maxEntries:1});
  const a=fixture({replayStore}),b=fixture({replayStore}),r=request();
  assert.equal(a.verifier.authorize(r).authorized,true);
  denied(b.verifier,r);denied(a.verifier,request());
  a.setTime(start+20000);
  assert.equal(a.verifier.authorize(request('investigate-case',{issuedAt:start+20000,expiresAt:start+40000})).authorized,true);
  denied(fixture({replayStore:{consume:()=>{throw Error('offline');}}}).verifier,request());
});
test('Issuer, independent approver and holder must use distinct Ed25519 keys',()=>{
  assert.throws(()=>fixture({approverKey:issuer.publicKey}),/denied/);
  const {verifier}=fixture();
  denied(verifier,request('investigate-case',{},issuer));
  denied(verifier,request('approve-response-plan',{},approver));
  assert.throws(()=>fixture({issuerKey:generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey}),/denied/);
});
test('Malformed signatures and unsupported actions cannot authorize',()=>{
  const {verifier}=fixture(),r=request();
  denied(verifier,{...r,issuerSignature:'a'.repeat(86)});
  denied(verifier,{...r,issuerSignature:r.issuerSignature+'='});
  denied(verifier,{...r,claims:{...r.claims,action:'unlisted-action'}});
  assert.throws(()=>requestFingerprint(Buffer.alloc(65537)),/denied/);
});
