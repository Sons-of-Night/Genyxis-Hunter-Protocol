import assert from 'node:assert/strict';
import {generateKeyPairSync, sign, verify} from 'node:crypto';
import test from 'node:test';
import {getBase58Decoder} from '@solana/codecs-strings';
import {getCompiledTransactionMessageEncoder} from '@solana/transaction-messages';
import {getTransactionDecoder, getTransactionEncoder} from '@solana/transactions';
import {createProtectedWithdrawalSigner, inspectWithdrawal, withdrawalApprovalMessage} from '../withdrawal-guard.mjs';

const payer = generateKeyPairSync('ed25519');
const approver = generateKeyPairSync('ed25519');
const base58 = getBase58Decoder();
const address = bytes => base58.decode(bytes);
const signer = address(Buffer.from(payer.publicKey.export({format:'jwk'}).x,'base64url'));
const system = '11111111111111111111111111111111';
const destination = address(Buffer.alloc(32, 11));
const otherDestination = address(Buffer.alloc(32, 12));
const genesis = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
const currentTime = 1_800_000_000_000;

function transfer({to = destination, lamports = 40n, blockhashByte = 7, version = 'legacy',
  program = system, opcode = 2, extraInstruction = false, useLookup = false, signed = false} = {}) {
  const data = Buffer.alloc(12);
  data.writeUInt32LE(opcode);
  data.writeBigUInt64LE(lamports, 4);
  const instruction = {programAddressIndex:2,accountIndices:[0,1],data};
  const messageBytes = getCompiledTransactionMessageEncoder().encode({
    version, header:{numSignerAccounts:1,numReadonlySignerAccounts:0,numReadonlyNonSignerAccounts:1},
    staticAccounts:[signer,to,program], lifetimeToken:address(Buffer.alloc(32,blockhashByte)),
    instructions:extraInstruction ? [instruction,instruction] : [instruction],
    ...(version === 0 && {addressTableLookups:useLookup
      ? [{lookupTableAddress:otherDestination,writableIndexes:[0],readonlyIndexes:[]}]
      : []})
  });
  const signatures = {[signer]:signed ? sign(null,messageBytes,payer.privateKey) : null};
  return Buffer.from(getTransactionEncoder().encode({messageBytes,signatures})).toString('base64');
}

function approval(transaction, expiresAt = currentTime + 30_000, key = approver.privateKey) {
  return {expiresAt,signature:sign(null,withdrawalApprovalMessage(transaction,expiresAt),key).toString('base64')};
}

function setup(overrides = {}) {
  const calls = [];
  const options = {
    signerAddress:signer, approverPublicKey:approver.publicKey.export({format:'pem',type:'spki'}),
    allowedDestinations:[destination], maxLamports:50n, blockaidApiKey:'test-key', now:()=>currentTime,
    signMessage:async message=>{
      calls.push('sign');
      return sign(null,message,payer.privateKey);
    },
    fetchImpl:async (url, init)=>{
      const body = JSON.parse(init.body);
      calls.push(body.method);
      if (body.method === 'getGenesisHash') return Response.json({id:1,result:genesis});
      if (body.method === 'simulateTransaction') {
        assert.equal(body.params[1].replaceRecentBlockhash,false);
        assert.equal(body.params[1].sigVerify,false);
        return Response.json({id:2,result:{value:{err:null}}});
      }
      assert.equal(url,'https://api.blockaid.io/v0/solana/message/scan');
      assert.equal(init.headers['X-API-Key'],'test-key');
      assert.equal(init.redirect,'error');
      assert.equal(body.chain,'mainnet');
      assert.deepEqual(body.options,['validation']);
      return Response.json({status:'SUCCESS',result:{validation:{result_type:'Benign'}}});
    }
  };
  return {options,calls,guard:createProtectedWithdrawalSigner({...options,...overrides})};
}

test('Guard signs only the exact independently approved message after fresh checks',async()=>{
  const {guard,calls} = setup();
  for (const version of ['legacy',0]) {
    const transaction = transfer({version});
    const approved = inspectWithdrawal(transaction);
    assert.equal(approved.destination,destination);
    assert.equal(approved.lamports,40n);
    const signed = await guard({transaction,approval:approval(transaction)});
    const original = getTransactionDecoder().decode(Buffer.from(transaction,'base64'));
    const final = getTransactionDecoder().decode(Buffer.from(signed,'base64'));
    assert.deepEqual(final.messageBytes,original.messageBytes);
    assert.equal(verify(null,final.messageBytes,payer.publicKey,final.signatures[signer]),true);
  }
  const sequence = ['getGenesisHash','simulateTransaction','signTransaction','sign'];
  assert.deepEqual(calls,[...sequence,...sequence]);
});

test('A single-byte mutation anywhere in the approved wire transaction cannot reach the signer',async()=>{
  const {guard,calls} = setup();
  const transaction = transfer();
  const ticket = approval(transaction);
  const bytes = Buffer.from(transaction,'base64');
  for (let offset = 0; offset < bytes.length; offset++) {
    const changed = Buffer.from(bytes);
    changed[offset] ^= 1;
    await assert.rejects(guard({transaction:changed.toString('base64'),approval:ticket}),`offset ${offset}`);
  }
  assert.deepEqual(calls,[]);
});

test('Compromised withdrawal caller cannot forge approvals or change an approved transaction',async()=>{
  const {guard,calls} = setup();
  const transaction = transfer();
  const ticket = approval(transaction);
  await assert.rejects(guard({transaction}),/independent approval/);
  await assert.rejects(guard({transaction,approval:approval(transaction,undefined,payer.privateKey)}),/independent approval/);
  await assert.rejects(guard({transaction:transfer({lamports:41n}),approval:ticket}),/exact bytes/);
  await assert.rejects(guard({transaction:transfer({blockhashByte:8}),approval:ticket}),/exact bytes/);
  await assert.rejects(guard({transaction,approval:{...ticket,expiresAt:ticket.expiresAt+1}}),/exact bytes/);
  await assert.rejects(guard({transaction,approval:approval(transaction,currentTime)}),/unexpired/);
  await assert.rejects(guard({transaction,approval:approval(transaction,currentTime+60_001)}),/unexpired/);
  const outsider = transfer({to:otherDestination});
  await assert.rejects(guard({transaction:outsider,approval:approval(outsider)}),/approved list/);
  const oversized = transfer({lamports:51n});
  await assert.rejects(guard({transaction:oversized,approval:approval(oversized)}),/configured cap/);
  assert.deepEqual(calls,[]);
});

test('Guard rejects hidden instructions, alternate programs, nonce use and noncanonical wire bytes',async()=>{
  const {guard,calls} = setup();
  const extraByte = Buffer.concat([Buffer.from(transfer(),'base64'),Buffer.from([0])]).toString('base64');
  const attempts = [transfer({extraInstruction:true}),transfer({program:otherDestination}),
    transfer({opcode:4}),transfer({version:0,useLookup:true}),transfer({signed:true}),extraByte];
  for (const transaction of attempts) await assert.rejects(guard({transaction}),/transaction|transfer/);
  assert.deepEqual(calls,[]);
});

test('Unavailable and changing threat verdicts, failed simulation and the wrong network fail closed',async()=>{
  const {options,calls} = setup();
  const transaction = transfer();
  const request = {transaction,approval:approval(transaction)};
  let failure = '';
  const guard = createProtectedWithdrawalSigner({...options,fetchImpl:async(url,init)=>{
    const body = JSON.parse(init.body);
    if (failure === 'wrong-network' && body.method === 'getGenesisHash') return Response.json({id:1,result:'devnet'});
    if (failure === 'simulation' && body.method === 'simulateTransaction') {
      return Response.json({id:2,result:{value:{err:'BlockhashNotFound'}}});
    }
    if (body.method === 'signTransaction') {
      assert.equal(body.transactions[0],transaction);
      if (failure === 'rate-limit') return new Response(null,{status:429});
      if (failure === 'missing-verdict') return Response.json({status:'SUCCESS',result:{}});
      if (failure) return Response.json({status:'SUCCESS',result:{validation:{result_type:failure}}});
    }
    return options.fetchImpl(url,init);
  }});
  await guard(request);
  for (failure of ['Malicious','Warning','Error','missing-verdict','rate-limit','simulation','wrong-network']) {
    await assert.rejects(guard(request),/screening/i);
  }
  assert.equal(calls.filter(call=>call==='sign').length,1);
});

test('A slow approval check or a signing adapter substituting bytes cannot release a signature',async()=>{
  const {options,calls} = setup();
  const transaction = transfer();
  const request = {transaction,approval:approval(transaction)};
  let time = currentTime;
  const delayed = createProtectedWithdrawalSigner({...options,now:()=>time,fetchImpl:async(url,init)=>{
    const response = await options.fetchImpl(url,init);
    if (url.includes('blockaid.io')) time = request.approval.expiresAt;
    return response;
  }});
  await assert.rejects(delayed(request),/expired before signing/);
  assert.ok(!calls.includes('sign'));
  const substituting = createProtectedWithdrawalSigner({...options,signMessage:async bytes=>{
    bytes[10] ^= 1;
    return sign(null,bytes,payer.privateKey);
  }});
  await assert.rejects(substituting(request),/different key or message/);
});
