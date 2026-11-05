import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {generateKeyPairSync, sign, verify} from 'node:crypto';
import {mkdtemp, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import {GetPublicKeyCommand, SignCommand} from '@aws-sdk/client-kms';
import {getBase58Decoder} from '@solana/codecs-strings';
import {getCompiledTransactionMessageEncoder} from '@solana/transaction-messages';
import {getTransactionDecoder, getTransactionEncoder} from '@solana/transactions';
import {createKmsWithdrawalSigner} from '../kms-withdrawal-signer.mjs';

const run = promisify(execFile);
const approvalTool = fileURLToPath(new URL('../withdrawal-approval.mjs', import.meta.url));
const signingTool = fileURLToPath(new URL('../kms-withdrawal-signer.mjs', import.meta.url));
const wallet = generateKeyPairSync('ed25519');
const approver = generateKeyPairSync('ed25519');
const base58 = getBase58Decoder();
const addressOf = key => base58.decode(Buffer.from(key.export({format:'jwk'}).x, 'base64url'));
const signer = addressOf(wallet.publicKey);
const destination = base58.decode(Buffer.alloc(32, 9));
const authorization = {withdrawalId:'pilot-0001', signer, destination, lamports:'40'};
const keyArn = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

function proposal(blockhash = 12) {
  const instruction = Buffer.alloc(12);
  instruction.writeUInt32LE(2);
  instruction.writeBigUInt64LE(40n, 4);
  const messageBytes = getCompiledTransactionMessageEncoder().encode({
    version:'legacy', header:{numSignerAccounts:1, numReadonlySignerAccounts:0, numReadonlyNonSignerAccounts:1},
    staticAccounts:[signer, destination, '11111111111111111111111111111111'],
    lifetimeToken:base58.decode(Buffer.alloc(32, blockhash)),
    instructions:[{programAddressIndex:2, accountIndices:[0,1], data:instruction}]
  });
  return Buffer.from(getTransactionEncoder().encode({messageBytes, signatures:{[signer]:null}})).toString('base64');
}

async function setupApprover(t, record = authorization) {
  const dir = await mkdtemp(join(tmpdir(), 'huntxr-withdrawal-'));
  t.after(() => rm(dir, {recursive:true, force:true}));
  const proposalFile = join(dir, 'unsigned.txt');
  const recordFile = join(dir, 'trusted-record.json');
  const keyFile = join(dir, 'approver-private.pem');
  const transaction = proposal();
  await Promise.all([
    writeFile(proposalFile, transaction + '\r\n'),
    writeFile(recordFile, '\uFEFF' + JSON.stringify(record)),
    writeFile(keyFile, approver.privateKey.export({format:'pem', type:'pkcs8'}), {mode:0o600})
  ]);
  return {dir, proposalFile, transaction, approve:() => run(process.execPath, [approvalTool, proposalFile, recordFile, keyFile, dir])};
}

function setupSigner(publicKey = wallet.publicKey, verdict = 'Benign') {
  const calls = [];
  const options = {
    keyArn, signerAddress:signer, allowedDestinations:[destination], maxLamports:50n,
    approverPublicKey:approver.publicKey.export({format:'pem', type:'spki'}), blockaidApiKey:'test-key',
    kms:{async send(command, {abortSignal}) {
      assert.equal(command.input.KeyId, keyArn);
      assert.ok(abortSignal instanceof AbortSignal);
      if (command instanceof GetPublicKeyCommand) {
        calls.push('GetPublicKey');
        return {KeyId:keyArn, KeySpec:'ECC_NIST_EDWARDS25519', KeyUsage:'SIGN_VERIFY',
          SigningAlgorithms:['ED25519_SHA_512'], PublicKey:publicKey.export({format:'der', type:'spki'})};
      }
      assert.ok(command instanceof SignCommand);
      assert.equal(command.input.MessageType, 'RAW');
      assert.equal(command.input.SigningAlgorithm, 'ED25519_SHA_512');
      calls.push('Sign');
      return {KeyId:keyArn, SigningAlgorithm:'ED25519_SHA_512', Signature:sign(null, command.input.Message, wallet.privateKey)};
    }},
    fetchImpl:async (_url, init) => {
      const {method} = JSON.parse(init.body);
      calls.push(method);
      if (method === 'getGenesisHash') return Response.json({id:1, result:'5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'});
      if (method === 'simulateTransaction') return Response.json({id:2, result:{value:{err:null}}});
      assert.equal(method, 'signTransaction');
      return Response.json({status:'SUCCESS', result:{validation:{result_type:verdict}}});
    }
  };
  return {calls, create:() => createKmsWithdrawalSigner(options)};
}

test('The approval command hands off a receipt that the KMS-backed guard can sign', async t => {
  const {approve, transaction} = await setupApprover(t);
  const {stdout} = await approve();
  const receipt = JSON.parse(await readFile(stdout.trim(), 'utf8'));
  assert.equal(receipt.withdrawalId, authorization.withdrawalId);
  const {calls, create} = setupSigner();
  const signWithdrawal = await create();
  const signed = await signWithdrawal({transaction, approval:receipt.approval});
  const decoder = getTransactionDecoder();
  const final = decoder.decode(Buffer.from(signed, 'base64'));
  assert.deepEqual(final.messageBytes, decoder.decode(Buffer.from(transaction, 'base64')).messageBytes);
  assert.ok(verify(null, final.messageBytes, wallet.publicKey, final.signatures[signer]));
  assert.deepEqual(calls, ['GetPublicKey', 'getGenesisHash', 'simulateTransaction', 'signTransaction', 'Sign']);
});

test('The approval command refuses a mismatch and issues only one receipt per record across processes', async t => {
  const rejected = await setupApprover(t, {...authorization, lamports:'41'});
  await assert.rejects(rejected.approve(), /differs from the trusted withdrawal record/);
  assert.equal((await readdir(rejected.dir)).length, 3);

  const accepted = await setupApprover(t);
  const results = await Promise.allSettled([accepted.approve(), accepted.approve()]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.match(results.find(result => result.status === 'rejected').reason.stderr, /approval already exists/);
  await writeFile(accepted.proposalFile, proposal(13));
  await assert.rejects(accepted.approve(), /approval already exists/);
  assert.equal((await readdir(accepted.dir)).length, 4);
});

test('A substituted KMS key or a suspicious scan never triggers a KMS signature', async t => {
  const wrongKey = setupSigner(approver.publicKey);
  await assert.rejects(wrongKey.create(), /does not match the configured Solana wallet/);
  assert.deepEqual(wrongKey.calls, ['GetPublicKey']);

  const {approve, transaction} = await setupApprover(t);
  const {stdout} = await approve();
  const {approval} = JSON.parse(await readFile(stdout.trim(), 'utf8'));
  const {calls, create} = setupSigner(wallet.publicKey, 'Warning');
  const signWithdrawal = await create();
  await assert.rejects(signWithdrawal({transaction, approval}), /did not clear/);
  await assert.rejects(signWithdrawal({transaction:proposal(13), approval}), /exact bytes/);
  assert.deepEqual(calls, ['GetPublicKey', 'getGenesisHash', 'simulateTransaction', 'signTransaction']);
});

test('The signer command exits without credentials when required inputs are missing', async () => {
  await assert.rejects(run(process.execPath, [signingTool]), /Usage: node kms-withdrawal-signer/);
});
