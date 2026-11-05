import {createPublicKey} from 'node:crypto';
import {readFile, writeFile} from 'node:fs/promises';
import {dirname, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {GetPublicKeyCommand, KMSClient, SignCommand} from '@aws-sdk/client-kms';
import {getBase58Decoder} from '@solana/codecs-strings';
import {createProtectedWithdrawalSigner} from './withdrawal-guard.mjs';

const ALGORITHM = 'ED25519_SHA_512';

export async function createKmsWithdrawalSigner({keyArn, kms, ...policy}) {
  const match = typeof keyArn === 'string' && /^arn:aws(?:-cn|-us-gov)?:kms:([a-z0-9-]+):[0-9]{12}:key\/[a-z0-9-]+$/.exec(keyArn);
  if (!match) throw new Error('Configure the immutable ARN of an AWS KMS key');
  const client = kms ?? new KMSClient({region:match[1], maxAttempts:1});

  const send = async (command, abortSignal, operation) => {
    try { return await client.send(command, {abortSignal}); }
    catch { throw new Error(`AWS KMS ${operation} failed`); }
  };

  const response = await send(new GetPublicKeyCommand({KeyId:keyArn}), AbortSignal.timeout(5_000), 'public key lookup');
  if (response.KeyId !== keyArn || response.KeySpec !== 'ECC_NIST_EDWARDS25519' || response.KeyUsage !== 'SIGN_VERIFY'
    || !response.SigningAlgorithms?.includes(ALGORITHM) || !(response.PublicKey instanceof Uint8Array)) {
    throw new Error('AWS KMS key metadata does not match the configured Ed25519 signing key');
  }
  const key = createPublicKey({key:Buffer.from(response.PublicKey), format:'der', type:'spki'});
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('AWS KMS did not return an Ed25519 public key');
  const signerAddress = getBase58Decoder().decode(Buffer.from(key.export({format:'jwk'}).x, 'base64url'));
  if (signerAddress !== policy.signerAddress) throw new Error('AWS KMS public key does not match the configured Solana wallet');

  return createProtectedWithdrawalSigner({...policy, signMessage:async (messageBytes, {signal}) => {
    const result = await send(new SignCommand({
      KeyId:keyArn, SigningAlgorithm:ALGORITHM, MessageType:'RAW', Message:messageBytes
    }), signal, 'signing');
    if (result.KeyId !== keyArn || result.SigningAlgorithm !== ALGORITHM) {
      throw new Error('AWS KMS signature metadata does not match the configured key');
    }
    return result.Signature;
  }});
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const [configFile, proposalFile, approvalFile, output, extra] = process.argv.slice(2);
    if (!output || extra !== undefined) {
      throw new Error('Usage: node kms-withdrawal-signer.mjs signer-config.json unsigned.txt approval.json signed.txt|--discard');
    }
    const readJson = async path => JSON.parse((await readFile(path, 'utf8')).replace(/^\uFEFF/, ''));
    const {keyArn, signerAddress, allowedDestinations, maxLamports, approverPublicKeyFile, rpcUrl} = await readJson(configFile);
    if (typeof maxLamports !== 'string' || !/^[1-9][0-9]{0,19}$/.test(maxLamports)) {
      throw new Error('The signer config must specify maxLamports as a positive decimal string');
    }
    const transaction = (await readFile(proposalFile, 'utf8')).trim();
    const {approval} = await readJson(approvalFile);
    const approverPublicKey = (await readFile(resolve(dirname(configFile), approverPublicKeyFile), 'utf8')).trim();
    const signWithdrawal = await createKmsWithdrawalSigner({
      keyArn, signerAddress, allowedDestinations, maxLamports:BigInt(maxLamports), approverPublicKey, rpcUrl,
      blockaidApiKey:process.env.BLOCKAID_CLIENT_API_KEY
    });
    const signed = await signWithdrawal({transaction, approval});
    if (output === '--discard') console.log('Signature verified and discarded');
    else {
      await writeFile(output, signed + '\n', {flag:'wx', mode:0o600});
      console.log('Verified signature written to the specified output file');
    }
  } catch (error) {
    console.error(`Signing failed: ${error instanceof SyntaxError ? 'Invalid configuration or approval JSON' : error.message}`);
    process.exitCode = 1;
  }
}
