import {createHash, createPublicKey, verify} from 'node:crypto';
import {getBase58Encoder} from '@solana/codecs-strings';
import {getCompiledTransactionMessageCodec} from '@solana/transaction-messages';
import {getTransactionDecoder, getTransactionEncoder} from '@solana/transactions';

const SYSTEM_PROGRAM = '11111111111111111111111111111111';
const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
const MAINNET_RPC = 'https://api.mainnet.solana.com';
const SCAN_URL = 'https://api.blockaid.io/v0/solana/message/scan';
const APPROVAL_TTL_MS = 60_000;
const MAX_LAMPORTS = (1n << 64n) - 1n;
const base58 = getBase58Encoder();
const messageCodec = getCompiledTransactionMessageCodec();
const transactionDecoder = getTransactionDecoder();
const transactionEncoder = getTransactionEncoder();

function publicKeyBytes(address) {
  if (typeof address !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) {
    throw new Error('Invalid Solana public key');
  }
  const bytes = Buffer.from(base58.encode(address));
  if (bytes.length !== 32) throw new Error('Invalid Solana public key');
  return bytes;
}

function decodeBase64(value, maxBytes) {
  if (typeof value !== 'string' || !value || value.length > 4 * Math.ceil(maxBytes / 3)) {
    throw new Error('Invalid base64 payload');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > maxBytes || bytes.toString('base64') !== value) throw new Error('Invalid base64 payload');
  return bytes;
}

function mainnetRpcUrl(rpcUrl) {
  const url = new URL(rpcUrl);
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new Error('Configure a trusted HTTPS Solana RPC');
  }
  return url.href;
}

async function postJson(fetchImpl, url, body, signal, headers = {}) {
  const response = await fetchImpl(url, {
    method:'POST', headers:{'Content-Type':'application/json', ...headers},
    body:JSON.stringify(body), signal, redirect:'error', cache:'no-store'
  });
  if (!response.ok) throw new Error('Upstream HTTP error');
  return response.json();
}

async function requireMainnet(fetchImpl, rpc, signal) {
  const genesis = await postJson(fetchImpl, rpc, {jsonrpc:'2.0',id:1,method:'getGenesisHash'}, signal);
  if (genesis?.id !== 1 || genesis.error || genesis.result !== MAINNET_GENESIS) {
    throw new Error('Mainnet identity unavailable');
  }
}

export async function prepareWithdrawalProposal({signer, destination, lamports, rpcUrl = MAINNET_RPC, fetchImpl = fetch}) {
  publicKeyBytes(signer);
  publicKeyBytes(destination);
  if (new Set([signer, destination, SYSTEM_PROGRAM]).size !== 3) {
    throw new Error('Use distinct wallet and destination addresses');
  }
  if (typeof lamports !== 'string' || !/^[1-9][0-9]{0,19}$/.test(lamports) || BigInt(lamports) > MAX_LAMPORTS) {
    throw new Error('Specify lamports as a positive decimal string within the Solana amount limit');
  }
  const rpc = mainnetRpcUrl(rpcUrl);
  const signal = AbortSignal.timeout(6_000);
  let blockhash, lastValidBlockHeight;
  try {
    await requireMainnet(fetchImpl, rpc, signal);
    const body = await postJson(fetchImpl, rpc, {
      jsonrpc:'2.0', id:2, method:'getLatestBlockhash', params:[{commitment:'confirmed'}]
    }, signal);
    if (body?.id !== 2 || body.error) throw new Error('Bad blockhash response');
    ({blockhash, lastValidBlockHeight} = body.result.value);
    publicKeyBytes(blockhash);
    if (!Number.isSafeInteger(lastValidBlockHeight) || lastValidBlockHeight <= 0) throw new Error('Bad block height');
  } catch {
    throw new Error('Unable to obtain a current Solana mainnet blockhash');
  }

  const transfer = Buffer.alloc(12);
  transfer.writeUInt32LE(2);
  transfer.writeBigUInt64LE(BigInt(lamports), 4);
  const messageBytes = messageCodec.encode({
    version:'legacy', header:{numSignerAccounts:1,numReadonlySignerAccounts:0,numReadonlyNonSignerAccounts:1},
    staticAccounts:[signer,destination,SYSTEM_PROGRAM], lifetimeToken:blockhash,
    instructions:[{programAddressIndex:2,accountIndices:[0,1],data:transfer}]
  });
  const transaction = Buffer.from(transactionEncoder.encode({messageBytes, signatures:{[signer]:null}})).toString('base64');
  return {transaction, lastValidBlockHeight};
}

// A narrow withdrawal policy keeps lookup tables, CPIs, extra fees and delegated
// authority outside the signing path even if a scanner misses a new attack.
function parseWithdrawal(transaction) {
  let message, wire, decoded;
  try {
    wire = decodeBase64(transaction, 1_232);
    decoded = transactionDecoder.decode(wire);
    const messageBytes = Buffer.from(decoded.messageBytes);
    message = messageCodec.decode(messageBytes);
    if (!wire.equals(transactionEncoder.encode(decoded)) || !messageBytes.equals(messageCodec.encode(message))) {
      throw new Error('Noncanonical transaction');
    }
  } catch {
    throw new Error('Malformed or unsupported Solana transaction');
  }
  const {header, staticAccounts, instructions, version, addressTableLookups} = message;
  const [signer, destination, program] = staticAccounts;
  if ((version !== 'legacy' && version !== 0) || addressTableLookups?.length || staticAccounts.length !== 3
    || new Set(staticAccounts).size !== 3 || program !== SYSTEM_PROGRAM
    || header.numSignerAccounts !== 1 || header.numReadonlySignerAccounts !== 0
    || header.numReadonlyNonSignerAccounts !== 1 || decoded.signatures[signer] !== null || instructions.length !== 1) {
    throw new Error('Only unsigned, single-signer native SOL transfers are supported');
  }
  const {programAddressIndex, accountIndices, data} = instructions[0];
  const instruction = Buffer.from(data ?? []);
  if (programAddressIndex !== 2 || accountIndices?.length !== 2 || accountIndices[0] !== 0 || accountIndices[1] !== 1
    || instruction.length !== 12 || instruction.readUInt32LE(0) !== 2) {
    throw new Error('Withdrawal instruction must be a native SOL transfer');
  }
  const lamports = instruction.readBigUInt64LE(4);
  if (lamports === 0n) throw new Error('Withdrawal amount must be positive');
  const messageHash = createHash('sha256').update(decoded.messageBytes).digest('hex');
  return {withdrawal:{signer, destination, lamports, messageHash}, decoded};
}

export function inspectWithdrawal(transaction) {
  return parseWithdrawal(transaction).withdrawal;
}

function approvalMessage({signer, messageHash}, expiresAt) {
  return Buffer.from(`huntxr:solana-mainnet-withdrawal:v1\n${signer}\n${messageHash}\n${expiresAt}`, 'utf8');
}

// The independent approver uses these bytes after reviewing the decoded transfer.
export function withdrawalApprovalMessage(transaction, expiresAt) {
  if (!Number.isSafeInteger(expiresAt)) throw new Error('Invalid approval expiry');
  return approvalMessage(inspectWithdrawal(transaction), expiresAt);
}

export function createProtectedWithdrawalSigner({
  signerAddress, approverPublicKey, allowedDestinations, maxLamports, signMessage,
  blockaidApiKey, rpcUrl = MAINNET_RPC, fetchImpl = fetch, now = Date.now
}) {
  const signerBytes = publicKeyBytes(signerAddress);
  const signer = createPublicKey({format:'jwk', key:{kty:'OKP',crv:'Ed25519',x:signerBytes.toString('base64url')}});
  if (typeof approverPublicKey !== 'string' || !approverPublicKey.startsWith('-----BEGIN PUBLIC KEY-----')) {
    throw new Error('Configure the independent approver Ed25519 public key as SPKI PEM');
  }
  const approver = createPublicKey(approverPublicKey);
  if (approver.asymmetricKeyType !== 'ed25519' || signerBytes.toString('base64url') === approver.export({format:'jwk'}).x) {
    throw new Error('The approval key must be a separate Ed25519 key');
  }
  if (!Array.isArray(allowedDestinations) || !allowedDestinations.length) throw new Error('Configure approved destinations');
  for (const address of allowedDestinations) publicKeyBytes(address);
  const destinations = new Set(allowedDestinations);
  if (typeof maxLamports !== 'bigint' || maxLamports <= 0n || maxLamports > MAX_LAMPORTS) {
    throw new Error('Configure a positive withdrawal cap in lamports as a BigInt');
  }
  if (typeof signMessage !== 'function' || typeof blockaidApiKey !== 'string' || !blockaidApiKey.trim()) {
    throw new Error('Configure the isolated signing adapter and Blockaid API key');
  }
  const rpc = mainnetRpcUrl(rpcUrl);

  return async function signWithdrawal({transaction, approval}) {
    const {withdrawal, decoded} = parseWithdrawal(transaction);
    if (withdrawal.signer !== signerAddress) throw new Error('Withdrawal signer does not match the configured wallet');
    if (!destinations.has(withdrawal.destination)) throw new Error('Withdrawal destination is outside the approved list');
    if (withdrawal.lamports > maxLamports) throw new Error('Withdrawal exceeds the configured cap');
    const {expiresAt, signature} = approval ?? {};
    const checkedAt = now();
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= checkedAt || expiresAt - checkedAt > APPROVAL_TTL_MS
      || !verify(null, approvalMessage(withdrawal, expiresAt), approver, decodeBase64(signature, 64))) {
      throw new Error('Withdrawal requires a valid, unexpired independent approval for these exact bytes');
    }

    const signal = AbortSignal.timeout(6_000);
    let scan;
    try {
      await requireMainnet(fetchImpl, rpc, signal);
      const simulation = await postJson(fetchImpl, rpc, {
        jsonrpc:'2.0',id:2,method:'simulateTransaction',params:[transaction,{
          encoding:'base64',commitment:'confirmed',sigVerify:false,replaceRecentBlockhash:false
        }]
      }, signal);
      if (simulation?.id !== 2 || simulation.error || simulation.result?.value?.err !== null) {
        throw new Error('Transaction simulation did not pass');
      }
      scan = await postJson(fetchImpl, SCAN_URL, {
        account_address:signerAddress, metadata:{}, transactions:[transaction],
        chain:'mainnet', encoding:'base64', method:'signTransaction', options:['validation']
      }, signal, {'X-API-Key':blockaidApiKey});
    } catch {
      throw new Error('Withdrawal screening failed. Signing was withheld');
    }
    if (scan?.status !== 'SUCCESS' || scan.error != null || scan.result?.validation?.result_type !== 'Benign') {
      throw new Error('Threat screening did not clear the withdrawal');
    }
    if (signal.aborted || expiresAt <= now()) throw new Error('Withdrawal screening or approval expired before signing');
    const messageBytes = Buffer.from(decoded.messageBytes);
    const signed = await signMessage(Buffer.from(messageBytes), {signal});
    if (!(signed instanceof Uint8Array) || signed.length !== 64 || !verify(null, messageBytes, signer, signed)) {
      throw new Error('The signer returned a signature for a different key or message');
    }
    if (signal.aborted || expiresAt <= now()) throw new Error('Withdrawal screening or approval expired before the signature was returned');
    return Buffer.from(transactionEncoder.encode({messageBytes, signatures:{[signerAddress]:signed}})).toString('base64');
  };
}
