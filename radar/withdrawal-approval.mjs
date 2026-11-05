import {createHash, createPrivateKey, sign} from 'node:crypto';
import {readFile, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {inspectWithdrawal, withdrawalApprovalMessage} from './withdrawal-guard.mjs';

export async function approveWithdrawal({transaction, authorization, approverPrivateKey, receiptDirectory}) {
  const {withdrawalId, signer, destination, lamports} = authorization;
  if (typeof withdrawalId !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,127}$/.test(withdrawalId)) {
    throw new Error('The trusted record must have a lowercase withdrawalId');
  }
  const decoded = inspectWithdrawal(transaction);
  if (signer !== decoded.signer || destination !== decoded.destination || lamports !== String(decoded.lamports)) {
    throw new Error('The transaction differs from the trusted withdrawal record');
  }

  const key = createPrivateKey(approverPrivateKey);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Use an Ed25519 approval key');
  const expiresAt = Date.now() + 45_000;
  const signature = sign(null, withdrawalApprovalMessage(transaction, expiresAt), key).toString('base64');
  const idHash = createHash('sha256').update(withdrawalId).digest('hex');
  const path = join(receiptDirectory, `${idHash}.json`);
  const receipt = {withdrawalId, signer, destination, lamports, messageHash:decoded.messageHash, approval:{expiresAt, signature}};
  try {
    await writeFile(path, JSON.stringify(receipt) + '\n', {flag:'wx', mode:0o600, flush:true});
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error('An approval already exists for this withdrawalId');
    throw error;
  }
  return path;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const [proposalFile, authorizationFile, privateKeyFile, receiptDirectory, extra] = process.argv.slice(2);
    if (!receiptDirectory || extra !== undefined) {
      throw new Error('Usage: node withdrawal-approval.mjs unsigned.txt trusted-record.json approver-private.pem receipt-directory');
    }
    const transaction = (await readFile(proposalFile, 'utf8')).trim();
    const authorization = JSON.parse((await readFile(authorizationFile, 'utf8')).replace(/^\uFEFF/, ''));
    const approverPrivateKey = (await readFile(privateKeyFile, 'utf8')).trim();
    const path = await approveWithdrawal({transaction, authorization, approverPrivateKey, receiptDirectory});
    console.log(path);
  } catch (error) {
    console.error(`Approval failed: ${error instanceof SyntaxError ? 'Invalid trusted record JSON' : error.message}`);
    process.exitCode = 1;
  }
}
