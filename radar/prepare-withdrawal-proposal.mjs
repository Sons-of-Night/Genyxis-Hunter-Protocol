import {readFile, writeFile} from 'node:fs/promises';
import {prepareWithdrawalProposal} from './withdrawal-guard.mjs';

try {
  const [input, output, extra] = process.argv.slice(2);
  if (!output || extra !== undefined) {
    throw new Error('Usage: node prepare-withdrawal-proposal.mjs proposal.json unsigned.txt');
  }
  const {signer, destination, lamports, rpcUrl} = JSON.parse((await readFile(input, 'utf8')).replace(/^\uFEFF/, ''));
  const {transaction, lastValidBlockHeight} = await prepareWithdrawalProposal({signer, destination, lamports, rpcUrl});
  await writeFile(output, transaction + '\n', {flag:'wx', mode:0o600});
  console.log(`Unsigned proposal written. Last valid block height: ${lastValidBlockHeight}`);
} catch (error) {
  console.error(`Proposal failed: ${error instanceof SyntaxError ? 'Invalid proposal JSON' : error.message}`);
  process.exitCode = 1;
}
