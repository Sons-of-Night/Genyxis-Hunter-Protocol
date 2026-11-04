import { createLab, createRequest, wallet } from './hunter.mjs';

const campaign = 'hunter-synthetic-rewards';
const slot = 100;
const claimant = wallet();
const permittedAutomation = wallet();
const unknownWallet = wallet();
const hunter = createLab(campaign, [claimant.publicKey, permittedAutomation.publicKey]);

function show(scenario, decision) {
  console.log(`${scenario.padEnd(43)} ${decision}`);
}

console.log('GENYXIS HUNTER PROTOCOL · OFFLINE LAB\n');
const request = createRequest(campaign, claimant, slot + 30);
const { permit } = hunter.issue(request, slot);
show('Eligible wallet', hunter.submit(request, permit, slot));
show('Reused permit', hunter.submit(request, permit, slot + 1));
show('Direct call without issuer signature', hunter.submit(request, undefined, slot));
show('Copied permit, different wallet', hunter.submit(
  createRequest(campaign, unknownWallet, slot + 30), permit, slot,
));
const unauthorized = createRequest(campaign, unknownWallet, slot + 30);
show('Ineligible wallet requesting a permit', hunter.issue(unauthorized, slot).decision);

const automated = createRequest(campaign, permittedAutomation, slot + 30);
const automatedPermit = hunter.issue(automated, slot).permit;
show('Permit presented at expiry', hunter.submit(automated, automatedPermit, slot + 30));
show('Eligible automated client', hunter.submit(automated, automatedPermit, slot + 1));
console.log(`\nAccepted claims: ${hunter.claimCount()}`);
