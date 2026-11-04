import assert from 'node:assert/strict';
import test from 'node:test';
import { createLab, createRequest, MAX_PERMIT_SLOTS, wallet } from './hunter.mjs';

function fixture() {
  const campaign = 'test-campaign';
  const slot = 400;
  const claimant = wallet();
  const other = wallet();
  const hunter = createLab(campaign, [claimant.publicKey, other.publicKey]);
  const request = createRequest(campaign, claimant, slot + 30);
  const { permit } = hunter.issue(request, slot);
  assert.equal(permit.length, 64);
  return { campaign, slot, claimant, other, hunter, request, permit };
}

test('an eligible wallet can claim exactly once', () => {
  const { hunter, request, permit, slot } = fixture();
  assert.equal(hunter.submit(request, permit, slot), 'CLAIM_ACCEPTED');
  assert.equal(hunter.submit(request, permit, slot + 1), 'ALREADY_CLAIMED');
  assert.equal(hunter.claimCount(), 1);
});

test('a freshly signed second permit still cannot claim twice', () => {
  const { hunter, request, permit, campaign, claimant, slot } = fixture();
  assert.equal(hunter.submit(request, permit, slot), 'CLAIM_ACCEPTED');
  const second = createRequest(campaign, claimant, slot + 40);
  assert.equal(hunter.submit(second, hunter.issue(second, slot).permit, slot), 'ALREADY_CLAIMED');
  assert.equal(hunter.claimCount(), 1);
});

test('a direct call without an issuer signature leaves no receipt', () => {
  const { hunter, request, slot } = fixture();
  assert.equal(hunter.submit(request, undefined, slot), 'ISSUER_SIGNATURE_REQUIRED');
  assert.equal(hunter.claimCount(), 0);
});

test('a copied permit does not authorize a different wallet', () => {
  const { hunter, permit, campaign, other, request, slot } = fixture();
  const alternate = createRequest(campaign, other, request.claim.expiresAtSlot);
  assert.equal(hunter.submit(alternate, permit, slot), 'INVALID_ISSUER_SIGNATURE');
  assert.equal(hunter.claimCount(), 0);
});

test('a wallet cannot extend the issuer-signed expiry', () => {
  const { hunter, campaign, claimant, permit, request, slot } = fixture();
  const modified = createRequest(campaign, claimant, request.claim.expiresAtSlot + 1);
  assert.equal(hunter.submit(modified, permit, slot), 'INVALID_ISSUER_SIGNATURE');
});

test('a second issuer cannot sign for a campaign', () => {
  const { campaign, claimant, hunter, request, slot } = fixture();
  const unrelatedIssuer = createLab(campaign, [claimant.publicKey]);
  const rogue = unrelatedIssuer.issue(request, slot);
  assert.equal(hunter.submit(request, rogue.permit, slot), 'INVALID_ISSUER_SIGNATURE');
});

test('eligibility and wallet authorization are independent requirements', () => {
  const { campaign, request, hunter, other, slot } = fixture();
  const unknown = createRequest(campaign, wallet(), slot + 30);
  assert.equal(hunter.issue(unknown, slot).decision, 'WALLET_NOT_ELIGIBLE');
  assert.equal(hunter.issue({ ...request, claimant: other.publicKey }, slot).decision,
    'INVALID_WALLET_SIGNATURE');
});

test('slot window is exclusive at expiry and capped at issuance', () => {
  const { hunter, campaign, claimant, request, permit, slot } = fixture();
  assert.equal(hunter.submit(request, permit, request.claim.expiresAtSlot), 'PERMIT_OUTSIDE_WINDOW');
  assert.equal(hunter.claimCount(), 0);
  const atCap = createRequest(campaign, claimant, slot + MAX_PERMIT_SLOTS);
  const overCap = createRequest(campaign, claimant, slot + MAX_PERMIT_SLOTS + 1);
  assert.equal(hunter.issue(atCap, slot).decision, 'PERMIT_ISSUED');
  assert.equal(hunter.issue(overCap, slot).decision, 'PERMIT_OUTSIDE_WINDOW');
});

test('permits are scoped to the campaign', () => {
  const { hunter, other, permit, slot } = fixture();
  const request = createRequest('other-campaign', other, slot + 30);
  assert.equal(hunter.submit(request, permit, slot), 'WRONG_CAMPAIGN');
});

test('an eligible automated client follows the same rules', () => {
  const { hunter, campaign, other, slot } = fixture();
  const request = createRequest(campaign, other, slot + 20);
  assert.equal(hunter.submit(request, hunter.issue(request, slot).permit, slot), 'CLAIM_ACCEPTED');
  assert.equal(hunter.claimCount(), 1);
});
