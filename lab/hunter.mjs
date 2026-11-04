import { generateKeyPairSync, sign, verify } from 'node:crypto';

export const MAX_PERMIT_SLOTS = 150;
const ACTION = 'genyxis-hunter:claim:model:v1';

export function wallet() {
  return generateKeyPairSync('ed25519');
}

function walletId(publicKey) {
  return publicKey.export({ format: 'jwk' }).x;
}

function claimBytes(claim) {
  return Buffer.from(JSON.stringify([
    ACTION, claim.campaign, claim.wallet, claim.expiresAtSlot,
  ]));
}

function validWindow(expiresAtSlot, slot) {
  return Number.isSafeInteger(expiresAtSlot)
    && Number.isSafeInteger(slot)
    && slot >= 0
    && expiresAtSlot > slot
    && expiresAtSlot - slot <= MAX_PERMIT_SLOTS;
}

export function createRequest(campaign, claimant, expiresAtSlot) {
  const claim = { campaign, wallet: walletId(claimant.publicKey), expiresAtSlot };
  return {
    claim,
    claimant: claimant.publicKey,
    walletSignature: sign(null, claimBytes(claim), claimant.privateKey),
  };
}

function walletAuthorized({ claim, claimant, walletSignature }) {
  return claimant?.asymmetricKeyType === 'ed25519'
    && claim.wallet === walletId(claimant)
    && Buffer.isBuffer(walletSignature)
    && walletSignature.length === 64
    && verify(null, claimBytes(claim), claimant, walletSignature);
}

export function createLab(campaign, eligiblePublicKeys) {
  const issuer = wallet();
  const issuerId = walletId(issuer.publicKey);
  const eligible = new Set(eligiblePublicKeys.map(walletId));
  const receipts = new Map();

  function issue(request, slot) {
    const { claim } = request;
    if (claim.campaign !== campaign) return { decision: 'WRONG_CAMPAIGN' };
    if (!validWindow(claim.expiresAtSlot, slot)) return { decision: 'PERMIT_OUTSIDE_WINDOW' };
    if (!walletAuthorized(request)) return { decision: 'INVALID_WALLET_SIGNATURE' };
    if (!eligible.has(claim.wallet) || claim.wallet === issuerId) {
      return { decision: 'WALLET_NOT_ELIGIBLE' };
    }
    return { decision: 'PERMIT_ISSUED', permit: sign(null, claimBytes(claim), issuer.privateKey) };
  }

  function submit(request, permit, slot) {
    const { claim } = request;
    if (claim.campaign !== campaign) return 'WRONG_CAMPAIGN';
    if (!walletAuthorized(request)) return 'INVALID_WALLET_SIGNATURE';
    if (!permit) return 'ISSUER_SIGNATURE_REQUIRED';
    if (!Buffer.isBuffer(permit) || permit.length !== 64
        || !verify(null, claimBytes(claim), issuer.publicKey, permit)) {
      return 'INVALID_ISSUER_SIGNATURE';
    }
    if (!validWindow(claim.expiresAtSlot, slot)) return 'PERMIT_OUTSIDE_WINDOW';
    if (claim.wallet === issuerId) return 'ISSUER_CANNOT_CLAIM';
    if (receipts.has(claim.wallet)) return 'ALREADY_CLAIMED';
    receipts.set(claim.wallet, { campaign, wallet: claim.wallet, claimedAtSlot: slot });
    return 'CLAIM_ACCEPTED';
  }

  return { issue, submit, claimCount: () => receipts.size };
}
