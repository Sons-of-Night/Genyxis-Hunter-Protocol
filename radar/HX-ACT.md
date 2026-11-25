# HX-ACT v1 — isolated authorization verifier

Status: development library; not connected to Radar, Solana, customer systems, or an active response executor. This module evaluates authorization only. An authorization result is not evidence that an action was performed or that a threat is real.

## Contract

| Action | Mode | Maximum lifetime |
|---|---|---:|
| read-telemetry | GREEN | 300 seconds |
| investigate-case | AMBER | 120 seconds |
| approve-response-plan | RED | 30 seconds |

RED approves a response plan, not its execution. All modes require a signed, single-use capability and a holder proof. Denial reports GREEN as the fallback mode but grants no access.

Claims are versioned and bound to audience, asset, action, SHA-256 digest of exact request bytes, holder public-key fingerprint, nonce and validity interval. The issuer signs a fixed-order JSON array with an explicit domain separator. The holder signs a separate domain plus the capability digest and a fresh 32-byte challenge. RED requires a third Ed25519 signature from a distinct independent approver. Use trusted issuer/approver public keys provisioned outside this library. Key possession alone does not establish human identity or hardware-backed custody.

The enforcement-side caller must construct the expected audience, asset, action and request digest from its own trusted request context, generate the challenge using a secure random generator, and associate it with the authenticated request/session. Never take expected values or challenge directly from an untrusted request body. Protect the full presentation against interception: challenge binding does not prevent theft and racing of an entire valid presentation for the same challenge. An allowlist specifies exact asset/action combinations; no wildcard or arbitrary command execution is supported.

## Qualification requirements

The memory replay store is only for tests and isolated fixtures. It does not survive a restart or coordinate independent processes. A production store must atomically consume a nonce across all enforcement instances, retain it through expiration, fail closed when unavailable, and handle clock rollback. A trusted clock, fresh revocation state for token and subject, secure challenge lifecycle, issuer/approver key lifecycle, hardware custody, authenticated transport, tamper-evident decision records and independent security review are required before actual enforcement. Revocation is a synchronous trusted callback; only explicit false permits authorization. A revoked token cannot authorize a new decision, but the verifier does not undo past decisions or maintain a live global mode.

## Tests

From the radar directory run:

    node --test test/hx-act.test.mjs
    npm test

The tests use disposable Ed25519 keys and isolated fixtures; no external service, real customer asset, or funded wallet is needed. The full radar suite also discovers the new test file automatically.

## Integration boundary

Keep HX-ACT independent of Exoward. Future identity credentials can establish eligibility for issuance without revealing DNA or personal data. Actual response execution requires a separate policy decision and enforcement point, current authorization at time of use, verified incident evidence, customer-approved asset ownership, independent approval, blast-radius limits, rollback and QMS qualification. No One Point proprietary technique, vendor API, or partnership is implied by this module.
