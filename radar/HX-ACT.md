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

## Persistent state — single-host pilot

`hx-act-state.mjs` uses the built-in SQLite API (Node.js 22.13 or newer; qualify the exact runtime). Provision a dedicated service-owned directory on a local filesystem with restricted permissions (including database, WAL, and SHM files). Keep a separate 32-byte random audit HMAC key in a protected secret store. Call `initializeState({path,auditKey})` explicitly once for a new deployment; an existing path cannot be initialized again. Call `openState({path,auditKey,checkpoint})` for subsequent runs; a missing file, wrong key, unsupported schema or failed integrity check prevents opening. Never automatically initialize state following failure or loss.

Pass the open state as `decisionStore` to `createVerifier` instead of the legacy `replayStore` and `isRevoked` options. After signature and scope verification, a single SQLite write transaction checks expiration against a fresh clock reading, emergency halt, subject and token revocation, and nonce reuse, then appends the decision. Concurrent connections share the same unique nonce constraint. A storage error or backward clock reading denies authorization; no successful decision is returned before commit.

Trusted administrative code may call `revokeSubject(fingerprint)`, `revokeToken(nonce)` or `emergencyHalt()`. These events persist in the ledger; no automatic unhalt or revocation removal exists. Halt prevents all new privileged authorizations; it does not undo prior decisions or stop an external action already in progress. Keep these methods behind a separately authorized administrative boundary; do not expose the object directly to untrusted requests.

`verifyAudit()` returns the latest sequence and HMAC. Save it in a separately protected, independently retained checkpoint store; supply a trusted checkpoint on opening or verification to detect truncation/rollback past it. The ledger authenticates rows and ordering, and contains no private keys, raw request bodies or genetic data. It records successful and state-denied cryptographically verified requests, plus administrative events; invalid presentations and storage failures still require external operational audit logging. HMAC integrity is not nonrepudiation, and does not protect against compromise of the audit key, live privileged database tampering or restoration to a newer-than-checkpoint valid prefix. Verify periodically and restrict database/key access. A detected audit verification failure latches the open handle into a denied state; close it and perform controlled recovery, not automatic reinitialization. No automatic pruning is provided: qualify growth, disk-full handling, backup/restore, clock recovery, monitoring and independent checkpoint publication before release. A multi-host deployment needs an independently qualified shared transactional backend; do not use a shared network filesystem for this SQLite pilot.

## Tests

From the radar directory run:

    node --test test/hx-act.test.mjs test/hx-act-state.test.mjs
    npm test

The tests use disposable Ed25519 keys and isolated fixtures; no external service, real customer asset, or funded wallet is needed. The full radar suite also discovers the new test file automatically.

## Integration boundary

Keep HX-ACT independent of Exoward. Future identity credentials can establish eligibility for issuance without revealing DNA or personal data. Actual response execution requires a separate policy decision and enforcement point, current authorization at time of use, verified incident evidence, customer-approved asset ownership, independent approval, blast-radius limits, rollback and QMS qualification. No One Point proprietary technique, vendor API, or partnership is implied by this module.
