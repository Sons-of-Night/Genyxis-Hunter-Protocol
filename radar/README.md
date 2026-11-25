# Hunter Radar — Solana Mainnet Security Operations

**Status:** Working mainnet telemetry foundation (development), not an audited or commercially ready security service. No fake transactions or threats.

Hunter Radar is a separate Solana security dashboard in Genyxis Hunter Protocol. It does NOT depend on the Hunter Guard program or a synthetic rewards campaign.

## Real capabilities

- Subscribes to Solana MAINNET non-vote transaction logs using RPC logsSubscribe with the all filter, plus optional targeted subscriptions for up to 12 public wallet/program addresses.
- Receives successful and failed transaction observations and actual program invocation IDs from blockchain logs. Failed does not mean malicious.
- Identifies observed invocations of programs included in an OPERATOR-CONFIGURED denylist. No external verified threat feed is installed yet.
- Offers a pre-sign policy-check HTTP API; applications may integrate and enforce a deny decision for their own users. This cannot block Solana-wide transactions.
- Live activity charts, realtime event feed, 3D projection using ACTUAL received signatures, mainnet slot health, stream outage flags and gap counts.
- All chain interactions are read-only. No private keys, signed transactions, ledger changes or interactions with Genyxis preserved fresh-v1.

## Start on real Solana mainnet

Node.js 22.13 or later required. From the repository root:

    cd radar
    node --version
    npm ci
    node --test test/*.test.mjs

    export HUNTER_RADAR_RPC_HTTP='https://api.mainnet.solana.com'
    export HUNTER_RADAR_RPC_WS='wss://api.mainnet.solana.com'

    # Optional: comma-separated Solana PUBLIC addresses only.
    export HUNTER_RADAR_WATCH_ADDRESSES=''
    export HUNTER_RADAR_DENY_ADDRESSES=''

    node server.mjs

Open http://127.0.0.1:4190 from the host computer. Radar binds only to 127.0.0.1 and uses port 4190.

The public Solana endpoints may reject or throttle high-volume stream requests; for sustained commercial use, configure a paid mainnet-capable RPC provider. Errors or unavailable coverage are displayed as such, never replaced by simulated data.

## Local operator authentication

Before starting Radar, provision a high-entropy 32-byte random secret encoded as 64 lowercase hexadecimal characters through the host's protected secret store. Set `HUNTER_RADAR_OPERATOR_TOKEN` in the service environment. Optionally provision a different secret as `HUNTER_RADAR_VIEWER_TOKEN`. For a temporary interactive Bash launch, read the provisioned operator secret without echoing it:

```bash
read -rsp 'Huntxr operator token: ' HUNTER_RADAR_OPERATOR_TOKEN; echo
export HUNTER_RADAR_OPERATOR_TOKEN
node server.mjs
unset HUNTER_RADAR_OPERATOR_TOKEN
```

Generate secrets using a cryptographically secure generator (32 random bytes); never use a sample value or a human password. Do not put secrets in repository files, URLs, browser JavaScript, screenshots, shell command arguments or logs. Use a dedicated service account and restrict access to its environment.

Open the loopback dashboard in the browser and authenticate using username `operator` or `viewer` and the corresponding token as the password. Operator can read telemetry and submit policy assessments; viewer can only read. All HTTP routes require credentials. Missing/invalid configuration prevents startup, invalid credentials return 401, and viewer policy requests return 403. API clients use HTTP Basic authentication; credentials should be supplied by the client's protected credential store. For example, curl can prompt for the token interactively with `--user operator`.

This is a local single-host credential boundary only. HTTP Basic does not encrypt traffic, has no independent session expiration or per-user identity, and browser credential caching may persist until the browser session is closed. Rotate secrets by replacing the protected environment configuration and restarting the service. Do not expose Radar via Cloudflare, reverse proxy, port forwarding, LAN listener or any remote tunnel. Local malicious software or a compromised operating-system account is outside this control's trust boundary. Remote authentication, secure sessions, rate limiting, audit records and tenancy are separate release gates.

## Pre-sign assessment

POST http://127.0.0.1:4190/api/assess
Content-Type: application/json

    {"programIds":["11111111111111111111111111111111"],"accounts":[]}

Returns decision=deny only for an address on the configured denylist; otherwise decision=no_match. No_match does NOT prove that the transaction is safe. This endpoint does not simulate, sign, submit or stop a transaction. A customer's wallet or dApp must integrate and honor its decision to provide preventive action. Operator authentication is required; do not expose this loopback-only prototype to any remote network.

Send up to 64 addresses in each array and keep the UTF-8 JSON body within 8 KiB. Requests larger than 8 KiB receive HTTP 413. Use a loopback hostname or address in the request URL.

## Protected SOL withdrawal signing

The withdrawal guard runs inside a separate, trusted signer. It addresses the signing-service bypass Binance described after the October 29, 2026 theft. A withdrawal container can propose a transfer, but the signer requires an independent approval even when the transfer looks ordinary and its destination has no known threat history. [Binance preliminary incident findings](https://www.binance.com/en/square/post/384328127385979)

1. Give the approval service a separate Ed25519 key and identity. Independently verify the withdrawal against your authorization records. Use `inspectWithdrawal(transaction)` to review the signer, destination, and amount in lamports before approving. Sign `withdrawalApprovalMessage(transaction, expiresAt)` with the approval key. Supply `{expiresAt, signature}` to the signer, with expiry in Unix milliseconds up to 60 seconds ahead and the Ed25519 signature in base64.
2. Keep the withdrawal key and its KMS permissions outside the withdrawal application, its CI/CD role, and the Radar dashboard. Configure the signer with the approval public key, a destination allowlist, and a per-transfer cap. Make the guard the only application path to the withdrawal key. Use distinct, separately managed access for approval and signer policy changes.
3. Configure a trusted Solana HTTPS RPC and a Blockaid API key in the isolated service. Each approved request checks the RPC's mainnet identity, simulates the exact unsigned transaction, and requests a new Blockaid verdict. An outage, failed simulation, warning, or missing verdict withholds the signature. Both providers receive the unsigned transaction. Blockaid also receives the signer’s public address. [Solana simulation API](https://solana.com/docs/rpc/http/simulatetransaction) · [Blockaid Solana API](https://github.com/blockaid-official/blockaid-client-node/blob/main/src/resources/solana/message.ts)

```js
import {createProtectedWithdrawalSigner} from './withdrawal-guard.mjs';

const signWithdrawal = createProtectedWithdrawalSigner({
  signerAddress: config.walletAddress,
  approverPublicKey: config.approverPublicKeyPem,
  allowedDestinations: config.treasuryAddresses,
  maxLamports: BigInt(config.maxWithdrawalLamports),
  blockaidApiKey: process.env.BLOCKAID_CLIENT_API_KEY,
  rpcUrl: config.mainnetRpcUrl,
  signMessage: (messageBytes, {signal}) => isolatedSigner.signEd25519(messageBytes, {signal})
});

const signedTransaction = await signWithdrawal({transaction, approval});
```

`transaction` is a canonical base64 Solana wire transaction with a zeroed signature slot. The guard permits a single native SOL transfer in legacy or v0 format, with a recent blockhash, one signer, and no lookup tables or extra instructions. The adapter returns a raw 64-byte Ed25519 signature. The guard verifies it against the original message and returns a base64 signed transaction for the caller to submit. This is a per-transfer policy for designated wallets and treasury destinations. Token withdrawals, swaps, v1 transactions, durable nonces, and other chains are outside its scope. The dashboard remains a separate read-only service. Live signer and provider acceptance tests are pending.

### Approval and signer pilot

From `radar`, run the handoff test using disposable keys and local provider fixtures. It covers the approval command, receipt validation, the KMS request, and verification of the returned Solana signature.

```powershell
npm.cmd ci
node --test .\test\withdrawal-pilot.test.mjs
```

For the live pilot, run `--address` with the pilot key's full KMS ARN. This reads the public key and prints the Solana address. Use it as `signer` in `proposal.json`. Supply `destination` as the pilot recipient's Solana address and `lamports` as a decimal string. Optional `rpcUrl` defaults to the public mainnet HTTPS endpoint. Generate `unsigned.txt` just before approval so its blockhash is still current. The proposal command reads the mainnet blockhash and writes an unsigned transaction. [Solana blockhash RPC](https://solana.com/docs/rpc/http/getlatestblockhash) · [AWS KMS public key API](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html)

```powershell
node .\kms-withdrawal-signer.mjs --address '<pilot-key-arn>'
node .\prepare-withdrawal-proposal.mjs .\proposal.json .\unsigned.txt
```

On the approval host, verify the withdrawal against an independent record. The record JSON must supply `withdrawalId` as a unique lowercase identifier, `signer` and `destination` as Solana addresses, and `lamports` as a decimal string. The approval command compares all three transfer fields, issues a 45-second approval, and prints the receipt path. Keep a single protected receipt directory for the approval role. The withdrawal application must have no write access to the records or receipts and no access to the approval key. The command refuses a second approval for the same ID, even with a different blockhash. Reconcile the earlier request before issuing any replacement.

```powershell
node .\withdrawal-approval.mjs .\unsigned.txt .\trusted-record.json .\approver-private.pem .\receipts
```

On the isolated signer host, configure `signer-config.json` with `keyArn`, `signerAddress`, `allowedDestinations` (an array), `maxLamports` (a decimal string), and `approverPublicKeyFile` (relative to the config file). Optional `rpcUrl` defaults to Solana's public mainnet HTTPS endpoint. Use a pilot Ed25519 `SIGN_VERIFY` KMS key with an immutable key ARN and pass `BLOCKAID_CLIENT_API_KEY` through the signer's secret store. Grant the signer role `kms:GetPublicKey` and `kms:Sign` on that key. Keep these permissions and role assumption outside the withdrawal application's and deployment role's reach. [AWS KMS signing API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)

Pass the printed receipt file and original proposal to the signer promptly. For the first live acceptance run, `--discard` verifies the KMS signature and releases no signed transaction. Use `signed.txt` in its place only when an integrating application needs the verified signed transaction. The signer writes a new file and does not broadcast it. Keep key files, configuration secrets, receipts, and signed transactions in access-controlled directories outside the repository.

```powershell
node .\kms-withdrawal-signer.mjs .\signer-config.json .\unsigned.txt .\approval-receipt.json --discard
```

## Current limits

1. The activity timeline aggregates the current minute and the previous 14 minutes independently of event details (500 in memory, 100 sent to the dashboard). The last 65,536 distinct signatures are tracked for deduplication during the session. Stream gaps are not backfilled, and confirmed transactions can still be reorganized.
2. An all-logs subscription may not provide complete reliable network coverage due to provider limits. Production requires durable indexing, Yellowstone/Geyser streaming, missed-slot backfill and coverage metrics.
3. No validated classification of malicious AI agents, drainers, exploits, safe contracts or infected wallets. Simple failed transactions are not attacks.
4. The dashboard’s address policy remains advisory. Enforcement applies when an isolated wallet signer integrates the protected SOL withdrawal guard.
5. Real security productization requires verified threat intelligence, decoded transactions and balances, pre-sign simulation, authenticated multi-tenant services, incident evidence, secure alerts, independent review and wallet/dApp enforcement integrations.
6. Watch addresses may be sensitive. Keep seed phrases, private keys, lab DNA data and other personal secrets off the dashboard and RPC provider.


## Kali Linux security integration — first real sensor

Hunter Radar now supports **read-only Suricata EVE JSON intrusion detection telemetry** alongside Solana mainnet observations. Suricata can run inside an authorized Kali Linux VM or a dedicated security-monitoring system. This does not depend on our own Hunter Guard program.

1. Install/configure a Suricata sensor on networks and systems you own or have authorization to monitor. Enable its standard EVE JSON alert output according to your installed Suricata configuration. The file is commonly called eve.json.
2. Make that log file readable by the same Linux user running Hunter Radar. In separate Kali/Ubuntu VMs, use a **securely managed log export**; do not expose the EVE file or the dashboard unauthenticated over the network.
3. Set the file path and start Radar:

       export HUNTER_RADAR_SURICATA_EVE_FILE='/var/log/suricata/eve.json'
       cd radar
       node server.mjs

4. Open the new **Kali Sensors** screen. Only *newly appended* alerts are counted from the time the file monitor starts. The dashboard reports Suricata's observed alerts and actions; it does not invent activity or claim that alerts were necessarily blocked.
5. Run the Kali integration tests with:

       node --test test/suricata.test.mjs

The backend deliberately excludes source/destination IP addresses, raw payloads and packet contents from browser output. It tracks file discontinuities and read failures instead of reporting full coverage. If no local sensor is configured, the GUI says so.

**What Kali brings next:** authorized network asset discovery (Nmap), passive traffic inspection (Zeek/tshark), local signature rules (Suricata), static artifact inspection (YARA), smart-contract and wallet threat intelligence, and quarantine of traffic/resources **that the operator owns or controls**. External exploitation, hack-back, and retaliatory activity are not implemented or part of Hunter Radar's defensive operation. None of these additional tool integrations are claimed complete.

**Solana distinction:** Suricata can detect traffic affecting our own RPC endpoints, applications and servers. It cannot inspect or quarantine arbitrary Solana validator processes, and its local network alerts must never be automatically attributed to on-chain accounts. True application protection requires wallet/dApp policy enforcement and validated on-chain risk analysis.

**Cloudflare boundary:** The current first sensor is local-file-based; it is **not deployed to Cloudflare**. A future authenticated telemetry uplink or managed container would be needed to securely stream sanitized Kali events into a Cloudflare-hosted customer dashboard.

## Validate the first sensor on Kali or Ubuntu

Run this on a Genyxis-owned or explicitly authorized Kali/Ubuntu host with Node.js 22.13 or newer, npm, and Suricata. Check prerequisites from the `radar` directory:

    node --version
    suricata -V
    npm test

If Suricata is missing, install the distribution package on the test host with `sudo apt update && sudo apt install suricata`. Then, in the same terminal:

    sudo -v
    npm run verify:suricata

The check starts a short-lived Suricata capture of one randomly assigned UDP destination port on `127.0.0.1`. A harmless marker sent to that port triggers a dedicated passive rule. The script checks the real EVE record and the alert in Radar's HTTP snapshot. It checks for zero reported blocks, zero Solana observations, and the absence of raw IPs, ports, or packet payloads from the API event. Only the packet capture runs with elevated permissions. Radar listens on a temporary loopback port and the test runs without external RPC traffic.

- **Pass:** Save the three console lines beginning with `PASS Hunter Radar live loopback` as evidence for roadmap issue #2. They include the Suricata and Node versions, time, and alert results.
- **Fail before capture:** Check that `suricata -V` succeeds and that `sudo -v` ran in the same terminal. Use the Linux host or VM where packet capture is permitted.
- **Fail during capture:** The script prints the paths of the local Suricata startup log and EVE file. Review startup errors first, then check whether EVE contains the probe signature. The EVE file includes raw loopback addresses and ports.

For the separate mainnet check, start Radar normally with the public mainnet endpoints in the setup section. Open `http://127.0.0.1:4190/api/health` and confirm `rpcOk: true`, an integer `currentSlot`, `subscribed: true`, and an increasing `counters.observed`. Stop Radar with Ctrl+C. Keep this result separate from the loopback evidence. A passing loopback proves local capture and ingestion. Mainnet availability and customer-network coverage require their own evidence.

## Verification

Run the offline deterministic logic tests with:

    node --test test/*.test.mjs

The tests use synthetic fixtures to validate the parser and API. The running product never reads test fixtures or displays mock alerts.

## Local HTTP boundary hardening

The Radar HTTP listener remains loopback-only. A Host matching the actual local listener, same-origin browser requests, and JSON policy submissions are required. It rejects DNS-rebinding hosts, cross-site requests and mismatched ports, and adds bounded HTTP request/header lifetimes and restrictive browser headers. The policy body limit remains **8 KiB** (not 4 KiB) to preserve the documented 64+64 address contract and interrupted-upload handling from PR #4.

The boundary has deterministic regression tests in `npm test`; loopback Host/origin checks alone are **not** authentication; the separate credential gate is mandatory. Do not forward this port or expose it via a public reverse proxy or Cloudflare Tunnel without a separate authenticated, authorized service boundary. Live host and network sensor verification are still required.
