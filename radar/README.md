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

Node.js 22 or later required. From the repository root:

    cd radar
    node --version
    node --test test/*.test.mjs

    export HUNTER_RADAR_RPC_HTTP='https://api.mainnet.solana.com'
    export HUNTER_RADAR_RPC_WS='wss://api.mainnet.solana.com'

    # Optional: comma-separated Solana PUBLIC addresses only.
    export HUNTER_RADAR_WATCH_ADDRESSES=''
    export HUNTER_RADAR_DENY_ADDRESSES=''

    node server.mjs

Open http://127.0.0.1:4190 from the host computer. Radar binds only to 127.0.0.1 and uses port 4190.

The public Solana endpoints may reject or throttle high-volume stream requests; for sustained commercial use, configure a paid mainnet-capable RPC provider. Errors or unavailable coverage are displayed as such, never replaced by simulated data.

## Pre-sign assessment

POST http://127.0.0.1:4190/api/assess
Content-Type: application/json

    {"programIds":["11111111111111111111111111111111"],"accounts":[]}

Returns decision=deny only for an address on the configured denylist; otherwise decision=no_match. No_match does NOT prove that the transaction is safe. This endpoint does not simulate, sign, submit or stop a transaction. A customer's wallet or dApp must integrate and honor its decision to provide preventive action. Do not directly expose this unauthenticated loopback-only prototype to the internet.

## Current limits

1. Session-only, bounded activity history (500 events in memory, last 100 sent to the dashboard). Stream gaps are not backfilled. Confirmed commitment can later be reorganized; no finalized reconciliation yet.
2. An all-logs subscription may not provide complete reliable network coverage due to provider limits. Production requires durable indexing, Yellowstone/Geyser streaming, missed-slot backfill and coverage metrics.
3. No validated classification of malicious AI agents, drainers, exploits, safe contracts or infected wallets. Simple failed transactions are not attacks.
4. Operator-configured denylist only; policy decisions are recommendations and not proof that an on-chain attack was blocked.
5. Real security productization requires verified threat intelligence, decoded transactions and balances, pre-sign simulation, authenticated multi-tenant services, incident evidence, secure alerts, independent review and wallet/dApp enforcement integrations.
6. Watch addresses may be sensitive. Keep seed phrases, private keys, lab DNA data and other personal secrets off the dashboard and RPC provider.

## Verification

Run the offline deterministic logic tests with:

    node --test test/*.test.mjs

The tests use synthetic fixtures to validate the parser and API. The running product never reads test fixtures or displays mock alerts.
