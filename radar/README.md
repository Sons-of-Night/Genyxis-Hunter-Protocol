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

Run this on a Genyxis-owned or explicitly authorized Kali/Ubuntu host with Node.js 22 or newer, npm, and Suricata. Check prerequisites from the `radar` directory:

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
