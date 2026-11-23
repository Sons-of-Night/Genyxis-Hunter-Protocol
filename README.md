# Genyxis Hunter Protocol

**Defensive security infrastructure for the Solana ecosystem**

Hunter is a Genyxis initiative to help Solana developers and operators **observe activity, investigate evidence-based threats, and enforce security decisions at infrastructure they control**. Its first operator-facing product is **Hunter Radar**: a local security console that combines actual Solana mainnet observations with Kali Linux-inspired network intrusion telemetry.

> **Status: development / research prototype.** Hunter Radar is not independently audited or production-ready. It does not detect every threat, identify "enemy AI" by appearance, prevent arbitrary Solana mainnet transactions, or hack back against third parties. The live dashboard does not fabricate transactions or alerts.

## Start here

| Component | What it does | Current status |
| --- | --- | --- |
| **Hunter Radar** (`radar/`) | Reads Solana mainnet transaction logs, displays live activity and slot health, offers a local pre-sign policy API, and ingests Suricata EVE alerts | Implemented development foundation; target-host and live-feed verification still needed |
| **Huntxr withdrawal guard** (`radar/withdrawal-guard.mjs`) | Requires independent approval, a permitted destination and amount, mainnet simulation, and a fresh threat verdict before signing a protected native SOL withdrawal | Signer-side library with automated tests. Live integration requires an isolated signing adapter and threat-screening credentials. |
| **Kali / Suricata sensor** (`radar/kali/`) | Reads newly appended EVE JSON intrusion alerts from a locally authorized sensor and presents sanitized alert metadata | Integration implemented; real loopback capture verification is in [draft PR #3](https://github.com/Sons-of-Night/Genyxis-Hunter-Protocol/pull/3) |
| **Hunter Guard** (`program/`) | Anchor/Solana program prototype that requires issuer authorization and records one claim receipt per campaign and claimant | Isolated synthetic-rewards proof of concept; not the Radar product |
| **Offline / chain labs** (`lab/`, `chain-lab/`) | Test authorization, signing, expiry and replay-resistance assumptions | Fixtures and test harness supplied; native Solana SBF/LiteSVM execution must be verified on a configured host |

These tracks are related, but **Hunter Radar runs independently of the synthetic rewards campaign and Hunter Guard**.

## Hunter Radar — run locally

**Requirements:** Linux (Ubuntu, Kali, or WSL) and **Node.js 22+**. Install the locked Solana SDK dependencies to run the withdrawal guard and its tests.

```bash
git clone https://github.com/Sons-of-Night/Genyxis-Hunter-Protocol.git
cd Genyxis-Hunter-Protocol/radar

node --version
npm ci
npm test

export HUNTER_RADAR_RPC_HTTP='https://api.mainnet.solana.com'
export HUNTER_RADAR_RPC_WS='wss://api.mainnet.solana.com'

npm start
```

Open **http://127.0.0.1:4190** on the same computer. Radar binds to loopback by default. Visit **http://127.0.0.1:4190/api/health** to view raw health data. A useful live-feed check is `rpcOk: true`, an integer `currentSlot`, `subscribed: true` and a rising `counters.observed` value as transactions arrive. Press **Ctrl+C** to stop.

The public mainnet endpoints may rate-limit or reject broad `logsSubscribe` requests. **A failed connection, low count, or gap is not evidence of an empty or safe network.** Commercial monitoring needs a suitable streaming/indexing provider, durable storage, gap recovery and finalized-state reconciliation.

### Optional configuration

| Variable | Purpose |
| --- | --- |
| `HUNTER_RADAR_RPC_HTTP` | Solana mainnet HTTPS JSON-RPC endpoint |
| `HUNTER_RADAR_RPC_WS` | Solana mainnet secure WebSocket endpoint |
| `HUNTER_RADAR_WATCH_ADDRESSES` | Comma-separated public Solana addresses to watch; maximum 12 |
| `HUNTER_RADAR_DENY_ADDRESSES` | Comma-separated operator-configured public addresses used by the policy API |
| `HUNTER_RADAR_SURICATA_EVE_FILE` | Absolute path of a locally readable Suricata `eve.json` alert log |

Only use **public wallet/program addresses**. Never enter seed phrases, private keys, API secrets or identity data into address lists, logs, screenshots or issues.

### Local pre-sign policy API

A participating wallet, dApp or transaction service can ask Hunter for a policy recommendation:

```bash
curl -sS -X POST http://127.0.0.1:4190/api/assess \
  -H 'Content-Type: application/json' \
  -d '{"programIds":["11111111111111111111111111111111"],"accounts":[]}'
```

- `decision: "deny"` means an address matched the **operator's configured denylist**.
- `decision: "no_match"` means there was no configured match. **It does not mean safe.**
- For enforcement at the signing boundary, integrate the [Huntxr withdrawal guard](radar/README.md#protected-sol-withdrawal-signing) in the signing service.

Do not expose the unauthenticated local API directly to the internet.

## Kali-inspired security: first real sensor

Hunter Radar currently supports **read-only Suricata EVE JSON alert ingestion**, not a full suite of Kali tools.

1. On a Genyxis-owned or explicitly authorized Linux host, install and configure Suricata to inspect traffic the operator is entitled to monitor. Check it with `suricata -V`.
2. Configure Suricata EVE `alert` output, and arrange read access for the non-root Radar process. A common path is `/var/log/suricata/eve.json`.
3. Start Radar with the EVE path configured:

```bash
cd Genyxis-Hunter-Protocol/radar
export HUNTER_RADAR_SURICATA_EVE_FILE='/var/log/suricata/eve.json'
npm start
```

4. Open the **Kali Sensors** view. Only alerts appended after the file follower starts are counted. Sensor errors and skipped/rotated log gaps must be treated as reduced coverage.
5. Test the parser with `npm test` or `node --test test/suricata.test.mjs`.

**Real sensor acceptance test:** [draft PR #3](https://github.com/Sons-of-Night/Genyxis-Hunter-Protocol/pull/3) introduces `npm run verify:suricata`, a controlled loopback capture check for Kali/Ubuntu. **That command is not on `main` until the PR is merged.** Running it successfully on the intended host is still pending. Keep the Suricata loopback result separate from Solana mainnet stream validation.

Radar's browser output omits raw packet data and source/destination IPs from parsed Suricata alerts. It must not infer that an intrusion alert identifies a malicious on-chain wallet, or that a reported alert was blocked. Cloudflare ingest, remote sensors, tenancy, authentication and managed retention are **not yet implemented**.

See [radar/README.md](radar/README.md) for detailed sensor setup, limitations and testing instructions.

## Hunter Guard research prototype

Hunter Guard is a **separate** authorization/replay-resistance experiment. Its sample campaign uses synthetic eligibility, an issuer co-signature, bounded slot expiry and a program-derived claim receipt. It demonstrates how an integrating program can constrain a protected action; it is **not a mechanism for censoring public blockchain traffic**.

Run the offline Node lab from the repository root:

```bash
node lab/demo.mjs
node --test lab/hunter.test.mjs
```

For Solana SBF and LiteSVM acceptance testing, use a host with the project's Rust/Solana toolchain installed:

```bash
mkdir -p target/deploy
cargo build-sbf --arch v2 --tools-version v1.52 --manifest-path program/Cargo.toml --sbf-out-dir "$PWD/target/deploy"
cargo test --manifest-path chain-lab/Cargo.toml --test guard -- --nocapture
```

These commands are **validation steps**, not claims that a chain build, deployment or audit has passed. The program ID is for an isolated fixture, not a public mainnet deployment. Keep this lab separate from the preserved Genyxis fresh-v1 validator, ledger, keys, PostgreSQL and operator console.

## Repository structure

```text
.
├── README.md         # Project overview and operator quick start
├── radar/            # Hunter Radar HTTP service, web UI, Kali adapter, tests
├── program/          # Hunter Guard Solana/Anchor experiment
├── lab/              # Offline signing/authorization model
├── chain-lab/        # Isolated Solana/LiteSVM acceptance tests
└── .github/          # Repository automation/configuration
```

## Engineering roadmap

The current [Hunter security-engine roadmap (issue #2)](https://github.com/Sons-of-Night/Genyxis-Hunter-Protocol/issues/2) tracks the work. Priorities:

1. **Prove current behavior:** execute the Suricata loopback acceptance check on authorized Kali/Ubuntu equipment; validate mainnet RPC health, subscriptions and observed events separately.
2. **Make observations trustworthy:** add loss-aware streaming, finalized-state reconciliation, bounded retention, traceable evidence and false-positive testing.
3. **Improve actual threat detection:** decode transactions and simulations; add verified reputation sources, wallet-drainer indicators and defensible, explainable risk scoring.
4. **Expand operator-owned network sensors:** passive Zeek/tshark analysis, static YARA scans, scoped Nmap discovery, and explicit consent/authorization controls.
5. **Provide enforceable response where possible:** integrate wallet/dApp policy gates and customer-controlled ingress/host quarantine, with approval, rollback and audit trails.
6. **Build secure commercial infrastructure:** authenticated Cloudflare telemetry intake, tenant isolation, encryption, access controls, durability, retention and independent security review.

**Scope limit:** Hunters may observe public on-chain activity and protect infrastructure/customers that authorize the integration. They do not exploit, retaliate against, or forcibly disable unrelated wallets, agents, validators, nodes or hosts.

## Security, disclosure and contributions

This repository is **public**. Do not commit credentials, key material, customer identifiers, private security rules, sensitive sensor logs or captured network payloads. Use synthetic fixtures or thoroughly sanitized evidence in issues and pull requests.

For a suspected security flaw, coordinate a private disclosure with the maintainers rather than posting working exploit details or secrets in a public issue. For ordinary bugs, tests or feature work, use a scoped issue/PR with the exact command, expected result, observed result and environmental details (without secrets).

**Genyxis Hunter Protocol — protect what you control; verify what you claim.**
