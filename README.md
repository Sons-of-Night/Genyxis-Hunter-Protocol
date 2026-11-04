# Genyxis Hunter Protocol

**0.1.0 · Development prototype · Synthetic rewards claims**

Hunter checks a protected action before a participating Solana program records it. The first action is a campaign claim. The example records a receipt and uses synthetic data.

## Run the demo on Ubuntu or WSL

Extract the ZIP, open a terminal in `Genyxis-Hunter-Protocol`, and run these commands with Node.js 20 or later. The offline lab uses Node's built-in Ed25519 support and needs no package install.

```bash
node lab/demo.mjs
node --test lab/hunter.test.mjs
```

| Scenario | Expected |
| --- | --- |
| Eligible wallet and authorized issuer | Accept one claim |
| Reused permit or freshly signed second claim | Reject the duplicate |
| Direct call without issuer approval | Reject the claim |
| Permit copied to another wallet or modified | Reject the signature |
| Expired or excessively long permit | Reject the expiry |
| Eligible automated client | Apply the same rules and accept |

The model signs its own fixed-format claim message and keeps receipts in process. Solana instead verifies both signatures on the complete transaction message and persists the receipt in a program-owned account. The model test result applies to the model. The separate chain lab is the acceptance check for the program.

## Protocol v0.1

1. A campaign administrator creates a campaign with a dedicated issuer. Its Solana address is derived from the admin and a 32-byte campaign identifier.
2. The prospective claimant authorizes the claim. The issuer checks its eligibility policy and co-signs the exact transaction. The transaction contains the campaign, claimant, claim instruction, and slot expiry. The issuer builds or fully validates the exact message before signing. Integrators pin the expected program and campaign.
3. Hunter Guard requires both signers and checks the issuer against the campaign account. It accepts an expiry 1 to 150 slots ahead at execution and relies on Solana's normal recent-blockhash checks.
4. Hunter Guard records the claim at the program-derived address for the campaign and claimant. Creating that same account again fails, including with a newly signed transaction. A failing transaction leaves no new receipt.

Each campaign depends on the issuer's eligibility policy. A wallet address alone establishes neither human identity nor malicious intent. The fixture uses a synthetic allowlist. The guard contains a single claim action and does not move tokens or hold custody. The campaign stores a fixed issuer for this milestone. Issuer rotation, policy administration, and an integration-specific access model need design and testing before a customer pilot.

## Run the Solana acceptance check

Use the Rust and Solana SBF tools from your Genyxis development setup. The program uses Anchor 1.2.0, and the SBF command follows Genyxis's Solana 3.1.10 and platform-tools v1.52 build. The isolated chain lab uses LiteSVM and creates ephemeral test wallets in process. It has no RPC endpoint or connection to fresh-v1.

From the extracted folder:

```bash
mkdir -p target/deploy
cargo build-sbf --arch v2 --tools-version v1.52 --manifest-path program/Cargo.toml --sbf-out-dir "$PWD/target/deploy"
cargo test --manifest-path chain-lab/Cargo.toml --test guard -- --nocapture
```

The chain test checks missing and wrong issuer approval, expired and overlong permits, the first successful receipt, and a second transaction with a new approval. It prints the compute units consumed by the successful claim. The program ID in the source is for the in-process fixture. Both Rust commands require their toolchain and dependency access. They are pending execution on a Solana-equipped host.

## Pilot milestones

1. Run the chain test and capture its result and compute units.
2. Add a staging issuer that constructs exactly one approved claim transaction. Keep the signing role separate from campaign administration and use a dedicated key. Exercise key rotation, expiry, signer outages, and policy errors before relying on it.
3. Connect Flytrap for ingress rate limiting and Shadow for observation. Record reason codes and inspect failed-transaction telemetry from the API and RPC. Keep suspicions separate from authorization decisions.
4. Exercise the staging boundary from an isolated lab using synthetic clients. Measure acceptance for eligible wallets, attempts stopped, and added latency before offering one protected rewards flow as a paid staging pilot.
