# Huntxr integrated release qualification

Scope: integrate telemetry integrity and capacity instrumentation (PR #8), local access control (PR #9), capability authorization (PR #11), and durable authorization state (PR #12). This is an internal release candidate, not a production authorization.

## Required acceptance evidence

| Gate | Required evidence |
| --- | --- |
| Source integration | Review exact candidate commit; no unresolved overlapping changes, missing files or undocumented runtime changes. |
| Reproducible install | Node.js 22.13 or later, exact version recorded; npm ci from radar; dependency and secret review. |
| Automated regression | npm test on exact candidate; retain CI run and results, including UTF-8 boundaries, telemetry load, HTTP roles, HX-ACT, concurrent durable replay and tamper detection. |
| Local operator deployment | Provision operator and optional viewer tokens via protected service configuration; start on loopback; verify 401, viewer 403 on assessment, operator success and dashboard browser behavior. Do not expose HTTP Basic to remote clients. |
| Live sensor and provider | Run npm run verify:suricata on an authorized supported host; verify actual Solana mainnet feed, interruption and recovery, observed message size histogram and resource consumption. |
| Persistent state | Use isolated pilot storage and protected HMAC key. Verify backup/recovery, independently retained checkpoints, disk failure, clock failure and emergency halt behavior. |
| Deployment artifact | Record candidate commit, runtime, dependencies, configuration, install/start/stop procedure and rollback. Do not overwrite an existing deployment without backup and controlled migration. |
| Independent review | Review security boundaries and residual risks before production approval. |

## Scope limits

The active response executor, durable multi-host state, remote identity/session management, authenticated administrative control, independent checkpoint publication and operational evidence pipeline are not delivered by this candidate. HX-ACT verifies a proposed response plan; it does not execute one. The 256 KiB limit protects application parsing, not transport buffering; the synthetic benchmark is not a mainnet throughput guarantee. No automatic deployment, credential generation in source, or modification of Genyxis live infrastructure is authorized by this file.

A successful automated test run is necessary but is not a replacement for the host, live-feed, recovery and integration acceptance evidence. Production approval remains withheld until the applicable requirements are verified and the authorized release decision is recorded.
