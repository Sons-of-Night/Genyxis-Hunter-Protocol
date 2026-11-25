# Huntxr Intelligence Core — Phase IV

This is a selected-event, single-host evidence archive, not a full-chain history, a SIEM, a proven incident attribution system, or an enforcement engine.

## Provisioning

Use Node 22.13+ and a dedicated service-owned local directory, with database, WAL and SHM files protected from other users. Provision a distinct random 32-byte HMAC secret through the host secret store. Set HUNTER_RADAR_EVIDENCE_PATH to the absolute path of a new database file and HUNTER_RADAR_EVIDENCE_KEY to the 64-character lowercase hexadecimal secret. From radar, run:

    node scripts/initialize-evidence.mjs

The command refuses to overwrite existing state. Save the returned genesis checkpoint separately. Start Radar normally with the same protected configuration and its required operator token. Neither the key nor the database belongs in Git or public deployment assets. Configuring only one of the two environment variables, supplying an invalid key, or opening a missing or corrupted database prevents startup. Leaving both unset preserves local monitoring without durable evidence; the dashboard explicitly warns.

## Evidence model

- Solana confirmed observations matching the configured program denylist are stored with signature, observed slot, outcome and matched public program identifiers. A duplicate signature plus identical match set is suppressed across restarts. This is a policy match, not proof of malicious behavior, finality or canonical chain inclusion.
- Sanitized Suricata alert metadata is recorded per delivered event. A sensor-reported block is not independently verified enforcement. No raw IP, packet payload or arbitrary original event fields are copied; rule names/categories can still contain sensitive operator-defined text.
- Potential Solana coverage gaps and reported sensor rotation/skip gaps are preserved with a reason and timestamp. No synthetic observations are inserted, and no gap is marked recovered. Sensor events are not linked to on-chain identities without evidence.
- The authenticated snapshot exposes counts and archive status, not the raw evidence database. A failed archive latches visibly for the process lifetime; live monitoring may continue, but it is not a complete incident record.

The archive defaults to 100,000 non-genesis records; reaching capacity denies new records and requires controlled operator intervention. No automatic deletion or retention rollover is implemented. SQLite FULL synchronous commits occur on the ingestion thread, so throughput and event-loop latency must be measured on the target host. The Solana deduplication key does not establish finality; sensor restart/rotation can omit or repeat observations. Existing sensor file-opening and partial-line handling require further hardening.

## Integrity and remaining gates

Each row authenticates its sequence, previous MAC and normalized payload using HMAC-SHA-256. Startup verifies the chain; the library can check an independently retained checkpoint using openEvidence or verifyAudit. The integrated service currently opens without an external checkpoint, so valid-prefix rollback is not automatically detected. HMAC is not nonrepudiation or protection from privileged host/key compromise. External checkpoint publication, periodic verification, authenticated evidence export, retention and capacity planning remain required.

Run node --test test/intelligence-core.test.mjs and the full npm test suite. Before production, qualify crash recovery, disk exhaustion, sustained ingest, clock and provider behavior, sensor integrity, independent checkpoints and access-controlled backup/restore. Durable missing-slot reconciliation, evidence-based cross-source incident correlation and response authorization remain separate workstreams.
