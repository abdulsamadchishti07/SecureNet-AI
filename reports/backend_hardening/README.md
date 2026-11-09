# Backend hardening evidence — 2026-11-09

The reviewed authentication, persistence and delivery defects have been addressed.
Setup, migration and operational limits are in the [backend guide](../../docs/BACKEND.md).
Machine-readable results and completion source hashes are in
[verification.json](verification.json).

## Changes verified

| Reviewed issue | Result |
| --- | --- |
| Anonymous telemetry/ingestion/WebSockets | User JWT, independent sensor authentication and authenticated WebSocket header/tickets |
| Non-admin unblock and public admin bootstrap | Admin dependency; explicit singleton local bootstrap |
| Default signing secret | Missing/default/weak keys fail startup before database initialization |
| Automatic replacement database | Explicit selected engine; connection/schema errors propagate |
| Untyped ingestion and missing provenance | Strict full event/proposal schemas; model run/hash and original validated payload persisted |
| Duplicate delivery failures | Identical retries return existing records; mismatches return 409; concurrent inserts roll back safely |
| Stale simulated block state | Pending request/expiry states and idempotent sensor acknowledgements |
| One-shot blocking HTTP forwarding | Separate sender, durable FIFO outbox, capped retries and retained dead letters |
| Password-boundary exceptions | New-password policy and safe login rejection |
| Tests initializing configured databases | Private app factories and injected temporary engines |
| Async ingestion and slow WebSockets | DB work in threadpool; bounded per-client sender queues |

## Verification

- **308 pytest cases passed**, zero failures/errors. Existing joblib/NumPy and
  Starlette/httpx deprecation warnings remain visible. JUnit output is ignored at
  `reports/tests/pytest.xml`.
- An actual loopback Uvicorn server used a temporary SQLite database and generated
  test credentials. The real sniffer CLI replayed six synthetic packets and sent
  three PORTSCAN detections to the authenticated API.
- An additional real-model event produced four persisted events total. Two manual
  requests returned 202 pending, then completed through sensor acknowledgements,
  including after simulator restart. Final real/simulated active block counts and
  pending-unblock count were zero. Stored model hashes matched the loaded bundle.
- Actual loopback WebSockets rejected anonymous handshakes with 403, accepted user
  Bearer authentication and single-use browser tickets, delivered live detection
  messages and rejected ticket replay. The missing protocol dependency was added
  to requirements and installed (`websockets` 17.4); four targeted regressions
  passed afterward and `pip check` found no broken requirements.
- A private PostgreSQL 18.6 cluster accepted Unix-socket connections only, with TCP
  disabled. Two concurrent identical inserts created one detection/block and
  returned one existing result. Authenticated routes, duplicate acknowledgements
  and repeatable legacy-schema migration passed. The cluster was stopped/removed.
- Legacy migration preserves rows on SQLite and PostgreSQL. Default backend tests
  require neither a configured database nor a PostgreSQL service.
- SHA-256 confirms 89 historical source-data/artifact/report files plus the unified
  model bundle and split artifact remain unchanged. No retraining.

The independent runtime probes used temporary scripts:
`/tmp/securenet_backend_hardening_smoke.py` and
`/tmp/securenet_backend_postgres_smoke.py`. Their sanitized outcomes are embedded
in the saved verification JSON; no credentials or authentication tokens are saved.

## Boundaries

The configured project database and existing environment file were not migrated
or replaced. Existing installations need the documented backup, explicit migration
and credential setup before restart. Audit old account/admin assignments; migration
preserves them. There was no live capture, real firewall execution, production
deployment, Redis/multi-worker integration, commit or push. Synthetic replay does
not resolve the ML campaign/capture-parity limitations.
