# Sprints 3–5 execution plan

Reviewed against the checkout on 2026-11-09 (Asia/Karachi). This is planned work,
not a completion report. It adapts the user-supplied Sprint 3–5 plan to the current
API, sensor lifecycle and evaluation limitations.

Sprint 3 is complete: PostgreSQL setup/migration, the user-selected TSX design
adaptation, dashboard/API integration and browser/CLI verification are implemented.
See [the completed Sprint 3 guide](SPRINT_3.md) for exact outcomes and commands.
Sprints 4 and 5 below remain planned work with unresolved evidence gates.

The checkout is on `main`, with a clean working tree before this planning update.
The backend hardening is now committed, superseding the historical uncommitted
status in the handoff. Its saved evidence records 308 passing tests; this planning
review did not rerun the suite. See [backend evidence](../reports/backend_hardening/README.md).

## Decisions before implementation

- User confirmed PostgreSQL is the main application database for Sprint 3.
  SQLite application databases remain limited to isolated automated test fixtures;
  the sensor's existing SQLite outbox is a delivery queue, not a database fallback.
  No SQLite demo database switch is requested. Never replace the configured database
  or copy a PostgreSQL URL into tracked documentation.
- The implemented dashboard is React/TypeScript/Vite in `frontend/`, adapting the
  user-selected TSX. FastAPI serves its compiled assets; Vite proxies the backend
  during development. The initial native-HTML adaptation was replaced.
- The dashboard must report `dry_run` as simulation. Current actual firewall block
  count is zero. A successful dashboard demo does not establish ML validity.
- Work proceeds by chunk. Completing Sprint 3 does not automatically satisfy the
  data and enforcement gates for Sprints 4 and 5. Do not push. Stage and commit each
  file separately only when requested.

## Sprint 3: local environment and authenticated dashboard

### 3.1: explicit configuration and migration

1. Confirm the selected database, check running backend/sensor processes, and stop
   writers before migration. Back up the selected database and existing environment
   configuration privately; verify the backup is usable.
2. Preserve the selected URL and existing settings. Add a separate cryptographically
   generated sensor token and sensor ID; validate the JWT key independently. The
   pre-migration `backend/.env` lacked sensor settings and was mode 0644; the
   completed setup added them and changed permissions to 0600. Never print credentials.
3. For a same-origin dashboard, no additional CORS origins are needed. Add explicit
   origins only for a separate browser origin that will actually be used.
4. Run the explicit additive migration. Inspect existing account roles; migration
   preserves accounts. `create-admin` is only for an empty user table and must not
   be run unconditionally against an existing installation.
5. Export a sensor-only environment file using the existing non-overwriting
   management command. Keep signing keys and database credentials out of the
   capture process environment.

Acceptance: selected database identity and row preservation verified; settings
validate; authenticated API and sensor access work; anonymous requests fail.
Record sanitized outcomes without storing credentials or backups in Git.

### 3.2: dashboard and the contracts it depends on

Implement the supplied TSX as React/TypeScript components in `frontend/src/`,
with typed API/hooks, styles and a pinned Vite toolchain. Build to `frontend/dist/`
and serve only the compiled shell/assets through `create_app`; Vite proxies the
backend in development. The initial plain HTML/JavaScript adaptation was replaced.
Do not expose the repository, runtime files, configuration or model artifacts.

- Login uses the existing form endpoint. Prefer an in-memory access token, clear
  it on logout/expiry, and require login again when necessary. Browser WebSockets
  obtain a fresh single-use ticket for every connection attempt. Handle reconnects,
  token expiry and ticket rejection without an unbounded retry loop.
- Show role, connection state, event/attack counts, simulated blocks and pending
  unblocks. Display actual firewall blocks separately, using the API's explicit
  response mode. Historical nullable provenance must render as unavailable.
- Provide seven-class distribution, paginated alert filters, flow endpoints and
  model/sensor provenance. Bound the live feed and deduplicate by event ID. Keep
  filters and chronological order consistent across HTTP refreshes and live events.
- At planning time, WebSocket messages contained only event ID, label, source/destination IP,
  confidence, action and mode. They omit timestamps, ports, protocol and provenance.
  The completed implementation extends the message contract with tested fields
  and refreshes authenticated alert queries. Do not fabricate missing metadata.
- Block lifecycle changes currently produce no dashboard WebSocket broadcast.
  Refresh/poll block and stats endpoints while commands or expiry are pending,
  or add explicit lifecycle notifications with tests.
- Admin unblock returns 202/PENDING. Keep `UNBLOCK_REQUESTED` visible until sensor
  acknowledgement; an offline sensor leaves it pending. Operators have no enabled
  mutation controls; backend RBAC remains the authority.
- The whitelist endpoint reports built-in defaults only. Label it accordingly;
  it does not include every sensor's custom `--protect` configuration.
- Account provisioning is admin-only. Match the actual policy: at least 12
  characters and at most 72 UTF-8 bytes. Do not describe this as 12–72 bytes.
- Render event text using safe DOM APIs, with no insertion of untrusted HTML.
  Define security/cache headers, accessible controls, responsive layouts, and clear
  loading, empty, disconnected and error states. Never place a JWT in a URL or
  browser assets; do not persist single-use WebSocket tickets.

### 3.3: integration and a reproducible demo

API/TestClient tests alone do not execute dashboard JavaScript. Add browser-level
coverage for login, role controls, filters, ticket reconnection, duplicate events,
pending/acknowledged unblock states and failed requests. Keep database fixtures
private and independent of the configured installation.

The original offline CLI exited after PCAP EOF and closed its response dispatcher.
Clicking Unblock afterward cannot be acknowledged by that stopped process. Add
an explicit, bounded demo wait after replay (now implemented as `--linger-seconds`)
or another documented long-running
sensor workflow. Test actual polling/acknowledgement while the sensor is alive;
also verify the honest pending state when it is stopped. Do not create a second
simultaneous process using the same sensor identity.

Acceptance: full pytest suite passes; a real browser against a loopback server
receives synthetic PCAP events, shows simulated counts, and completes the 202 →
sensor acknowledgement → UNBLOCKED workflow. Check logout, reconnect and mobile
layout. No real capture or kernel rule changes are required for this demonstration.

## Sprint 4: evidence for extraction and response decisions

### 4.1: provenance and differential replay

Before calling a result parity, obtain matching captures and reference CSVs, their
checksums, capture repairs, label policy and the pinned reference exporter/version.
The current synthetic demo PCAP is a regression fixture, not original-capture proof.

Build `scripts/evaluate_pcap_parity.py` to match bidirectional flows using endpoints
and capture times, with explicit orientation and timeout/termination semantics.
Report ambiguous, matched and unmatched flows in both directions. Compare all 20
features with declared units and per-feature absolute/relative tolerances, including
zero reference values. Preserve evidence for exclusions and ordering differences.

Acceptance: a documented matched-capture comparison with discrepancies quantified.
If matching inputs are unavailable, record the blocked evidence gate; a passing
synthetic comparison cannot replace it.

### 4.2: port ablations and independent evaluation

Use isolated experiment artifacts; preserve the current model, splits and reports.
Compare full features, no source port, and no source/destination ports using paired
training conditions and training-only transforms. Select configuration on training/
validation data and report the frozen test comparison once. These existing test
sets have already been observed, so describe the comparison as exploratory.

An ablation on existing unified partitions measures sensitivity within that split;
it cannot establish campaign independence. Several attack families have only one
endpoint pair shared across partitions. Collect separate lab campaigns/hosts or
explicitly limit the supported evaluation classes; do not silently fall back to
row splitting. Current runtime/schema contracts require 20 features: experimental
19/18-feature models need an isolated path, not an incompatible replacement bundle.

### 4.3: replay clock and policy calibration

Current `DetectionEvent.observed_at` is processing time, not the original packet
time. Reading it in `ResponsePolicy` alone will not recover historical timing.
Carry explicit capture/flow timing from extraction and define flow start/end,
out-of-order events and clock advancement during idle periods. Keep observation
time and replay time distinguishable. Specify whether simulated expiry uses replay
time too; policy evidence windows and block lifetimes need coherent semantics.

Calibrate thresholds/windows on a separate calibration cohort with benign traffic
and independent attacks. Measure false block proposals, missed attack sources,
alert volume and delay including flow finalization. Freeze the policy before the
evaluation replay. WEB_ATTACK stays alert-only while its coverage is unsupported.

Acceptance: provenance, extraction discrepancies, independent class coverage and
false-alarm bounds are recorded, with unsupported claims explicitly excluded.
See [validity review](<ML Engine/VALIDITY_REVIEW.md>).

## Sprint 5: isolated enforcement and demonstration packaging

### 5.1: privilege separation and narrowly scoped rules

Proceed only after Sprint 4 has defensible results for the intended lab scope and
the user explicitly authorizes the lab target and activation. Keep dry-run default.

First define the enforcement point: an INPUT chain protects traffic addressed to
that host. It does not block traffic merely observed at a passive/SPAN sensor or
forwarded through a router. Choose the chain/hook for the actual lab topology.

Use an unprivileged API/inference process and a separate helper with a small,
validated, authenticated command interface. Extend event schemas, sensor commands,
stored lifecycle and statistics for confirmed enforcement before displaying ACTIVE
prevention. Do not bypass the current dry-run-only validation to execute proposals.

Manage only owned rules/chains, preserve other host policy, protect management
endpoints/CIDRs and keep operation IDs idempotent. A rollback mechanism must remain
effective if the worker crashes or is killed; a Python shutdown handler alone is
insufficient. Test lease loss, restart, duplicate commands, rule limits and rollback
in a disposable VM/network namespace before a supervised lab activation.

### 5.2: reproducible launch and FYP demonstration

Write `docs/DEMO_RUNBOOK.md` and launch/stop scripts with explicit configuration,
dependency/environment recording, one API worker, one process per sensor identity,
health checks, logs, graceful shutdown, outbox recovery and cleanup. A dry-run demo
can be packaged before enforcement is eligible and must be clearly labelled.

Distinguish measured within-capture ML scores, synthetic integration checks,
independent lab evidence and any confirmed lab firewall actions. Demonstrate the
supported system and its limitations without claiming production readiness.
