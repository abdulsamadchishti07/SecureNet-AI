# SecureNet AI — Agent Handoff

Last updated: 2026-11-12 (Asia/Karachi).


## Sprint 4 tooling and exploratory evidence — 2026-11-12

- Implemented `scripts/evaluate_pcap_parity.py`: endpoint/time matching, conservative
  ambiguity reporting, orientation flags, 20-feature errors/tolerances, input/code
  hashes and extraction diagnostics. No reference means extraction-only. Three
  independent arithmetic synthetic flows agree; original-capture parity remains open.
- `ml_engine/ablation.py` compares RF and XGBoost across 20/19/18 features using the
  same seeded 50,000 training rows and complete frozen validation/test partitions.
  Source-port removal slightly improves macro F1 on this sample; both-port removal
  lowers it. This is exploratory within-split sensitivity, not campaign independence.
  Only new reports and sampled provenance are saved; serving artifacts are preserved.
- Flows/events carry capture start/end/availability separately from processing time.
  `--clock-mode event_time` requires offline response replay and complete timing;
  uses availability with a nondecreasing watermark and rejects late events.
  Runtime firewall lifetimes stay monotonic and simulated. Both clocks are audited.
- Strict API validation/payload JSON/HTTP/WebSocket preserve optional capture fields
  without database migration; legacy delivery fingerprints remain compatible.
  `python -m sniffer.calibration` reports policy sensitivity, labels its truth basis
  and distinguishes pre-onset proposals from valid post-onset latency/misses.
- Guides: `docs/SPRINT_4.md`, `docs/RESPONSE_CALIBRATION.md`. Evidence:
  `reports/{parity,ablation,sprint4}/` and `reports/response/calibration.json`.
  No original PCAP or independent calibration cohort was supplied; Sprint 5 stays gated.
- Verification: see `reports/sprint4/verification.json` for final regression/CLI/hash
  results. Existing `requirements.txt` edit was preserved. No configured DB writes,
  model replacement, live capture, host firewall action, staging, commit or push.

## Workspace cleanup & naming standardization — 2026-11-11

- Renamed `frontend/src/securenet_ai_threat_detection_response_platform.tsx` to
  idiomatic `frontend/src/App.tsx` and updated `frontend/src/main.tsx` and docs.
- Removed obsolete root `.env` (0-byte leftover), root `securenet.db` (stale empty
  SQLite DB), empty `docs/Network/`, `reports/tests/`, superseded
  `reports/sprint3/initial-vanilla-verification.json`, and 31 temporary probe/demo
  files in `runtime/`. Kept private `runtime/admin-login.txt`, `runtime/sensor.env`,
  `runtime/backups/` and `runtime/response_demo_offline.pcap`.
- Removed obsolete `runtime/sprint3-vanilla-backup/` and generated project Python /
  pytest caches. Kept active React source/build/dependencies, datasets/models,
  database state, credentials and reports.
- No files staged, committed or pushed.

## Current frontend: React/TypeScript correction — 2026-11-09

- User clarified the TSX must be implemented in React. The initial native-HTML /
  imperative-JS adaptation was the wrong stack and is superseded by actual React,
  TypeScript, Vite and Lucide components. The working TSX is under frontend/src/.
- Actual component: `frontend/src/App.tsx` (renamed from
  `securenet_ai_threat_detection_response_platform.tsx`).
  ReactDOM createRoot is in `src/main.tsx`; typed API/session/polling/WebSocket
  hooks are in `src/{api,usePlatform,types}.ts`. UI uses declarative JSX, not the
  old DOM controller. The obsolete native dashboard backup was removed during cleanup.
- Exact packages/lockfile: React/ReactDOM 19.3.1, TypeScript 7.0.2, Vite 8.3.7,
  plugin-react 6.3.0, lucide-react 1.70.0 and Prettier 3.9.10. Clean offline npm ci,
  strict typecheck/build/format passed; npm audit reported zero known advisories.
- `npm --prefix frontend run dev`: 5173 proxies HTTP `/api` and `/ws/alerts` to
  backend 8010. Development login/stream proxy verified. Production build writes
  ignored dist/; FastAPI serves only dist/index.html and dist/static. Missing build
  returns 503 at `/` without disabling API. Never serve frontend source directly.
- `create_app` accepts injected frontend_dir. Python static/security fixtures use
  tiny private builds and need no npm; browser tests require actual Vite output.
  Current verification: 327 default tests passed (5208 known warnings, 63.34s),
  nine React browser workflows passed (36.17s). Guide: frontend/README.md.
- Configured PostgreSQL + saved-model offline CLI + Chromium verified a real React
  root, three new predictions/events, provenance and exact-block acknowledgement.
  No browser exceptions, external requests or browser-stored credentials. Final
  actual/simulated blocks and pending unblocks are zero; sensor stopped cleanly.
- Main DB retains 12 synthetic PORTSCAN events: nine earlier native-probe records
  plus three React-verification records. No credential/config reset or retraining.
- React dev (5173) and compiled dashboard/API (8010) left running. Uvicorn now uses
  both --no-access-log and --log-level warning: accepted WebSocket URLs are still
  logged at INFO with only no-access-log. Keep tickets/passwords out of logs.
- Current guide/evidence: docs/SPRINT_3.md and reports/sprint3/. Initial native
  checkpoint is preserved separately. No staging, commits or pushes. PostgreSQL
  remains main DB; independent-data/capture-parity/enforcement gates are unchanged.

## Initial Sprint 3 implementation — frontend superseded above

- User selected `securenet_ai_threat_detection_response_platform.tsx` as the design,
  resolving confirmation. Reference preserved; `DESIGN.md` records the selection.
- Implemented `frontend/{index.html,styles.css,app.js,mark.svg}` and local licensed
  fonts. Reference slate/emerald sidebar, five metric cards, chart panels and
  crimson feed are served by FastAPI without a Node build. Main DB is PostgreSQL.
- In-memory JWT clears on logout/expiry; reload requires login. Stream uses a new
  single-use ticket for every reconnect with bounded backoff/retries. Filters,
  25-row pagination, eight-event feed, provenance dialog, JSON export, admin account
  provisioning and operator monitoring are functional. No mock traffic is used.
- Authenticated `/api/analytics` accepts 15..10080 minutes: SQL groups 20 UTC
  observation-time bins, protocol counts and five non-benign source counts. Native
  timestamp comparisons work on PostgreSQL and SQLite. No packet-rate, email/SMS,
  payload/SHAP, eBPF, alternate-model or fabricated resource metrics are claimed.
- UI distinguishes simulated/actual blocks, sends exact block UUID on unblock and
  polls lifecycle/stats every five seconds. Offline sensor leaves pending requests.
  Protected ranges are labelled built-in defaults. Kernel actions remain absent.
- Default suite: 326 passed, 5208 known warnings (66.54 seconds). Browser suite:
  nine passed (33.98 seconds) after final mobile/error-state refinements. A combined
  19-case dashboard API/browser run passed. Browser fixtures use private temporary
  SQLite/loopback servers; configured PostgreSQL is not used by these tests.
- Configured PostgreSQL + actual saved model/offline CLI + Chromium verified three
  new predictions/events, live metadata/hash and the exact new simulated block UUID
  through 202 request and sensor acknowledgement. No browser exceptions, external
  asset requests or browser-stored credentials; sensor shutdown was clean.
- Three probe attempts left nine synthetic PORTSCAN events and response history in
  the application DB. Earlier assertions were corrected for polling delay and old
  same-IP rows; records were preserved. Final actual/simulated blocks and pending
  unblocks are zero. No model retraining, real capture or firewall execution.
- Screenshots/evidence: `reports/sprint3/`; guide: `docs/SPRINT_3.md`. Dashboard/API
  left on loopback 8010 with access logs off to avoid recording tickets. Port 8000's
  unrelated service was preserved. Initial login remains in private
  `runtime/admin-login.txt`; sensor env is `runtime/sensor.env`. Never print secrets.
- SHA-256 verified 89 historical files plus unified bundle/splits unchanged. All
  eight views passed overflow checks at 360/390/768/1024/1440/1920px, and actual
  metadata JSON export passed. No staging, commits or pushes.
  Sprints 4/5 remain future work with independent-data, capture-parity and lab gates.

## Earlier Sprint 3 checkpoint — superseded by completion above

- User explicitly said to start Sprint 3 and confirmed PostgreSQL as the main DB.
  Completed local configuration/migration; dashboard implementation is pending
  confirmation of `DESIGN.md` required by the applied web-design skill. The async
  question offers dark-slate/teal L1 design or a light theme. Do not silently treat
  elapsed time as that design approval. Guide: `docs/SPRINT_3.md`.
- Configured `SecureNet_AI` had three empty tables/no users. Created a private
  pg_dump/environment backup under `runtime/backups/`, restored it in a disposable
  Unix-socket-only PostgreSQL cluster and removed that cluster. Added sensor
  credentials, preserved DATABASE_URL/JWT key, migrated and verified original rows.
  `backend/.env` and `runtime/sensor.env` are 0600. Initial admin login is in private
  `runtime/admin-login.txt`; never print its password or commit runtime files.
  Sanitized setup/restore/API outcomes are `runtime/sprint3-*.json`.
- API verified on loopback 8010; 8000 is occupied by another service. Keep that
  unrelated service intact. Browser shell assets do not exist at this checkpoint;
  conditional static serving/security headers are ready, not a completed UI.
- WebSocket detection messages now include full HTTP alert fields/provenance with
  `type: detection`, preserving action/mode. Unblock optionally accepts `block_id`
  and returns it, targeting the chosen record even if another exists for that IP.
- `--linger-seconds 0..3600` keeps the original offline response dispatcher alive
  after EOF, checks worker/sender health and supports Ctrl+C. Requires pcap/respond;
  default behavior is unchanged. Policy still uses processing time, not capture time.
- All 316 default tests pass; existing warnings remain. Browser tests and private
  fixtures are prepared under opt-in `browser_tests/`, not yet run against UI.
  `requirements-browser.txt` adds Playwright; current install is 1.64.1, Chromium
  156.0.8078.79 launched successfully, and pip check passes. No model retraining,
  real capture/firewall operation, commit or push.

## Sprint 3–5 planning review — 2026-11-09

- User supplied the detailed Sprint 3–5 plan. Reviewed it against current code;
  the corrected, repository-local plan is `docs/SPRINT_3_TO_5_PLAN.md`.
- User confirmed PostgreSQL is the main application database for Sprint 3;
  SQLite is for isolated automated tests, with no application database switch.
  Proposed dashboard default is a FastAPI-served same-origin application. No
  configuration changes, database migration or dashboard implementation occurred
  during this review. Existing `.env` lacks sensor settings and is mode 0644;
  harden permissions as part of the configuration chunk without printing secrets.
- Current WebSocket detection messages lack full flow/provenance fields; block
  acknowledgements do not broadcast lifecycle updates. Dashboard must refresh
  authenticated queries or gain tested notification contracts. Offline replay
  closes the sensor at EOF; a later UI unblock needs a documented running sensor.
- `observed_at` currently means processing time. Replay calibration requires
  capture timing to be carried explicitly. Old-split port ablations cannot establish
  campaign independence; matching source captures and independent lab data remain
  evidence gates. Real enforcement also requires schema/statistics integration and
  a lab topology where the chosen firewall hook can actually affect traffic.
- Checkout was clean on `main`; backend hardening is now committed, superseding
  the historical uncommitted status below. Saved evidence records 308 passing tests;
  tests were not rerun for this documentation-only review. No commit or push here.

## Current backend hardening — completed 2026-11-09

- User asked for a backend/auth/database review, then explicitly authorized fixing
  the pasted findings. The review itself was read-only. The implementation below
  fixes all seven MUST FIX, four SHOULD FIX and two additional review findings.
  It supersedes the original Sprint 2 security/completion claims below.
- `backend/main.py::create_app` owns its settings, engine/session factory, tickets
  and WebSocket manager. No database connects on import. Monitoring requires an
  active user JWT; admin creation/unblock require `require_admin`. Sensor ingestion/
  lifecycle/command routes use separate `X-Sensor-Token` and `X-Sensor-ID` headers.
- `backend/config.py` requires explicit DATABASE_URL, independent 32+ byte JWT and
  sensor secrets, HS256 and explicit CORS origins. Default/insecure/missing keys
  stop startup. DB connection/schema errors never switch to another database.
- `backend/manage.py`: private, non-overwriting `init-config`, sensor-only credential
  export, repeatable additive `migrate`, and interactive `create-admin`. Singleton
  bootstrap is local-only and requires an empty user table. New passwords require
  12+ characters / <=72 UTF-8 bytes; login safely handles invalid/overlong values
  and permits existing short nonempty passwords. Old JWT claims are rejected.
- `backend/schemas.py` validates full 20-feature events, endpoint metadata, model
  run/hash, probabilities, timestamps and consistent dry-run proposals. Invalid
  data returns 422. `backend/service.py` persists provenance/payload fingerprints,
  makes identical delivery idempotent and conflicts 409, including concurrent DB
  uniqueness races. Both detections and lifecycle acknowledgements are idempotent.
- `backend/models.py` adds nullable legacy-compatible provenance fields and new
  bootstrap, firewall-event and command tables. Timestamp mapping preserves UTC
  awareness across SQLite round trips. `init_db` refuses legacy schemas; explicit
  migration preserves old rows and creates missing indexes/tables.
- Every simulated block has a UUID. Manual unblock returns 202/PENDING and stores
  the requesting admin; sensor acknowledgement completes UNBLOCKED. An overdue
  record is EXPIRY_PENDING until the sensor confirms EXPIRED. Old commands cannot
  remove a new block for the same IP. Actual firewall execution remains absent.
- `backend/outbox.py` transactionally retains API messages outside the policy
  consumer, binds them to one API/sensor, and locks one process per outbox. Defaults:
  100,000 messages, eight attempts with capped backoff; permanent/exhausted failures
  remain dead letters. FIFO ordering, credentials-free storage, restart recovery,
  endpoint-specific acknowledgement validation and manual retry CLI are tested.
- `backend/worker.py` sends asynchronously, forwards expiry and polls/acknowledges
  unblock commands. Sensor credential comes from the agent environment; use the
  documented sensor-only export. `--api-url` requires response mode and credentials;
  `--sensor-id`/`--outbox` configure identity/stable storage. Pending/dead-letter
  counts are distinct from local processing; shutdown keeps undelivered records.
- WebSocket Authorization headers or 30-second single-use browser tickets are
  required. Tokens in query parameters are not accepted. Bounded per-client queues,
  send deadlines and connection/token expiry isolate slow clients. State is local:
  one API worker and one sensor process per configured identity until a shared
  broker/identity registry is added. Ticket URLs should not be logged.
- All 308 pytest cases pass with private app/DB fixtures; warnings remain visible.
  Real loopback API + offline PCAP CLI verified three predictions, four persisted
  events overall and two acknowledged unblocks, with no real firewall actions.
  A private Unix-socket-only PostgreSQL 18.6 cluster verified concurrent idempotency,
  auth/control and repeated legacy migration, then was stopped and removed.
- Final network WebSocket checks exposed a missing Uvicorn protocol dependency;
  `websockets` is now declared/installed (17.4 in this environment). Actual loopback
  Bearer/ticket handshakes and event delivery passed, anonymous/reused tickets were
  rejected, four targeted regressions passed afterward and `pip check` passed.
- SHA-256 verified 89 historical files plus unified bundle/splits unchanged. No
  model retraining, live capture or production deployment. The configured database
  and existing `.env` were not changed; follow `docs/BACKEND.md` before restarting
  an existing installation. Audit historical admin assignments. Legacy block rows
  lack sensor ownership; do not infer safe control targets for them.
- Documentation: `docs/BACKEND.md`; evidence:
  `reports/backend_hardening/{README.md,verification.json}`. Regressions are in
  `tests/test_backend.py`, `tests/test_delivery.py` and the simulator suite.
- No files were staged/committed/pushed for this fix. If requested later, stage and
  commit files separately. Remaining work: independent lab/capture parity, policy
  calibration, real response isolation, login rate limits, shared broker and UI.

## Current backend & API persistence — completed Sprint 2, 2026-11-09

- Implemented Sprint 2 deliverables: persistent database schema, secure authentication,
  REST endpoints, WebSocket live broadcast, and sniffer API forwarding.
- `backend/models.py`: SQLAlchemy models for `User` (RBAC/admin flag), `Alert` (flow,
  model metadata, probabilities, features JSON, policy decision, timestamp), and
  `BlockedIP` (IP, threat label, dry-run/active status, unblock timestamps, iptables rule).
- `backend/config.py`: Environment loader parsing `backend/.env` (and root fallback) for
  database URL, JWT secrets, Redis connection, and SMTP email parameters.
- `backend/database.py`: SQLAlchemy engine and session factory with automatic local
  SQLite fallback (`securenet.db`) if external PostgreSQL service is offline, ensuring
  zero local startup failure during testing and offline development.
- `backend/auth.py`: Bcrypt password hashing and verification, signed JWT token generation
  and decoding, plus `get_current_user` OAuth2 dependency.
- `backend/service.py`: `AlertService` with detection persistence (`record_detection`),
  alert filtering (`list_alerts`), aggregate dashboard metrics (`get_summary_stats`),
  and manual unblock management (`unblock_ip`).
- `backend/main.py`: FastAPI application providing:
  - Auth routes: `/api/auth/register`, `/api/auth/login`, `/api/auth/me`.
  - Alert routes: `/api/alerts` (filtering & pagination), `/api/stats`, `/api/alerts/ingest`.
  - Firewall routes: `/api/firewall/blocked`, `/api/firewall/unblock/{ip}`, `/api/firewall/whitelist`.
  - WebSocket endpoint: `/ws/alerts` for real-time alert broadcasts to connected dashboard clients.
- `backend/worker.py` & `sniffer/main.py`: Added `--api-url` support to forward detection
  events directly to `/api/alerts/ingest` with network failure isolation and statistics tracking.
- `tests/test_backend.py`: 8 comprehensive unit and integration tests covering password hashing,
  JWT auth, database models, REST endpoints, firewall management, and dispatcher API forwarding.
- Total test suite expanded to 251 passing tests (243 regression + 8 backend tests).
- All files staged and committed separately per user instructions.

## Current response integration — completed first chunk, 2026-11-08

- User supplied the response-engine sprint plan and said to start after the
  readiness review. Implemented the agreed first chunk: structured detection
  events, a bounded local queue, JSONL auditing and dry-run firewall decisions.
  Real firewall execution, Redis, APIs, database and dashboard remain later work.
- `--respond` requires `--predict` and always simulates. Default inference remains
  unified; the existing detection-only stdout format is preserved. Audit defaults
  to `runtime/alerts.jsonl`; queue/response summary is on stderr. `runtime/` is ignored.
- `sniffer/events.py` validates/freeze-copies IPs, the 20 features, prediction
  probabilities and model identity. Predictor caches the SHA-256 of exactly the
  deserialized bytes so events identify the model even after a disk file changes.
  This is provenance, not authentication; pickle still requires trusted files.
- Queue capacity 1,024; overflow rejects the incoming event and is counted/warned.
  Worker failure raises, and normal shutdown drains accepted events, including a
  tested final-publish/timeout race. Logs append and flush per record; no fsync/
  transactional durability or crash replay. New log files use permissions 0600.
- Policy defaults: score >=0.90, three distinct event IDs for one source/model/
  class within 60 seconds of consumer processing time. WEB_ATTACK and historical
  attack-label scopes remain alert-only. BENIGN is ignored but recorded. Evidence
  and duplicate caches are bounded; thresholds are experimental, not calibrated.
- `backend/firewall.py` simulates validated IPv4 INPUT rule proposals, protected
  CIDRs, duplicate suppression and 900-second monotonic expiry. It never executes
  commands. Configure gateway/DNS/admin/sensor addresses with repeated `--protect`;
  there is no automatic discovery or blanket private-subnet exemption. Virtual
  blocks and policy state exist only in that process and expire only while it runs.
- Added `scripts/create_response_demo.py` to write six synthetic packets with
  explicit Ethernet addresses and no packet transmission. Real saved-model replay
  produced three PORTSCAN predictions (score 0.9966566), two alerts then one
  `would_block`; three events accepted/processed, zero dropped/pending/unlogged.
- All 243 parametrized cases pass, including 12 sniffer cases; dependency warnings
  remain. SHA-256 verified 89 historical files plus unified bundle/splits unchanged.
  No model retraining, live capture or host firewall changes were performed.
- Guide and revised sprint sequence: `docs/RESPONSE_ENGINE.md`. Evidence:
  `reports/response/{README.md,verification.json,demo_events.json}`. Local replay
  output: `runtime/response_verified_{alerts.jsonl,predictions.jsonl,summary.log}`.
- Next chunk: persistent alerts/actions and an authenticated backend/event broker;
  isolated lab/replay and policy validation precede any privileged response service.
  Do not call this live-validated prevention or promise one-second attack-onset
  blocking: flow finalization can wait for the five-second grace/120-second timeout.
- Current response changes are not committed or pushed. If asked, stage and commit
  each file separately. Earlier commit-status notes below are historical.

## Current unified implementation — completed 2026-11-08

- User supplied a unified-detector implementation plan and confirmed seven broad
  classes, the existing 20 features, and supported Attempted flows mapped to BENIGN.
  Rare excluded families still take precedence over the Attempted mapping.
- Unified classes: BENIGN, BOTNET, BRUTE_FORCE, DDOS, DOS, PORTSCAN, WEB_ATTACK.
  Historical weekday label policies/artifacts remain unchanged.
- Added `ml_engine.unify` with chunked original-CSV ingestion, source checksums and
  row provenance, global duplicate/conflict removal and globally recomputed
  bidirectional connection groups. `normalize_rows`, `deduplicate_flows` and
  `connection_keys` are shared helpers in preprocessing.
- Corrected the supplied sampling order: reserve global 60/20/20 partitions first,
  then cap training BENIGN at 150,000 across source days. Validation/test retain
  cleaned source prevalence; discarded training row IDs are recorded.
- Registered `unified_v1`; shared RF/XGBoost training/evaluation support seven
  classes, with two training workers. Evaluation adds per-source false alarms and
  original-label target counts. Inference and sniffer now default to `unified`;
  explicit weekday overrides remain, and missing unified artifacts do not fall back.
- Sniffer catches input-specific `FeatureValidationError` only, preserving model/
  artifact errors. Monday's default historical four-model comparison is preserved;
  explicit unified exposure loading supports multi-source checksums/hashes.
- Shared pytest fixtures include the seven-class policy; component unification
  tests cover chunk/day conflicts, source-row parity, global groups, training-only
  caps and real small-model end-to-end behavior. All 169 parametrized cases pass,
  including seven sniffer cases. Joblib/NumPy deprecation warnings remain visible.
- Full preparation read 2,099,971 source rows and retained 2,081,457 after removing
  110 excluded rows, 18,400 same-target duplicates and four conflicting rows.
  There are 1,083,995 global connection groups; no invalid/header rows were found.
- Final train/validation/test: 451,304 / 416,291 / 416,290 rows. Training BENIGN is
  exactly 150,000 (30,000 per source); 797,572 training-only benign rows were dropped.
- Random Forest won validation macro F1 (99.8866% versus XGBoost 99.5254%). Selected
  test accuracy is 99.9649283%, macro F1 99.8192265%, benign FPR 0.0275440%
  (87/315,858). Of 146 errors, 17 attacks were missed and 42 had wrong attack families.
- WEB_ATTACK has only 91 cleaned rows and 19 test examples (17 brute-force, two XSS).
  All 19 correct predictions share one endpoint pair across partitions; this does
  not establish robust web detection. All attack classes have shared endpoint pairs.
- Full source-row/label/connection parity, split disjointness, training-only scaler
  statistics and default single/batch/direct predictions were verified. A synthetic
  offline PCAP produced the same default seven-class prediction as the public API;
  it is not original-capture parity. No actual network capture was performed.
- SHA-256 confirms 89 prior dataset/model/report files unchanged. The preservation
  baseline is saved in `reports/unified/preserved_previous_runs.json`.
- Measured preparation/training: 665.33 / 142.12 seconds; peak RSS 2.398 / 0.830 GiB.
  Host swap was already in use. Details: `reports/unified/resources.json`.
- Outputs are `dataset/processed/{cleaned_unified.csv,unified_splits.pkl}`,
  `ml_engine/models/unified_v1/` and `reports/unified/`. Guide:
  `docs/ML Engine/UNIFIED.md`; results: `reports/unified/README.md`. Existing output
  guards require archiving before reruns. No current-task files have been committed
  or pushed; when requested, stage and commit each file separately.
- This is an experimental within-capture candidate, not a production-validity
  milestone. Provenance, independent campaigns, source-port ablation, non-Attempted
  web support and PCAP parity remain unresolved. No firewall or backend work.

## Priority correction — validity review

Read `docs/ML Engine/VALIDITY_REVIEW.md` before interpreting the completed-run
sections below. The runs are completed experiments, not validated live detectors.
Five-tuple grouping prevents connection overlap but does not isolate attack
campaigns: Tuesday FTP/SSH, all four Wednesday DoS families and Thursday's two
web families each have just one endpoint pair shared across train/validation/test.
Changing the group key alone cannot provide both pair independence and full class
coverage. Source-port ablations have not been run; score causation is not proved.

The hypothetical four-model OR on the existing Monday common cohort flags
3,357 / 189,279 flows (1.7736%). It is not deployed. The November 8 unified candidate
now supplies default inference; the historical weekday models remain explicit.
Historical unconditional Attempted-to-attack merging needs review against the exact release
and intended detector target. The 2022 reprocessing authors recommend a BENIGN
mapping when uncertain; local provenance is consistent with that family but is
not checksum-verified. Do not tune Thursday subtypes before resolving these gates.

Sniffer parity is unvalidated. Earlier claims below that its generating extractor
was identified and semantics were verified are too strong: formula checks and
synthetic packets did not reproduce original captures. No PCAPs were found in
the workspace or `aaa.zip`; no differential replay has been performed. Obtain
matching captures, repairs and a pinned exporter before claiming parity.

Revised order: provenance/target definitions and independent-campaign feasibility;
differential PCAP replay; defensible evaluation and port ablations; unified serving
candidate with supported coverage. Per-flow error isolation, vectorized decoding,
trusted artifact loading and legacy quarantine can proceed independently. Current
runtime rejects invalid inputs; the sniffer now isolates input-validation failures.
Pickle loading still requires trusted artifacts. No fixes, retraining, relabelling
or migration were performed during the original review; subsequent changes are
recorded above. Evidence: `reports/validity_review/findings.json`.

## User intent and current authorization

The user is building SecureNet AI, a final-year network intrusion detection and
response project. The current work is offline weekday ML training before
integrating live traffic. Corrected Friday, Thursday, Wednesday and Tuesday baselines are done.
Monday normal-reference preparation and saved-model false-alarm evaluation are also done.
The user subsequently authorized and clarified the unified seven-class experiment;
it is complete as recorded above. Live validation and response remain future work.
The user then authorized starting response integration. Its local dry-run first
chunk is complete above; active prevention and external-service work remain future.

The user first requested analysis and a plan, then authorized fixing Friday's data
leakage and running the corrected pipeline. That run is complete. The user then
explicitly chose Thursday next; its separate training/evaluation run is also
complete. The user then explicitly selected Wednesday; its separate run is now
complete too. The user then selected Tuesday; that separate run is now complete.
During Tuesday documentation completion, the user selected Monday next. Its
BENIGN-only data was prepared and used for false-alarm evaluation, not training.
Do not overwrite unrelated user changes or implicitly start other
weekday runs. See the latest sniffer entry for the independent capture work.

The original analysis was read-only. The implementation now changes the ML
pipeline, adds focused tests/reports, and keeps legacy artifacts in their original
locations. See the latest change-log entry and reports for completion status.

## Current test suite — updated 2026-11-09

- The user explicitly requested removing weekday-specific test files and using
  pytest fixtures/parametrization. Tests now follow software responsibilities.
- Run `.venv/bin/python -m pip install -r requirements-dev.txt`, then
  `.venv/bin/python -m pytest -q`. Configuration is `pytest.ini`; detailed test
  responsibilities and coverage limits are in `tests/README.md`.
- `tests/conftest.py` owns independent expected label-policy cases, one synthetic
  flow factory, per-test temporary project paths, fresh caches and small real RF/
  XGBoost fits. Shared assertions run across all five configured classifier scopes.
- There are 308 passing parametrized cases, including 12 sniffer cases. Original
  23-test counts elsewhere in this handoff are historical. Tests do not require
  local CSV/model artifacts, root capture privileges or external services.
- Combined test report: `--junitxml=reports/tests/pytest.xml` (ignored by Git).
  `reports/README.md` indexes completed experiment evidence kept in its original
  locations to preserve saved paths/checksums. Historical test names in run records
  describe the pre-consolidation suite.
- The original consolidation changed tests/configuration/docs only. The subsequent
  unified implementation also changes runtime code and the new target policy.
  Independent campaigns, capture parity, port ablations and artifact trust remain open.

## Project context

- Read `Claude.md` for the original project description if more context is needed.
- Intended pipeline: packet capture → bidirectional flow features → ML inference
  → backend decisions → storage, alerts, firewall response → dashboard.
- Python ML prototype exists. Backend, frontend, and deployment remain planned.
- Unified classes/default: BENIGN, BOTNET, BRUTE_FORCE, DDOS, DOS, PORTSCAN, WEB_ATTACK.
- Friday classes: BENIGN, BOTNET, DDOS, PORTSCAN.
- Thursday classes: BENIGN, PORTSCAN, WEB_BRUTE_FORCE, WEB_XSS.
- Wednesday classes: BENIGN, DOS_GOLDENEYE, DOS_HULK, DOS_SLOWHTTPTEST, DOS_SLOWLORIS.
- Tuesday classes: BENIGN, FTP_BRUTE_FORCE, SSH_BRUTE_FORCE.
- Monday: BENIGN-only reference, no supervised classifier or model registry entry.
- Current feature schema: `ml_engine/preprocess.py::SELECTED_COLUMNS` (20 features).
- Dataset source/provenance should be documented accurately: `Claude.md` describes
  CICIDS2017, while the legacy `docs/ML Engine/Friday.md` plan names UNSW Canberra.
  That file was previously called `Friday.docx`. Do not assume
  the exact downloaded variant or feature definitions without checking.

## Repository map and actual state

| Path | State / purpose |
| --- | --- |
| `ml_engine/datasets.py` | Unified and preserved weekday policies, paths and inference default |
| `ml_engine/unify.py` | Five-source normalization, global dedup/groups, splits and training-only benign cap |
| `ml_engine/monday.py` | Normal-only reference and overlap-controlled saved-model false alarms |
| `ml_engine/preprocess.py` | Weekday cleaning/deduplication and grouped 60/20/20 raw-valued splits |
| `ml_engine/train.py` | Training-only scaling, class weights, RF/XGBoost, validation model selection |
| `ml_engine/evaluate.py` | Selected model's held-out test metrics and confusion matrix |
| `ml_engine/predictor.py` | Atomic bundle loading; selected model; validated single/batch inputs |
| `ml_engine/__init__.py` | Lazily imports public entry points |
| `sniffer/capture.py` | `start_capture()`: pcap/pcapng reader or live Scapy AsyncSniffer |
| `sniffer/extractor.py` | Flow table emitting 20 features + IPs; CICFlowMeter parity unvalidated |
| `sniffer/events.py` | Validated immutable model/source-tagged detection events |
| `sniffer/publisher.py` | Bounded in-process event queue with overflow accounting |
| `sniffer/rules.py` | Bounded repeated-flow dry-run policy with alert-only coverage gates |
| `sniffer/main.py` | CLI capture/prediction and opt-in `--respond` dry-run audit |
| `backend/firewall.py` | Firewall simulation, protection, idempotency and expiry; no executor |
| `backend/worker.py` | Local consumer, JSONL audit, shutdown drain and failure propagation |
| `backend/main.py` | App factory, authenticated monitoring/admin/sensor routes and WebSocket access |
| `backend/auth.py` | JWT/password validation and user/admin/sensor dependencies |
| `backend/database.py` | Explicit engine initialization/session injection, no fallback |
| `backend/models.py` | User/event/block/command schema and UTC timestamp mapping |
| `backend/service.py` | Idempotent persistence, lifecycle transitions and acknowledged commands |
| `backend/schemas.py` | Strict ingestion/proposal/action contracts |
| `backend/outbox.py` | Durable FIFO HTTP delivery, retries/dead letters and recovery CLI |
| `backend/realtime.py` | Single-use browser tickets and bounded subscriber queues |
| `backend/manage.py` | Explicit migration, private configuration and local admin bootstrap |
| `scripts/create_response_demo.py` | Offline synthetic fixture generator; sends no packets |
| `dataset/raw/` | Local CSVs for all five weekdays, including `_plus` variants |
| `dataset/processed/` | Unified and separate weekday cleaned CSVs/raw-valued split pickles |
| `ml_engine/models/` | `unified_v1/` default candidate plus preserved historical weekday/legacy artifacts |
| `requirements.txt` | Unpinned ML dependencies plus Scapy |
| `README.md` | Setup/run commands, split strategy, artifact paths and limitations |
| `docs/ML Engine/Friday.md` | Legacy Friday plan; source variant/provenance still needs documentation |
| `docs/ML Engine/WEDNESDAY.md` | Wednesday methodology, results, limits and usage |
| `docs/ML Engine/TUESDAY.md` | Tuesday methodology, results, limits and usage |
| `docs/ML Engine/MONDAY.md` | Monday normal-reference method, limits, results and usage |
| `docs/ML Engine/UNIFIED.md` | Current unified target policy, methods, commands and limitations |
| `tests/conftest.py` | Shared policy cases, flow factory, isolated paths/caches and small real estimators |
| `tests/test_preprocessing.py` | Label/cleaning, raw-value and deterministic connection split contracts |
| `tests/test_training.py` | Training-only transforms, validation selection and saved-run guards |
| `tests/test_inference.py` | Inputs, feature order, single/batch/direct agreement and bundle identity |
| `tests/test_evaluation.py` | Report coverage and changed/mismatched artifact rejection |
| `tests/test_unification.py` | Global source contracts, training-only caps and end-to-end unified behavior |
| `tests/test_response.py` | Events, transport, policy, audit failures and shutdown/expiry contracts |
| `tests/test_firewall.py` | Simulated firewall contracts with real subprocess execution forbidden |
| `tests/test_reference.py` | Normal-only no-fitting, overlap filtering and fingerprint contracts |
| `tests/test_sniffer.py` | Synthetic packet/flow regressions; not source-capture parity proof |
| `reports/friday/` | Baseline checksums, data audit, training/evaluation results, verification, PNG |
| `reports/thursday/` | Thursday audit/results/verification and Friday preservation checksums |
| `reports/wednesday/` | Wednesday audit/results/verification and previous-file preservation checksums |
| `reports/tuesday/` | Tuesday audit/results/verification and previous-file preservation checksums |
| `reports/monday/` | Normal-reference audit, false-alarm evaluation and preservation checks |

The backend includes authenticated APIs, database persistence and durable HTTP
sensor delivery. Actual firewall execution, notifications, dashboard, shared Redis
delivery and Docker deployment do not exist yet.

## Current Monday reference — completed 2026-11-07

- User selected Monday after Tuesday. Actual `monday.csv` is 371,621 BENIGN rows,
  no attacks. No standalone Monday model/scaler/encoder was fitted or selected.
  Monday is not in the supervised registry; do not add a one-class fake baseline.
- Added `ml_engine.monday` and a backward-compatible explicit-config option to
  shared `clean_data`. No default weekday behavior, previous model settings or
  sniffer behavior changed. `monday_plus.csv` was not used.
- Removed 2,024 duplicate feature vectors; no invalid/contradictory/header rows or
  label exclusions. Clean normal reference: 369,597 flows / 249,108 connection
  groups. No Monday train/validation/test split; all values remain raw.
- Saved all four weekday classifiers were evaluated as-is. Full Monday results
  can overlap earlier runs. A common strict cohort excludes any feature-vector
  OR canonical connection-key match in any earlier train/validation/test partition
  of ANY compared model. Day-local group IDs were not compared across files.
- Feature fingerprints normalize numeric types/signed zero; keys use bidirectional
  IP/ports/protocol. Keys omit dates, so reuse across days may over-exclude actual
  independent connections. The filtered population is not random/host-independent.
- Excluded overlap union 180,318 rows (feature overlap 1,582; connection overlap
  179,945; categories intersect). Common cohort: 189,279 identical rows per model.
- Full-reference false positives / 369,597: Friday 57 (0.0154%), Thursday 3,208
  (0.8680%), Wednesday 148 (0.0400%), Tuesday 0 (0.0000%).
- Common-cohort false positives / 189,279: Friday 57 (0.0301%), Thursday 3,154
  (1.6663%), Wednesday 147 (0.0777%), Tuesday 0 (0.0000%). Thursday's common
  errors: 103 PORTSCAN, 2,059 WEB_BRUTE_FORCE, 992 WEB_XSS. Its web weakness persists.
- Monday cannot assess attack recall/precision/F1 or choose an overall best model.
  Different scopes and filtered denominators matter; zero observed false positives
  is not a live guarantee. All metrics assume source BENIGN annotations are correct.
- Data artifacts: `cleaned_monday.csv`, `monday_reference.pkl`,
  `monday_common_cohort.pkl` in `dataset/processed/`. Last file stores eligible raw
  row IDs and reference checksum. No `monday_splits.pkl` or Monday model bundle.
- Evidence: `reports/monday/{data_audit,false_alarm_evaluation,verification}.json`,
  preservation hashes and README. Detailed docs: `docs/ML Engine/MONDAY.md`.
- Three Monday tests added; 23 total tests pass (19 ML/reference + four sniffer).
  Tests forbid fitting during evaluation and check common-cohort union, empty
  metrics, source/split checksums and reference overwrite guards.
- Actual verification recomputed source-row/fingerprint matches, all previous
  exposure exclusions, cohort checksum, and metric arithmetic; 30 predictions per
  saved model match the public API. Checksums verified 74 previous files unchanged.
- Recompute results: `.venv/bin/python -m ml_engine.monday --evaluate-only`.
  Read saved JSON/README for no writes. Default model list is all four; selecting
  fewer via `--models` changes the common cohort. Preparation refuses replacing an
  existing reference; archive reference/data/reports before preparing again.
- Monday is NOT automatically incorporated into model training. A future combined
  model must group/deduplicate original days jointly. After training on Monday,
  do not present this observed reference as unseen evaluation for the new model.
  No combined model, model selection, live capture or firewall work was performed.

## Current Tuesday run — completed 2026-11-07

- User selected Tuesday next. Only `dataset/raw/tuesday.csv` was used; no `_plus`
  file was combined. Added Tuesday's policy/paths to the existing registry and
  ignored `ml_engine/models/tuesday_v1/`. Shared pipeline/model settings unchanged.
- CLI uses `--dataset tuesday`; Python uses `predict(features, dataset="tuesday")`
  or its batch equivalent. Friday remains the default, including sniffer CLI
  `--predict`. Four independent weekday classifiers exist, not one combined model.
- Three labels: BENIGN, FTP_BRUTE_FORCE, SSH_BRUTE_FORCE. Merge FTP-Patator and
  SSH-Patator with their Attempted variants; preserve original-label/attempted
  metadata. No label exclusions. Unknown labels fail rather than being discarded.
- Raw 322,078 rows: BENIGN 315,106; FTP base/attempted 3,972/12; SSH 2,961/27.
  Removed 2,158 duplicate BENIGN feature vectors. No invalid numeric rows,
  conflicting labels or repeated headers. Retained 319,920 original flows:
  BENIGN 312,948; FTP 3,984; SSH 2,988.
- Total connection groups 211,633. Train 191,952 rows / 126,980 groups; validation
  63,984 / 42,327; test 63,984 / 42,326. Verified zero overlapping row IDs,
  connections or model inputs; every split feature row matches its raw source.
- Same 20 features, training-only scaler/encoder and balanced class weights. No
  synthetic rows, SMOTE or undersampling. Verified scaler mean/variance against
  original training rows; all identity/label metadata stays outside model inputs.
- Validation macro F1: RF 1.0; XGBoost 0.9994381911381741. Selected Random Forest
  on validation before evaluating test. No post-test tuning occurred.
- Test accuracy 0.9999843710927732; macro F1 0.9997183971186455; benign FPR 0.0
  (0/62,589); one error/63,984: a base-label SSH-Patator flow predicted BENIGN.
- Test family supports: BENIGN 62,589; FTP 797; SSH 598. F1: BENIGN 99.9992%,
  FTP 100%, SSH 99.9163%. Attempted test support is only three FTP and six SSH
  rows, all correct; don't generalize from such small subgroups or promise zero
  live false positives based on this partition.
- Artifacts: `ml_engine/models/tuesday_v1/inference_bundle.pkl` and
  `dataset/processed/tuesday_splits.pkl`; evidence `reports/tuesday/`;
  documentation `docs/ML Engine/TUESDAY.md`. Bundle contains selected RF and its
  matching transforms/metadata; selection is not hardcoded to XGBoost.
- Added three Tuesday tests. All 20 tests pass (16 ML + four sniffer). Verified
  30 Tuesday, 20 Friday, 20 Thursday and 25 Wednesday validation predictions in
  one process with cache isolation and matching direct/single/batch predictions.
- Checksums verified 59 prior artifacts/reports/processed/sniffer files unchanged.
  Preserved raw datasets, other weekday runs and unrelated workspace changes.
- View results: `.venv/bin/python -m ml_engine.evaluate --dataset tuesday`.
  Preprocessing/training refuse overwriting a trained default Tuesday run;
  archive models, splits and reports before a future run.
- Limits: within-day grouped evaluation, potential host/campaign overlap and
  dataset-specific ports; no chronological/independent/live validation. Provenance
  and full feature-domain validation remain open. Thursday web weaknesses persist.
- Monday normal-data integration, combined cross-day modeling and live integration
  are future work. Do not concatenate prepared day splits blindly or select a day
  from an assumed attack label. No other milestone is authorized by this run.

## Current Wednesday run — completed 2026-11-07

- User explicitly selected Wednesday next. Only `dataset/raw/wednesday.csv` was
  used; `_plus` files were not combined. Added the Wednesday dataset configuration
  and ignored `ml_engine/models/wednesday_v1/`; shared pipeline implementation and
  all prior label policies/model parameters remain unchanged.
- CLI: `--dataset wednesday` for preprocessing, training and evaluation. Python:
  `predict(features, dataset="wednesday")`, or the batch equivalent. Default
  inference and existing sniffer CLI `--predict` still use Friday.
- Five classes: BENIGN, DOS_GOLDENEYE, DOS_HULK, DOS_SLOWHTTPTEST, DOS_SLOWLORIS.
  Merge each DoS family's base/Attempted labels; retain original-label and attempted
  metadata. Exclude Heartbleed explicitly: 11 rows from one connection group.
- Raw 496,640 → retained 494,528 flows. Removed 2,101 same-label duplicates; no
  conflicting labels, invalid numeric rows or repeated headers were found.
- Retained counts: BENIGN 317,045; DOS_GOLDENEYE 7,647; DOS_HULK 159,049;
  DOS_SLOWHTTPTEST 5,108; DOS_SLOWLORIS 5,679. All 20 features unchanged; identities
  and labels are metadata only. No resampling/SMOTE or synthetic rows.
- Connection groups: 226,691. Training 296,712 flows / 136,014 groups; validation
  98,909 / 45,338; test 98,907 / 45,339. Verified zero cross-partition row,
  connection or identical-input overlaps; every feature row matches raw source.
- Scaler and encoder fit only on original training. Actual scaler mean/variance
  match training-only statistics; class weights use training only.
- Validation macro F1: RF 0.9983642760744365, XGBoost 0.9987194645582488.
  Selected XGBoost on validation macro F1. RF had lower validation benign FPR
  (0.0063% versus 0.0095%); selection criterion remained macro F1.
- Selected XGBoost test accuracy 0.9998079003508347, macro F1 0.9986344542992166,
  benign FPR 0.00015770631929221403 (10/63,409). Errors: 19/98,907 = 10 benign
  flagged, four attacks labelled benign, five cross-family mistakes.
- Test F1: BENIGN 99.99%, GoldenEye 99.77%, Hulk 99.99%, Slowhttptest 99.66%,
  Slowloris 99.91%. GoldenEye - Attempted subgroup has 14/17 correct (three Hulk
  predictions); don't conceal small-subgroup limits with aggregate scores.
- Bundle: `ml_engine/models/wednesday_v1/inference_bundle.pkl`; splits:
  `dataset/processed/wednesday_splits.pkl`; evidence: `reports/wednesday/`;
  detailed documentation: `docs/ML Engine/WEDNESDAY.md`.
- Added four Wednesday tests; all 17 project tests pass (13 ML + four sniffer).
  Verified 50 Wednesday and 20 each previous-day validation predictions with all
  caches in one process. Source/training code hashes match recorded Wednesday run.
- Checksums verified 44 previous model/report/processed/sniffer files unchanged.
  Preserved existing unrelated changes, including legacy Friday plan rename and
  the spreadsheet lock file. No other training, sniffer or response work occurred.
- Test evaluated after validation selection with no subsequent tuning. Remaining
  limits: within-day host/campaign overlap, no temporal/independent/live evaluation,
  dataset-specific ports and unresolved provenance; Heartbleed outside coverage.
- Wednesday training/preprocessing refuse overwriting a trained default run.
  Archive models/splits/reports before reruns. To view existing results:
  `.venv/bin/python -m ml_engine.evaluate --dataset wednesday`.
- Tuesday and a combined cross-day classifier remain future work. Thursday web
  weaknesses are unchanged. Do not infer live readiness or begin another milestone
  without the user's next instruction.

## Current Thursday run — completed 2026-11-07

- User explicitly selected Thursday, rather than Tuesday or Friday Plus. Only
  `dataset/raw/thursday.csv` was used; `_plus` files were not combined or trained.
- Added `--dataset {friday,thursday}` to preprocessing, training and evaluation.
  No argument still means Friday. Programmatic inference accepts
  `predict(features, dataset="thursday")` and the equivalent batch argument.
- Kept all 20 model features. IPs, original labels, attempted status, row IDs and
  connection group IDs are metadata only, never classifier inputs.
- Map `Infiltration - Portscan` to PORTSCAN; merge base/Attempted web brute-force
  labels into WEB_BRUTE_FORCE and base/Attempted XSS labels into WEB_XSS. Preserve
  original labels and attempted status; report original-label test metrics.
- Exclude 99 rows explicitly: Infiltration 36, Infiltration - Attempted 45,
  Web Attack - SQL Injection 13, SQL Injection - Attempted 5. Unknown labels fail.
- Raw 362,075 rows → 356,781 retained. Removed 5,191 same-label duplicates and
  four conflicting-label rows; no invalid numeric rows or duplicate headers.
- Retained class counts: BENIGN 286,134; PORTSCAN 68,609; WEB_BRUTE_FORCE 1,365;
  WEB_XSS 673. Retained web connection groups: 1,363 and 673 respectively.
- Training 214,068; validation 71,357; test 71,356 original flows. Same grouped
  isolation as Friday, no resampling/SMOTE, training-only transforms/class weights.
- Validation macro F1: RF 0.6766085674659057; XGBoost 0.7116348117297955. Selected
  XGBoost on validation only; test evaluated after selection, without retuning.
- Test accuracy 0.9900639049274063; macro F1 0.7090194208560743; benign FPR
  0.010204973176996873 (584/57,227). Total errors: 709/71,356.
- Test F1: BENIGN 99.43%, PORTSCAN 99.93%, WEB_BRUTE_FORCE 45.40%, WEB_XSS 38.84%.
  Web precision is poor (32.89% and 27.71%). Do not call Thursday robust or ready
  for blocking based on its 99% accuracy. Web false positives/family confusion
  require further work using training/validation, not repeated test tuning.
- Web test support is mostly attempted traffic. Base-label web samples are just
  14 brute-force and four XSS rows; their correct predictions are not sufficient
  evidence of generalization. See `original_label_results` in evaluation JSON.
- Bundle: `ml_engine/models/thursday_v1/inference_bundle.pkl`. Splits:
  `dataset/processed/thursday_splits.pkl`. Reports: `reports/thursday/`.
- Verified zero shared original rows, connections or model inputs across splits;
  every split feature row matches the original CSV. Scaler mean/variance match
  training only. Thursday inference checked on 40 validation flows and Friday on
  20 in the same process; cache isolation confirmed. All nine tests pass.
- Checksums for 23 Friday artifacts/reports/processed files were verified unchanged.
  Do not rerun Friday merely to inspect this expansion. Thursday remains a separate
  model; a future combined model requires global cross-day deduplication/grouping.
- Training refuses nonempty output directories. Thursday preprocessing refuses
  replacing its default split when a Thursday model already exists. Archive the
  Thursday run AND reports before another run. Evaluation checks the split hash.
- To see results: `.venv/bin/python -m ml_engine.evaluate --dataset thursday`;
  view `reports/thursday/confusion_matrix.png` or its README for interpretation.
- Remaining: Thursday web-class improvement, provenance, environment pinning,
  independent host/day/campaign and live evaluation. No live capture or response
  work was performed. Ask which next milestone the user wants before expanding scope.

## Current corrected Friday run — completed 2026-11-07

- 547,557 raw rows; removed 2,086 same-label feature duplicates. No invalid or
  conflicting-label rows were found in the actual run. Retained 545,471 flows.
- Split on canonical bidirectional IP/port/protocol connection groups. Same
  connection, original row, or identical model input cannot cross partitions.
- Train: 327,283; validation: 109,094; test: 109,094 original rows.
- No undersampling or SMOTE. Both models use training-only balanced class weights.
  A comparison against alternative balancing methods remains future work.
- Scaler and encoder fitted only on original training rows. Full-data verification
  matched scaler mean/variance to training-only statistics.
- Validation macro F1: RF 0.999295; XGBoost 0.999625. Selected XGBoost on validation.
- Selected XGBoost test accuracy: 0.9998900031165784; macro F1:
  0.999926666204674; benign false-positive rate: 0.00012217257749232057.
- Test errors: 7 benign flows flagged PORTSCAN, 5 PORTSCAN flows labelled BENIGN.
- Test recalls: BOTNET 1.0 (959 examples), DDOS 1.0 (19,029 examples), PORTSCAN
  0.9998428167243005 (31,810 examples). These are dataset results, not live guarantees.
- Predictor was checked on 40 validation flows, including every class. Batch,
  single and direct bundle predictions agree; missing features are rejected;
  empty batches return `[]`.
- All five automated tests pass. `git diff --check` passes. SHA-256 checks verified
  that legacy artifacts remain unchanged.
- New model bundle: `ml_engine/models/friday_v2/inference_bundle.pkl`. Predictor
  uses this bundle; there is no fallback to old leaky models.
- New artifacts are ignored by Git; reports/tests/code are reviewable source.
- Training refuses to overwrite a nonempty `friday_v2/` directory. Archive that
  run AND reports before future retraining. Reprocessing replaces the split
  artifact; evaluation refuses a split checksum different from training's.
- Remaining limitations: no independent-host/campaign/day or live evaluation.
  Timestamp strings lack full date/hour information; chronological splitting was
  not attempted. Ports may encode dataset-specific patterns. Exact dataset
  provenance still needs documentation. Do not tune repeatedly on this test set.
- Next work should be chosen with the user: further inference hardening/environment
  pinning or packet/flow extraction. Do not start backend/firewall work implicitly.

## Verified baseline (2026-11-07)

These are historical observations from this review; recheck when relevant rather
than treating them as permanent environment facts.

- All Python modules parsed successfully using `ast.parse`.
- Use `.venv/bin/python` for project commands. The system interpreter lacked
  several ML dependencies; the local virtual environment had them.
- `.venv` contained NumPy, pandas, scikit-learn, imbalanced-learn, XGBoost, joblib,
  matplotlib and seaborn, but not Scapy.
- `.venv/bin/python -m pip check` reported no broken installed requirements.
  This does not establish that every entry in `requirements.txt` is installed.
- Local Friday CSV: 89 columns; selected feature headers match the code.
- Raw label counts:
  - BENIGN: 288,544
  - Portscan: 159,066
  - DDoS: 95,144
  - Botnet - Attempted: 4,067
  - Botnet: 736
- Saved encoder classes: BENIGN, BOTNET, DDOS, PORTSCAN.
- Saved scaler: 20 features, 636,264 fitted samples.
- Saved test data: 127,253 rows, 20 features, approximately balanced classes.
- Both saved models loaded and predicted successfully.
- Recomputed on the saved test set without rewriting artifacts:
  - RF accuracy: 0.9999449914736784; macro F1: 0.9999449911648594.
  - XGBoost accuracy: 0.9999764249172908; macro F1: 0.9999764247319753.
- One raw flow produced a BENIGN prediction.
- `predict({})` returned a prediction rather than rejecting missing features.
- `predict_batch([])` raised a 2D-array shape ValueError.

These legacy scores are reproducible but are NOT reliable evidence of generalization:
the original pipeline leaked information across the train/test boundary.

## Findings to address

Historical findings below describe the ORIGINAL pipeline. Items 1, 2, 4, 5, 6
and 8 were addressed in the corrected run; generic SMOTE was removed (item 3).
Item 7 now rejects missing/nonfinite/negative inputs and handles empty batches;
complete per-feature domain validation remains future work. Items 9 and 10
remain partially or wholly open; tests and README have been added, dependencies
are recorded but not pinned. See current-run status above before repeating work.

1. **Evaluation leakage:** `preprocess.py` applies SMOTE and fits StandardScaler
   before `train.py` splits the resulting data. Related real/synthetic examples
   can cross the split, and scaler statistics include held-out data. Split the
   original cleaned data before fitted transformations or resampling. Inspect
   duplicate/related flows and choose appropriate grouping or chronological
   boundaries using the available raw metadata.
2. **Balancing differs from comments/spec:** default `SMOTE(random_state=42)`
   balances all minority classes to the largest class, not just BOTNET to 50,000.
   The saved scaler sample count matches 4 × 159,066. Documentation's roughly
   200,000-row target is inconsistent with current behavior.
3. **SMOTE geometry and feature validity:** SMOTE currently uses unscaled
   features, letting large-range features dominate distances. Generic interpolation
   can also produce fractional ports, protocol identifiers, and flag values.
   Compare class weighting and a deliberate resampling strategy; do not apply
   generic SMOTE blindly.
4. **Model selection disconnected from inference:** evaluation prints the macro
   F1 winner, but prediction always loads `random_forest.pkl`.
5. **Artifact consistency:** preprocessing independently overwrites scaler and
   encoder. Their modification dates were newer than the model dates. This is
   a consistency risk, not proof that the current artifacts are mismatched.
   Bundle/version all inference components and metadata together.
6. **Partial model loading:** `_load_model()` assigns `_model` before loading
   scaler/encoder, yet its early return checks only `_model`. A failed later load
   can leave inference partially initialized. Load atomically.
7. **Input validation:** missing features silently become zero; empty batches
   fail. Validate required feature names, numeric values, finiteness, shape, and
   appropriate ranges, and explicitly define empty-batch behavior.
8. **Inference dependency coupling:** package imports pull in training, SMOTE,
   XGBoost, and plotting dependencies even for RF inference. Separate runtime
   schema/artifact definitions from training modules.
9. **Live feature parity:** extraction must reproduce direction, units, lengths,
   rates, flag semantics, and flow expiry rules of the actual training dataset.
   This remains unimplemented and unvalidated.
10. **Reproducibility/documentation:** pin a verified dependency environment,
    provide usable setup instructions, focused tests, and dataset provenance.

## Proposed implementation plan

Historical implementation plan; the priority correction above and validity review
override its scientific-completion claims and next-work order.

Chunks 1–5 form the Friday model milestone. Baseline preservation, corrected
splits and the first retraining/evaluation run are completed. Class weighting
is the initial balancing choice; comparative balancing experiments and full
inference hardening/environment pinning are not complete. Chunks 6–9 are future work.

### Chunk 1 — Preserve the baseline

- Record dependency versions, dataset counts/checksums, feature schema, and metrics.
- Preserve existing models, scaler, encoder and test data together before replacing
  anything; use isolated/versioned output directories.
- Done when the previous version can be reproduced and compared.

### Chunk 2 — Correct data preparation

- Audit labels, invalid/nonfinite values, feature ranges, duplicates and provenance.
- Reserve original validation/test data before balancing or fitting transforms.
- Assess related-flow leakage and grouped/chronological split feasibility.
- Retain useful split metadata without feeding identities into the classifier.
- Done when split boundaries and exclusions are documented and held-out data is
  untouched by fitted preprocessing/resampling.

### Chunk 3 — Fix class balancing

- Compare class weighting with a controlled training-only resampling strategy.
- Use explicit targets and preserve meaningful categorical/discrete feature values.
- Keep validation/test data representative of the intended evaluation population.
- Done when the chosen method and class counts are explicit and justified.

### Chunk 4 — Retrain and evaluate Friday

- Train RF and XGBoost under the corrected pipeline.
- Select using validation macro F1, attack recall, and benign false-positive rate.
- Evaluate the selected configuration once on the untouched test set.
- Save per-class precision/recall/F1, confusion matrices, split metadata, training
  configuration, and relevant timing/resource measurements.
- Done when there is an honest, reproducible baseline; lower scores than the old
  leaky evaluation are acceptable.

### Chunk 5 — Harden inference

- Bundle the selected model, transformations, encoder, ordered schema and metadata.
- Validate inputs, define empty-batch behavior, and make loading atomic.
- Separate inference imports from training/evaluation dependencies.
- Pin the working environment and add focused tests for meaningful failure cases,
  artifact consistency, feature order, and single/batch prediction agreement.
- Done when inference is repeatable and invalid inputs fail clearly.

### Chunk 6 — Implement flow extraction

- Implement capture, bidirectional flow tracking, expiry and the 20 features.
- Specify units and feature definitions using the actual dataset generation method.
- Validate against recorded traffic before relying on live capture.
- Done when packet recordings yield consistent, valid model inputs.

### Chunk 7 — Validate live detection

- Connect extraction to inference in the isolated lab, initially detection-only.
- Measure false alerts, missed attacks, latency, throughput and memory use.
- Done when live/recorded traffic provides evidence beyond dataset evaluation.

### Chunk 8 — Build backend and response

- Implement FastAPI, authentication, persistent alerts, event delivery and notifications.
- Add firewall response with allowlists, expiry, audit records and manual unblock.
- Test response behavior in the lab before enabling automatic blocking.
- Done when detection-to-response actions are controlled and traceable.

### Chunk 9 — Dashboard and deployment

- Build live alerts, statistics, blocked-IP management and forensic views.
- Add deployment configuration, health checks, secrets configuration and setup docs.
- Done when the end-to-end demonstration is reproducible.

Tuesday, Wednesday, Thursday and Friday baselines are complete; Thursday's web
weaknesses remain unresolved. Monday normal-data integration and a combined model
remain future work. Keep explicit coverage and cross-day leakage decisions for
that future work when requested.

Monday normal-reference preparation and saved-model false-alarm evaluation are
complete. Integration into training is a different, still-unimplemented milestone.

## Working conventions

- Read this handoff first; inspect relevant source before edits rather than repeating
  the entire initial review. Refresh historical observations as needed.
- Preserve raw datasets, existing artifacts and unrelated user modifications.
- Initial git status before this file: modified `dataset/processed/.gitkeep`,
  modified `dataset/raw/.gitkeep`, untracked `Claude.md`.
- CSVs and pickle models are ignored by Git; a clean Git status does not prove
  local datasets or artifacts are absent.
- Do not launch full preprocessing/training simply to inspect the project: those
  commands overwrite existing outputs. Use explicit isolated outputs when authorized.
- Do not interpret high saved test scores as proof the system is ready for blocking.
- After each implemented chunk, append a concise dated entry below with changes,
  checks/results, remaining issues and the next step. Never mark planned work done
  without evidence.

## Change log

- 2026-11-07: User requested documentation in `docs/`. Added
  `docs/ML Engine/ML_ENGINE.md` covering the Friday leakage correction, Thursday
  labels/exclusions, cleaning/splits, training/selection, exact saved results,
  artifact/API usage, limits and a proposed validation-based improvement plan.
  Added `docs/README.md` and linked from the project README. Read saved JSON/code
  to ground the document; no retraining, evaluation rerun or runtime changes were
  performed. Preserved existing sniffer implementation and all unrelated changes.

- 2026-11-07: Completed read-only project analysis and saved this handoff/plan.
  No implementation chunks completed. Await the user's next implementation instruction.
- 2026-11-07: User authorized fixing Friday leakage and running it. Reworked
  preprocessing into duplicate-free, connection-grouped train/validation/test
  splits; replaced SMOTE/undersampling with training-only class weights; fitted
  transforms on training only; selected XGBoost on validation; completed held-out
  evaluation. Added a matching inference bundle, input checks, lazy package imports,
  overwrite/checksum guards, five passing tests, README and reports. Preserved all
  legacy artifact checksums and unrelated `.gitkeep`/`Claude.md` changes. See
  `reports/friday/README.md` and `verification.json` for results. No live capture,
  packet collection, firewall changes or backend work was performed.
- 2026-11-07: User selected Thursday next. Added explicit dataset policies and
  `--dataset thursday` support with separate artifacts; preserved Friday defaults
  and verified 23 Friday files unchanged. Audited/cleaned Thursday, grouped splits,
  trained RF/XGBoost using class weights, selected XGBoost on validation and evaluated
  once on held-out data. Added four Thursday tests (nine total passing), original
  label/subgroup reports, inference/cache checks, README and handoff updates.
  Thursday accuracy 99.0064% hides macro F1 70.9019% and weak web precision/F1;
  this is an honest baseline requiring validation-based improvement. No other
  weekday, combined model, live capture, backend or firewall work was started.
- 2026-11-07: User asked to write the sniffer. Implemented capture + flow extraction
  mirroring the DistriNet-fixed CICFlowMeter (GintsEngelen/CICFlowMeter source) that
  produced the Friday CSV; semantics verified against the CSV (µs, payload lengths,
  120 s timeout, no 1-packet/zero-duration flows, rate/mean formulas exact). Added
  `tests/test_sniffer.py` (4 tests; 13 total pass), installed Scapy 2.8.0 in `.venv`.
  A pcap SYN/RST probe classified PORTSCAN, a normal session BENIGN. Deviations:
  torn-down TCP flows emit after a 5 s idle grace (reference waits for SYN/120 s);
  IPv4 only; no recorded-traffic validation yet. Live capture needs root (verified
  it fails loudly without). `publisher.py`/`rules.py` left as placeholders (backend
  future). Next: validate on lab pcaps (Chunk 6 done-criterion), then Chunk 7.
- 2026-11-07: User selected Wednesday. Added its explicit five-class DoS policy,
  excluded Heartbleed (11 rows/one group), cleaned/grouped original data and trained
  RF/XGBoost with the existing pipeline. Selected XGBoost on validation; held-out
  accuracy 99.9808%, macro F1 99.8634%, 19/98,907 errors. Added four Wednesday
  tests (17 total passing), audit/training/evaluation/verification reports and
  Wednesday documentation; updated shared docs/README/handoff. Verified no split
  overlaps, training-only scaler statistics, five-class inference and preservation
  of 44 previous files. Previous models, reports and sniffer code are unchanged;
  no combined model, Tuesday run or live integration was started.
- 2026-11-07: User selected Tuesday. Added its three-class FTP/SSH policy without
  exclusions; cleaned/grouped raw data and trained RF/XGBoost using the existing
  pipeline. Random Forest won validation selection; held-out accuracy 99.9984%,
  macro F1 99.9718%, one SSH flow missed/63,984, zero benign false positives in
  this partition. Added three tests (20 total passing), full run/verification
  reports and Tuesday documentation; updated shared docs/README/handoff. Verified
  training-only transforms, split isolation, all four caches and 59 preserved
  previous files. No other-day retraining, sniffer changes, combined model or live
  integration was performed.
- 2026-11-07: User selected Monday during Tuesday completion. Verified BENIGN-only
  labels; cleaned a 369,597-row normal reference without training a classifier.
  Added saved-model false-alarm evaluation on full/reference and a shared 189,279-
  row cohort excluding prior input/connection exposure. Common FPR: Friday 0.0301%,
  Thursday 1.6663%, Wednesday 0.0777%, Tuesday 0%. Added three tests (23 total
  passing), source/cohort/API/preservation verification, Monday reports/docs and
  updated shared README/handoff. All 74 previous files are unchanged. No previous
  model/scaler was fitted, no model winner selected and no live behavior changed.
- 2026-11-07: Audited the user's validity critique. Confirmed endpoint-pair overlap
  across partitions and measured the hypothetical Monday OR false-positive union
  (3,357/189,279). Reviewed primary dataset/persistence documentation; identified
  unresolved Attempted semantics, provenance, capture parity and runtime failure/
  artifact trust boundaries. Saved findings and revised priorities in
  `docs/ML Engine/VALIDITY_REVIEW.md` and `reports/validity_review/findings.json`;
  corrected prominent documentation claims and marked the old SMOTE plan obsolete.
  Updated report interpretation notes; existing metric JSON, splits, raw data, model
  artifacts and runtime code were not changed. No ablation, replay, retraining,
  runtime fix or artifact quarantine was performed. Next: provenance/target and
  matching-capture evidence before further performance claims.
- 2026-11-07: User requested consolidating weekday-fragmented tests into pytest.
  Replaced five weekday test modules with responsibility-based preprocessing,
  training, inference, evaluation and normal-reference modules; converted the
  sniffer tests to pytest. Added shared expected policy cases, one flow factory,
  isolated temporary paths/caches and small real RF/XGBoost fits. Original 23 tests
  passed before migration; 121 parametrized cases pass after migration. Added
  pytest configuration/dev dependency, test guide, central report index and optional
  combined JUnit output. Updated active docs/commands; historical experiment
  evidence, production code, raw/processed data and saved models were preserved.
  Existing dependency deprecation warnings arise from joblib/NumPy persistence.
  The validity review's scientific and serving issues remain unresolved; do not
  infer model generalization from a green regression suite.
- 2026-11-08: Implemented and ran the user-approved unified seven-class experiment
  with the existing 20 features and supported Attempted flows mapped to BENIGN.
  Recomputed global cleaning/groups across five original CSVs; capped BENIGN only
  after reserving validation/test. Trained RF/XGBoost, selected RF on validation and
  evaluated once: accuracy 99.9649283%, macro F1 99.8192265%, benign FPR 0.0275440%.
  Default API/sniffer now use the unified bundle, retaining explicit weekday scopes.
  All 169 tests pass; full source/split/scaler/API checks and an offline synthetic
  PCAP smoke passed. Verified 89 prior files unchanged. Added reports, measured
  resources, methodology and handoff notes. Campaign overlap, tiny web support,
  provenance, port ablation and original-PCAP parity remain unresolved. No live
  capture, backend/firewall work, current-task commits or push was performed.
- 2026-11-08: User authorized starting response integration. Added immutable events,
  model-byte identity, bounded local transport, repeated-flow/coverage gates,
  protected/idempotent firewall simulation and background JSONL audit. Connected
  opt-in `--respond`, added an offline fixture generator, component tests, guide,
  revised sprint sequence and saved evidence. All 243 tests pass. Actual-model
  synthetic replay yielded three PORTSCAN events and one `would_block`; all events
  drained/logged. Fixed and tested the shutdown publish/timeout race. Verified 91
  historical/unified artifact files unchanged. No live capture, real firewall rules,
  retraining, external services, current-task commits or push. Next: persistence/
  authenticated API and explicit broker semantics, with lab validation before
  privileged prevention.
- 2026-11-09: User authorized implementing the backend review fixes. Replaced
  anonymous access/public bootstrap/default secrets/database fallback with scoped
  auth, explicit bootstrap/configuration and fail-closed app/DB initialization.
  Added strict schemas, atomic idempotency/provenance, explicit preserving migration,
  UTC storage, acknowledged block lifecycle, durable asynchronous outbox and bounded
  authenticated WebSockets. Fixed password boundaries and isolated test lifespan.
  All 308 cases pass; real loopback CLI/API and isolated PostgreSQL checks passed.
  Verified 91 previous artifact/data/report files unchanged. Saved guide/evidence
  and updated handoff. Existing DB/env were preserved, no real rules/capture,
  retraining, commits or push. Existing deployments need documented configuration,
  backup/migration and restart; independent detector validation remains open.
