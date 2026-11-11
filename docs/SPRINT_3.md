# Sprint 3: authenticated SOC dashboard and PostgreSQL setup

Updated 2026-11-09 (Asia/Karachi). PostgreSQL remains the main application
database. Temporary SQLite fixtures are only for isolated automated tests.
The sensor also keeps its existing durable delivery queue in a local SQLite
outbox; it is not an alternative application database or PostgreSQL fallback.

**Sprint 3 is complete.** The working dashboard (`frontend/src/App.tsx`) is
React/TypeScript built with Vite and local bundled fonts,
using the existing authenticated PostgreSQL-backed API. The initial plain
HTML/JavaScript adaptation was replaced after the user's React clarification.
See [frontend setup and source map](../frontend/README.md).

## Completed: configuration, migration and backend contracts

- Connected to the configured `SecureNet_AI` PostgreSQL database. Its original
  `users`, `alerts` and `blocked_ips` tables were empty, with no accounts.
- Backed up the original database and environment before migration. The private
  backup location is recorded in `runtime/sprint3-setup.json`. Successfully restored
  the archive into a disposable Unix-socket-only PostgreSQL cluster, then stopped
  and removed that verification cluster.
- Added the missing independent sensor token/identity. Preserved the database URL,
  existing JWT key and other environment settings; same-origin delivery needs no
  additional CORS origins. Environment files now use mode 0600.
- Applied the additive migration and checked original table row counts. Created
  the initial `admin` account because the user table was empty. Its generated
  login is in `runtime/admin-login.txt` (0600); credentials are not in Git or
  documentation. The sensor-only credential file is `runtime/sensor.env` (0600).
- Verified the real PostgreSQL-backed API accepts that admin, protects monitoring
  endpoints, reports dry-run mode and issues authenticated browser tickets.
- Detection WebSocket messages now include the same flow/provenance fields as
  alert queries, plus `type: detection`, retaining existing `action`/`mode` fields.
- Admin unblock accepts optional `?block_id=<UUID>` and returns the selected block
  ID. The dashboard can target an exact row rather than a newer block for the same
  IP. Existing clients without the query parameter keep their previous behavior.
- Added bounded `--linger-seconds` for offline `--predict --respond` runs. The same
  dispatcher stays alive after PCAP EOF for command polling and expiry; Ctrl+C
  ends the wait. Invalid contexts/ranges fail before capture. Worker/sender errors
  propagate while waiting. This is not replay-time policy calibration.
- Same-origin browser security headers and static serving are active in
  `create_app`. The dashboard is at `/`; repository/runtime/configuration
  directories are not mounted. Credentials and API responses use `no-store`.

## Dashboard behavior

The updated [design specification](../DESIGN.md) follows the supplied TSX's slate
surfaces, emerald navigation, five metric cards, timeline/distribution/source
panels and crimson live-feed sidebar. The reference is preserved as supplied.

- Sign in through the real form endpoint. JWTs stay in module memory, with no
  browser storage; reloading requires login again. Logout/expiry closes the stream
  and clears the session. Tickets are single-use and replaced on reconnect.
- Dashboard shows all-time persisted flow counts, non-benign verdicts, simulated
  blocks, pending unblocks and API status. Real firewall blocks remain separately
  visible at zero. API connection is not a claim that a capture sensor is online.
- `/api/analytics?minutes=15..10080` provides authenticated SQL aggregates: 20
  timestamp buckets, protocol counts and five top non-benign sources. The chart
  selector supports 15 minutes, one hour, one day and seven days. Buckets use native
  UTC timestamp comparisons on PostgreSQL and SQLite; rows are not loaded en masse
  into Python. Observation time is processing time for current sniffer events.
- Seven-class distribution uses actual all-time counts. No random traffic, packet
  rate, email/SMS, resource usage, payload, SHAP or alternate-model metrics from the
  mockup are presented as operational data.
- Alerts support class/confidence filters, 25-row pagination, ordered/deduplicated
  live refresh, an eight-event feed, provenance details and JSON metadata export.
- Response tabs show active/requested/expiry-pending/expired/unblocked records,
  exact-block UUIDs, proposed commands and built-in protected ranges. Unblock
  returns 202, remains pending while the sensor is offline, and changes to terminal
  state only after acknowledgement. Lifecycle queries refresh every five seconds.
- Admins can provision operators/admins; operators have no mutation controls.
  The backend enforces the role independently of the UI. Password validation
  matches the 12-character minimum / 72 UTF-8-byte maximum.
- Traffic, logs, forensics, analytics and settings views use supported data. Logs
  mean detection decisions, not a complete firewall audit. Built-in protection
  ranges do not include custom per-sensor `--protect` settings.
- Responsive tables scroll within their panels. Dialogs, keyboard focus, reduced
  motion, error/empty states and mobile touch targets are implemented. Bundled
  Plus Jakarta Sans/JetBrains Mono retain their OFL licenses; runtime uses no CDN.

The HTML shell is public so users can reach login; monitoring data remains
authenticated. Content Security Policy permits local scripts/styles/fonts only,
with no inline script permission. Static traversal tests reject repository secrets.

## Local commands

Port 8000 belongs to an existing service. Choose a free loopback port, such as 8010:

```bash
npm --prefix frontend ci
npm --prefix frontend run build
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8010 --workers 1 --no-access-log --log-level warning
```

Both logging flags are needed: accepted WebSocket URLs are logged at INFO even
with access logging disabled. Use
the admin login stored privately in `runtime/admin-login.txt`. Existing setup is
already migrated: do not rerun first-admin bootstrap or overwrite credential files.
See the [backend guide](BACKEND.md) for migration/authentication details.

Open `http://127.0.0.1:8010` and sign in. The verification server was left running
on that port at completion; if it has stopped, use the command above. Do not start
a duplicate server or stop the unrelated process on port 8000.

For React development, keep the backend on 8010 and run
`npm --prefix frontend run dev`, then open `http://127.0.0.1:5173`. Vite proxies
HTTP/WebSocket API traffic; PostgreSQL and credentials stay in the backend.
FastAPI serves only `frontend/dist/`; missing builds return an explicit 503 at `/`
while the API stays available. Default Python tests inject a private build fixture.

For another dashboard demonstration, create a fresh synthetic PCAP and keep its
sensor alive for five minutes after EOF:

```bash
.venv/bin/python scripts/create_response_demo.py runtime/sprint3-demo.pcap
set -a
. runtime/sensor.env
set +a
.venv/bin/python -m sniffer.main -r runtime/sprint3-demo.pcap --predict --respond --api-url http://127.0.0.1:8010 --linger-seconds 300
```

Run a single process for this sensor identity. Simulated blocks are process-local;
stopping the sensor leaves unacknowledged commands pending until it reconnects.
This command sends no packets and makes no real firewall changes.

## Verification

- All **327** default pytest cases pass, including static boundaries, missing-build
  behavior, analytics,
  exact-block targeting and linger
  regressions; existing dependency deprecation warnings remain visible.
- All **nine real-browser workflows** pass: live event/details/unblock, operator
  controls/filters, reconnect/logout, expiry, mobile provisioning, failed requests/
  inert untrusted text, offline-sensor pending state, duplicate delivery/pagination,
  and password-byte-limit/account conflicts.
- PostgreSQL migration, backup restore and authenticated loopback API checks passed.
- A real PostgreSQL-backed browser plus offline CLI run produced three new model
  predictions/events and verified the exact new block UUID through manual unblock
  and sensor acknowledgement. No browser exceptions, storage credentials or
  external asset requests were observed. Sensor shutdown was clean.
- The initial three integration attempts left **nine synthetic PORTSCAN events** and their
  response history in the application database. Earlier probe assertions needed
  adjustment for polling delay and old rows sharing the same source IP; those
  records were preserved. Final real/simulated block counts and pending unblocks
  are all zero. Successful final evidence checks the selected UUID, not only IP.
- React conversion was reverified with all nine browser workflows, a real React
  root and another real-model PostgreSQL/PCAP run (three new events). Current DB
  contains 12 synthetic PORTSCAN events; final real/simulated blocks and pending
  commands are zero. Vite development login and WebSocket proxy also passed.
- Exact-pinned npm lockfile clean-install, strict TypeScript checking, production
  build and formatting passed. npm audit reported zero known advisories at this
  verification. Build output is ignored and can be reproduced with npm ci/build.
- Desktop 1920×1080 and mobile 390×844 screenshots were inspected; the mobile page
  has no horizontal overflow. Images and sanitized evidence are in
  [reports/sprint3/](../reports/sprint3/README.md).
- All eight views passed page-overflow checks at 360, 390, 768, 1024, 1440 and
  1920px widths. Actual page-metadata JSON export also passed.
- SHA-256 confirms 89 historical files and both unified artifacts unchanged.
  Playwright 1.64.1 / Chromium 156.0.8078.79 were used; `pip check` passed.

The default suite requires neither PostgreSQL nor a browser. Optional browser
fixtures use a real loopback server with a private temporary SQLite database:

```bash
.venv/bin/python -m pip install -r requirements-browser.txt
# If system Chromium is unavailable:
.venv/bin/python -m playwright install chromium
npm --prefix frontend ci
npm --prefix frontend run build
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest browser_tests -q
# Both suites can also run together:
.venv/bin/python -m pytest tests browser_tests -q
```

The [reviewed execution plan](SPRINT_3_TO_5_PLAN.md) retains the independent-data,
capture-parity and policy gates for later sprints. No model was retrained and no
kernel firewall command was executed. No files have been committed or pushed here.
