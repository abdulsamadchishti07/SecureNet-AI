# Sprint 3 complete — 2026-11-09

PostgreSQL setup, the authenticated SOC dashboard and integration checks are
complete. After the user clarified React, the native adaptation was replaced with
actual React/TypeScript components, Vite and Lucide. The original TSX is preserved;
FastAPI serves the compiled React build and Vite provides the development server.

- **327 default pytest cases passed**; 5208 known deprecation warnings remain.
  **Nine Chromium browser workflows passed on React.** Static tests inject a private
  build; browser tests use real Vite output and isolated database/server fixtures.
- Clean lockfile npm ci, strict TypeScript checking, production build and formatting
  passed. npm audit reported zero known advisories at verification. React/ReactDOM
  19.3.1, TypeScript 7.0.2, Vite 8.3.7 and dependencies are exact-pinned.
- Main PostgreSQL was backed up and explicitly migrated, preserving its original
  empty tables and URL/JWT key. The backup restored in a disposable Unix-socket-only
  cluster, then that cluster was stopped/removed. Admin/sensor credentials remain
  in private, ignored runtime files.
- Configured PostgreSQL + actual unified model + offline CLI + browser verified
  three new predictions/events, ticket-authenticated live display, model run/hash,
  SQL analytics and an exact-block UUID manual request/acknowledgement.
- Earlier native-probe assertions were corrected for five-second polling and historical
  same-IP rows. All three attempts' nine synthetic PORTSCAN events/response history
  remain in the DB. The final run checks its own UUID; real/simulated active blocks
  and pending unblocks are zero. Sensor shutdown was clean.
- The React migration then verified a real React root, another three saved-model
  detections and its exact new block UUID through acknowledgement. Current main DB
  retains 12 synthetic events, with zero active blocks/pending commands. Development
  login and ticket WebSocket proxy also passed at 5173; compiled app is on 8010.
- No uncaught browser exceptions, external runtime requests or credentials in
  local/session storage. Desktop 1920×1080 and mobile 390×844 were inspected;
  mobile has no horizontal page overflow.
- All eight views also passed overflow checks at six widths (360..1920px), and
  actual page-metadata JSON export passed.
- Covered: static isolation/headers, role controls, errors, reconnect/logout/expiry,
  pagination/duplicates, account validation and offline-sensor pending status.
- SHA-256 verifies 89 historical files and both unified artifacts unchanged.
  `pip check`, JavaScript syntax and `git diff --check` passed. No retraining, live
  capture, kernel firewall commands, commit or push.

Evidence: [verification.json](verification.json),
[desktop screenshot](dashboard-desktop.png), [mobile screenshot](dashboard-mobile.png).
Usage: [Sprint 3 guide](../../docs/SPRINT_3.md); design: [DESIGN.md](../../DESIGN.md).
Completion source/asset hashes and sanitized probe outcomes are recorded in JSON;
setup/runtime probes themselves were temporary scripts.

The compiled API/dashboard was left on loopback 8010 with access logs off and
log level WARNING (no-access-log alone does not suppress WebSocket URL INFO logs),
plus the Vite dev server on 5173, preserving the
unrelated service on 8000. Responses remain simulated. Campaign independence,
original-capture parity, calibrated policy and isolated enforcement are future work.
