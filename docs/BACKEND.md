# Backend authentication, database and durable sensor delivery

Updated: 2026-11-09 (Asia/Karachi).

This supersedes the initial Sprint 2 implementation. Monitoring requires a user
JWT; ingestion and sensor control use a separate sensor credential. The response
controller remains a simulator. No endpoint executes firewall commands.

## Existing installations

1. Stop the old backend and sensor before changing their configuration/schema.
2. Back up the selected database using the SQLite backup API or PostgreSQL backup
   tooling. Preserve its existing `DATABASE_URL`; there is no automatic fallback.
3. Keep a strong existing JWT secret, or rotate a default/compromised secret. Add
   an independently generated `SENSOR_API_TOKEN` of at least 32 bytes and a
   `SENSOR_ID`, normally `sensor-local`. Do not share either credential in chat.
4. Run `.venv/bin/python -m backend.manage migrate` against that explicit database.
5. Review existing users/admin flags. The old public registration route could
   assign administrator access; migration preserves accounts and cannot determine
   which accounts are legitimate. Old JWTs lack the new required claims and users
   must log in again.

Migration adds nullable provenance fields/indexes and new lifecycle/bootstrap
tables without rewriting historical rows. It is repeatable and has been checked
with SQLite and a private PostgreSQL cluster. Legacy events have unknown model
hashes; legacy block rows have no sensor ownership and cannot be sent to an agent
as trustworthy unblock commands. Reconcile those historical records explicitly.
Startup refuses an old schema instead of partially operating or selecting a new DB.

The implementation did not migrate your configured database or replace your
existing environment file. These are explicit operator steps before restarting an
existing installation.

## New local installation

Use the existing project environment and run from the repository root. Keep
runtime files private and run the backend without root privileges:

```bash
umask 077
mkdir -p runtime
.venv/bin/python -m backend.manage init-config --database-url sqlite:///./runtime/securenet.sqlite3
.venv/bin/python -m backend.manage migrate
.venv/bin/python -m backend.manage create-admin --username admin --email admin@example.com
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Install the updated requirements in a fresh/older environment. `websockets` is now
explicitly declared for actual Uvicorn WebSocket support; TestClient alone does not
verify that transport dependency. See [Uvicorn installation](https://uvicorn.dev/installation/).

`init-config` generates independent random keys in `backend/.env`, mode 0600,
without printing them. It refuses to overwrite an existing file. Use the existing
installation steps when one already exists. `create-admin` prompts for a password
and confirmation; passwords need at least 12 characters and at most 72 UTF-8
bytes. The singleton bootstrap works only on an empty user table and prevents
competing bootstrap attempts from creating multiple initial administrators.

The environment loader reads `backend/.env`, or root `.env` if the backend file is
absent. Existing process environment values take precedence. SQLite is a deliberate
development choice in the command above. PostgreSQL deployments must configure
their actual URL; connection/schema failures stop startup and never create a
replacement SQLite security database. Protect existing database files and backups
with appropriate filesystem permissions too.

## User authentication and authorization

`POST /api/auth/login` accepts form fields `username` and `password`. Its response
contains `access_token`, `token_type` and `expires_in`. Send subsequent user requests
with `Authorization: Bearer <access_token>`. Tokens expire after 30 minutes by
default (`ACCESS_TOKEN_EXPIRE_MINUTES`, 1–1440); HS256 is the fixed signing algorithm.
Expiry, issue time, audience, issuer, token purpose and numeric user ID are required.
Current account activation/admin status is read from the database.

| Endpoint | Credential / behavior |
| --- | --- |
| `GET /api/health` | Public readiness after successful startup; exposes no credentials |
| `POST /api/auth/login` | Username/password; inactive or invalid accounts return 401 |
| `GET /api/auth/me` | Active user JWT |
| `POST /api/auth/register` | Administrator JWT; provisions another operator/admin |
| `GET /api/alerts`, `/api/stats` | Active user JWT |
| `GET /api/firewall/blocked`, `/api/firewall/whitelist` | Active user JWT |
| `POST /api/firewall/unblock/{ip}` | Administrator JWT; returns 202 and pending command ID |
| `POST /api/alerts/ingest` | Sensor token and matching sensor ID; user JWTs are insufficient |
| `GET /api/sensor/commands` | Sensor credentials; returns only that sensor's pending commands |
| `POST /api/sensor/commands/{id}/ack` | Sensor credentials; validates command/block identity |
| `POST /api/sensor/firewall-events` | Sensor credentials; idempotent expiry/lifecycle persistence |

There is no public first-user registration. Admin-only registration checks username,
email and password bounds, handles unique conflicts with 409 and rolls back failed
inserts. Login handles overlong/invalid passwords with 401 rather than a bcrypt
exception. Existing short nonempty passwords can still log in; newly provisioned
passwords follow the new policy.

## WebSocket access

HTTP-capable clients may connect to `/ws/alerts` using an Authorization Bearer
header. Browsers should first call authenticated `POST /api/auth/ws-ticket`, then
connect to `/ws/alerts?ticket=<ticket>`. Tickets expire after 30 seconds, are single
use and recheck the user's active status. A JWT in a query parameter is not accepted.
Avoid logging ticket URLs; use TLS when serving beyond loopback.

Unauthorized connections are rejected before subscription. Connections end when
the underlying user token expires. Each client has a bounded 100-message queue and
five-second send timeout; slow clients are disconnected rather than delaying
ingestion/other clients. Maximum connections are 256, with at most 1,024 outstanding
tickets. Tickets and broadcasts are process-local: use one Uvicorn worker until a
shared broker/ticket store is introduced. Configure explicit dashboard origins in
`CORS_ORIGINS`; the default allows no browser cross-origin access.

## Sensor setup and persistent delivery

Export only the sensor credential to the sniffer environment, not the user JWT key
or database URL:

```bash
.venv/bin/python -m backend.manage export-sensor-config --output runtime/sensor.env
set -a
. runtime/sensor.env
set +a
.venv/bin/python -m sniffer.main -r capture.pcap --predict --respond --api-url http://127.0.0.1:8000
```

The export file uses 0600 and is never overwritten. An agent on another machine
needs only `SENSOR_API_TOKEN` and `SENSOR_ID`, transmitted through your secure
configuration process. HTTP forwarding is allowed on loopback; remote agents must
use HTTPS. Credentials are sent as `X-Sensor-Token` and `X-Sensor-ID` headers. HTTP
redirects are rejected. `--api-url` requires `--respond`/`--predict` and fails early
when the sensor credential is missing. `--sensor-id` overrides the environment ID.

The local response consumer writes JSONL, then transactionally queues the API
message in a SQLite outbox. The default path for `runtime/alerts.jsonl` is
`runtime/alerts.outbox.sqlite3`; `--outbox` overrides it. A separate sender performs
HTTP, leaving the policy/audit consumer independent of network delay. The outbox:

- Survives restart; keep its path stable to resume pending delivery.
- Binds to one API URL/sensor ID and holds an exclusive process lock.
- Stores no credentials. New database files use mode 0600.
- Preserves pending FIFO order so detections precede dependent expiry events.
- Retries transient errors with capped exponential backoff, at most eight attempts.
- Retains exhausted or permanent failures as dead letters, including bad
  credentials, invalid payloads and mismatched acknowledgement identities.
- Deletes a message only after a matching endpoint-specific acknowledgement.
- Holds at most 100,000 pending/failed messages; a full outbox fails visibly while
  retaining the corresponding JSONL evidence.

`api_pending` and `api_dead_letters` are separate from local `processed` counts.
Shutdown allows a bounded delivery grace; undelivered messages remain on disk.
Fix the cause of a failure, stop the sensor, inspect/retry and restart it using the
same API/sensor/outbox:

```bash
.venv/bin/python -m backend.outbox status runtime/alerts.outbox.sqlite3
.venv/bin/python -m backend.outbox retry runtime/alerts.outbox.sqlite3
```

The capture queue remains bounded and process-local; an overflow loses the incoming
response event and is reported. JSONL and outbox writes are not one distributed
transaction, so a crash between them can leave an event only in JSONL. This does
not provide exactly-once capture or automatic reconstruction of virtual blocks.

## Block lifecycle and honest status

All proposals are `dry_run`. Ingestion rejects active/real-firewall claims. New
simulated blocks have UUIDs. An unblock targets both IP and block UUID, so an old
command cannot remove a newer block for the same IP.

Manual unblock records the requesting administrator and returns `PENDING` while
the database block is `UNBLOCK_REQUESTED`. The running sensor polls, updates its
own simulator and durably acknowledges the result. Only then does the backend
mark the record `UNBLOCKED`. If the old simulator process has restarted, a
`not_simulated` acknowledgement confirms that old virtual block is absent.

An overdue record becomes `EXPIRY_PENDING` rather than remaining ACTIVE or claiming
confirmed expiry. The sensor forwards expiry events to complete the `EXPIRED`
transition. Lifecycle event IDs and command acknowledgements are idempotent.
Offline sensors leave commands/status pending until they reconnect. A sensor
must run for its own identity; concurrent processes with different outbox paths
must not share one sensor identity.

`active_blocked_ips` remains zero because no real firewall executor exists.
`active_simulated_blocks` reports current simulated records separately. Timestamps
are normalized to aware UTC, including SQLite round trips. The whitelist endpoint
reports built-in defaults; custom `--protect` values belong to the sensor's audit.

## Verification and remaining scope

The full regression suite passes 308 cases. Additional checks used an actual
loopback Uvicorn API with the real saved model/offline synthetic PCAP, and a
private Unix-socket-only PostgreSQL cluster for concurrent ingestion, acknowledgements
and repeatable legacy migration. See [saved evidence](../reports/backend_hardening/README.md).
Tests use app factories with injected private engines; no configured database is
initialized by test lifespan.

Live capture parity, campaign-independent detection, calibrated response policy,
privileged firewall execution, Redis/multiple API workers, login rate limiting,
dashboard and production deployment validation remain separate work. The existing
ML score/capture limitations in the [validity review](<ML Engine/VALIDITY_REVIEW.md>)
remain unchanged. No model was retrained, no live packets captured and no host
firewall rules applied during this hardening.
