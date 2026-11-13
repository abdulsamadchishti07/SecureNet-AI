# SecureNet AI — Demonstration Runbook

This runbook provides reproducible, single-command and step-by-step workflows for demonstrating SecureNet AI in **default dry-run mode** and in an **isolated Linux network-namespace (`netns`) enforcement lab**.

---

## 1. Safety & Scope Principles

1. **Dry-run is always the default:** Running `sniffer.main --predict --respond` without `--enforce` never executes firewall commands.
2. **Privilege separation:** When `--enforce` is explicitly enabled, the unprivileged sensor communicates over a local Unix socket (`runtime/fw_helper.sock`) with [`backend/fw_helper.py`](../backend/fw_helper.py), a pure Python standard-library daemon executed via `/usr/bin/python3 -I`.
3. **Owned `nftables` table:** The helper manages only `table ip securenet` (`chain input` + expiring `set blocked_ips`) and never flushes or alters external host firewall tables.
4. **Automatic rollback & reconciliation:** On sensor shutdown or helper lease expiration, `table ip securenet` is deleted and the sensor reconciles active blocks in PostgreSQL to `ROLLED_BACK` (cancelling any pending unblock commands).
5. **Port 8000 preservation:** Local demonstration scripts default to `127.0.0.1:8010` and refuse port `8000` unless `ALLOW_PORT_8000=1` is explicitly set.

---

## 2. Prerequisites & One-Time Setup

Ensure the Python virtual environment, compiled React frontend, and private configuration files exist:

```bash
# 1. Install dependencies (if not already installed)
.venv/bin/python -m pip install -r requirements-dev.txt
npm --prefix frontend ci
npm --prefix frontend run build

# 2. Initialize private backend/.env and sensor credentials (non-overwriting)
.venv/bin/python -m backend.manage init-config
.venv/bin/python -m backend.manage export-sensor-env runtime/sensor.env
.venv/bin/python -m backend.manage migrate
```

> **Note:** Never print or commit `backend/.env`, `runtime/sensor.env`, or `runtime/admin-login.txt`.

---

## 3. Workflow A — Default Dry-Run SOC Dashboard Demo

Start the FastAPI backend (if not already running on `127.0.0.1:8010`) and replay the synthetic portscan PCAP with a 300-second sensor linger window so manual unblock requests from the React UI are acknowledged live:

```bash
./scripts/demo_up.sh
```

What `./scripts/demo_up.sh` does:
1. Verifies `backend/.env`, `frontend/dist/index.html`, and `runtime/sensor.env` (`0600`).
2. Runs `.venv/bin/python -m backend.manage migrate`.
3. Starts or reuses `uvicorn backend.main:app` on `http://127.0.0.1:8010` (`--no-access-log --log-level warning`).
4. Generates `runtime/response_demo_offline.pcap` (if missing) via [`scripts/create_response_demo.py`](../scripts/create_response_demo.py).
5. Runs `sniffer.main` in `dry_run` mode with `--linger-seconds 300`, forwarding 3 `PORTSCAN` detections and 1 `would_block` proposal to the API.

### Interactive UI Walkthrough
1. Open `http://127.0.0.1:8010` and sign in with your administrator account.
2. Observe **Total Events**, **Threats Detected**, **Simulated Blocks (`1`)**, and the live **Alerts Feed**.
3. Click **Inspect event** on any `PORTSCAN` row to verify the 20 flow features, model SHA-256 provenance, and capture/observation timestamps.
4. Open **Blocked IPs** (`Response` view), verify the `ACTIVE` simulated block (`dry_run`), and click **Request unblock**.
5. Within ~1 second, the lingering sensor polls `/api/sensor/commands`, acknowledges the unblock, and transitions the record to the **Unblocked** tab.

### Clean Teardown & Outbox Verification
```bash
./scripts/demo_down.sh
```
`./scripts/demo_down.sh` sends `SIGTERM` to the lingering sensor, prints the durable outbox status (`{"pending": 0, "failed": 0}`), and stops the demo API process if `demo_up.sh` started it.

---

## 4. Workflow B — Isolated Network-Namespace (`netns`) Enforcement Demo

To verify real kernel `nftables` blocking and automatic teardown rollback without touching the host's default network namespace:

```bash
./scripts/netns_lab_demo.sh
```

What [`scripts/netns_lab_demo.sh`](../scripts/netns_lab_demo.sh) does:
1. Enters an isolated Linux network namespace (`unshare --net`) and creates a `veth` pair (`veth-sensor` `10.200.0.1/24` ↔ `veth-attk` `10.200.0.2/24`).
2. Launches `/usr/bin/python3 -I backend/fw_helper.py` bound to a temporary Unix socket with `--protect 10.200.0.1/32` and a 10-second lease watchdog.
3. Starts `ResponseDispatcher` with `FirewallController(mode="enforced", ...)` and publishes repeated high-confidence `PORTSCAN` events from `10.200.0.2`.
4. Verifies that `nft list table ip securenet` contains `10.200.0.2` in `set blocked_ips` with a kernel timeout.
5. Closes `ResponseDispatcher` and verifies that `table ip securenet` is deleted on shutdown and that `startup_rollback` / `shutdown_rollback` audit records are written.

---

## 5. Troubleshooting & Operational Recovery

- **Inspect or retry durable outbox messages (while sensor is stopped):**
  ```bash
  .venv/bin/python -m backend.outbox status runtime/demo_alerts.outbox.sqlite3
  .venv/bin/python -m backend.outbox retry runtime/demo_alerts.outbox.sqlite3
  ```
- **Stale PID files:** `./scripts/demo_up.sh` automatically cleans up stale PID files if the recorded process is no longer alive, or instructs you to run `./scripts/demo_down.sh` if a demo process is still active.

