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
./scripts/demo_up.sh [OPTIONS]
# Options: --mode dry-run|live-dry-run|enforced, -r/--pcap PATH, -i/--iface IFACE,
#          --protect CIDR, --helper-socket PATH, --allow-unprotected-lab, --linger-seconds N
```

What `./scripts/demo_up.sh` does:
1. Parses and validates demo mode/capture arguments up front (failing with exit status `2` on invalid combinations).
2. Verifies `backend/.env`, `frontend/dist/index.html`, and `runtime/sensor.env` (`0600`), then runs `.venv/bin/python -m backend.manage migrate`.
3. Starts or reuses `uvicorn backend.main:app` on `http://127.0.0.1:8010` (`--no-access-log --log-level warning`).
4. Generates `runtime/response_demo_offline.pcap` (if using the default offline replay and missing) via [`scripts/create_response_demo.py`](../scripts/create_response_demo.py).
5. Launches `sniffer.main` with `--linger-seconds 300` (default) and verifies sensor readiness; if startup fails, prints the trailing sensor log, stops any backend it started, removes PID files, and exits `1`.

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
`./scripts/demo_down.sh` sends `SIGTERM` to the lingering sensor (triggering orderly `sniffer.main` shutdown drain/reconciliation with exit status `0`), prints the durable outbox status (`{"pending": 0, "failed": 0}`), and stops the demo API process if `demo_up.sh` started it.

---

## 4. Workflow B — Isolated Network-Namespace (`netns`) Enforcement Demo

To verify real kernel `nftables` packet drops, manual unblock recovery, and crash lease-rollback recovery without touching the host's default network namespace:

```bash
./scripts/netns_lab_demo.sh
```

What [`scripts/netns_lab_demo.sh`](../scripts/netns_lab_demo.sh) does:
1. Creates two separate Linux network namespaces (`sensor` and `attacker`) linked by a `veth` pair (`veth-sensor` `10.200.0.1/24` in the sensor namespace ↔ `veth-attk` `10.200.0.2/24` in the attacker namespace).
2. Starts an isolated SQLite FastAPI backend, `/usr/bin/python3 -I backend/fw_helper.py` (`--protect 10.200.0.1/32 --lease-seconds 5`), and live `.venv/bin/python -m sniffer.main -i veth-sensor --predict --respond --enforce`.
3. Verifies baseline TCP and ICMP reachability from attacker (`10.200.0.2`) to sensor (`10.200.0.1`), then sends a live TCP SYN portscan (`8081..8083`), confirms `PORTSCAN` classification and kernel packet drops (`TCP` and `ICMP` blocked), and proves `POST /api/firewall/unblock/10.200.0.2` restores connectivity.
4. Triggers a second live block, sends `SIGKILL` to the sensor process, proves the helper lease watchdog deletes `table ip securenet` and restores connectivity, then restarts the sensor briefly and sends `SIGTERM` to verify startup database reconciliation (`ROLLED_BACK`) and clean exit (`0`).

---

## 5. Troubleshooting & Operational Recovery

- **Inspect or retry durable outbox messages (while sensor is stopped):**
  ```bash
  .venv/bin/python -m backend.outbox status runtime/demo_alerts.outbox.sqlite3
  .venv/bin/python -m backend.outbox retry runtime/demo_alerts.outbox.sqlite3
  ```
- **Stale PID files:** `./scripts/demo_up.sh` automatically cleans up stale PID files if the recorded process is no longer alive, or instructs you to run `./scripts/demo_down.sh` if a demo process is still active.

