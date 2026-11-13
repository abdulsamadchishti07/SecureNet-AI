# Sprint 5 — Isolated Enforcement & Demonstration Packaging

## Overview

Sprint 5 delivers optional, privilege-separated `nftables` host-input enforcement for isolated lab environments (Sprint 5.1) together with reproducible demonstration scripts and runbooks (Sprint 5.2), while preserving `dry_run` simulation as the default across all CLI, worker, and API paths.

---

## Architecture & Security Boundaries

### 1. Privilege-Separated `nftables` Helper ([`backend/fw_helper.py`](../backend/fw_helper.py))
- **Pure Python stdlib (`/usr/bin/python3 -I`):** Runs in isolated interpreter mode so privileged execution never imports third-party packages from `.venv` (`scapy`, `joblib`, `sklearn`, `xgboost`, `fastapi`) or user `PYTHONPATH`.
- **Peer credential verification (`SO_PEERCRED`):** Inspects the connecting Unix domain socket peer UID and rejects unauthorized local users before parsing any request.
- **Dedicated `nftables` table ownership:** Manages only `table ip securenet` with `set blocked_ips { type ipv4_addr; flags timeout; size <max_blocks>; }` and `chain input { type filter hook input priority filter; policy accept; ip saddr @blocked_ips drop; }`. Unrelated host firewall tables are never flushed or modified.
- **Independent guardrails:** Re-validates built-in (`0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, `240.0.0.0/4`) and operator-supplied `--protect` CIDRs, enforces `max_blocks` (default `256`), and deduplicates retries via a bounded `op_id` cache.
- **Lease watchdog:** Requires periodic `heartbeat` renewals from the unprivileged worker; if the worker crashes or misses its lease deadline, the helper automatically deletes `table ip securenet`.

### 2. Unprivileged Client, Controller & Worker ([`backend/fw_client.py`](../backend/fw_client.py), [`backend/firewall.py`](../backend/firewall.py), [`backend/worker.py`](../backend/worker.py))
- **Default `dry_run` preserved:** `FirewallController()` defaults to `mode="dry_run"`, `max_blocks=4096`, and zero subprocess/socket activity.
- **Fail-stop enforcement:** When `mode="enforced"`, `FirewallController` requires a `FwHelperClient` and at least one `--protect` CIDR (or `--allow-unprotected-lab` for isolated `netns` testing). Helper errors raise `EnforcementError`, stopping the worker loudly rather than silently downgrading to `dry_run`.
- **Startup & shutdown reconciliation:** On startup and shutdown in `enforced` mode, `ResponseDispatcher` logs a `reconcile` record and enqueues `POST /api/sensor/reconcile` via the durable SQLite outbox so the database never retains ghost `ACTIVE` enforced blocks.

### 3. Backend Wire Contracts, Database & React UI ([`backend/schemas.py`](../backend/schemas.py), [`backend/service.py`](../backend/service.py), [`backend/main.py`](../backend/main.py), [`frontend/src/App.tsx`](../frontend/src/App.tsx))
- **Dual-mode validation:** `BlockIn`, `ProposalIn`, and `FirewallActionIn` validate both `dry_run` (`iptables` proposals) and `enforced` (`nft add/delete element ip securenet blocked_ips ...`) payloads while keeping `BENIGN`, `WEB_ATTACK`, and non-`unified` scopes strictly alert-only.
- **Explicit `ROLLED_BACK` lifecycle state:** `POST /api/sensor/reconcile` transitions non-active enforced blocks for that sensor from `ACTIVE` / `EXPIRY_PENDING` / `UNBLOCK_REQUESTED` to `ROLLED_BACK` and marks any pending `ResponseCommand` rows as `CANCELLED`.
- **Dashboard visibility:** `/api/stats` reports `active_blocked_ips` (enforced), `active_simulated_blocks` (dry-run), and `response_mode` (`"dry_run"`, `"enforced"`, or `"mixed"`). The React `Response` view adds the **Rolled back** tab and displays per-block mode metadata.

---

## CLI Usage

```bash
# 1. Start the privileged helper (inside an isolated netns or dedicated lab host)
sudo /usr/bin/python3 -I backend/fw_helper.py \
    --socket runtime/fw_helper.sock \
    --protect 10.0.0.1/32 \
    --allowed-uid "$(id -u)"

# 2. Run the sensor in enforced mode
.venv/bin/python -m sniffer.main \
    -r runtime/response_demo_offline.pcap \
    --predict --respond --enforce \
    --helper-socket runtime/fw_helper.sock \
    --protect 10.0.0.1/32
```

See the [Demonstration Runbook](DEMO_RUNBOOK.md) for `./scripts/demo_up.sh`, `./scripts/demo_down.sh`, and `./scripts/netns_lab_demo.sh`.

---

## Remaining Limitations

- Campaign-independent ML generalization and original CIC-IDS2017 PCAP parity remain governed by the evidence gates documented in [`docs/SPRINT_4.md`](SPRINT_4.md) and [`docs/ML Engine/VALIDITY_REVIEW.md`](<ML Engine/VALIDITY_REVIEW.md>).
- Flow-level detection occurs after flow completion or timeout (`--termination-grace`), so post-onset blocking applies to subsequent packets/connections from the offending source IP rather than mid-stream packet scrubbing.

