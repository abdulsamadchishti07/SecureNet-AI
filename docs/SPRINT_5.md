# Sprint 5 — Isolated Enforcement & Demonstration Packaging

## Overview

Sprint 5 delivers optional, privilege-separated `nftables` host-input enforcement for isolated lab environments (Sprint 5.1) together with reproducible demonstration scripts and runbooks (Sprint 5.2), while preserving `dry_run` simulation as the default across all CLI, worker, and API paths.

---

## Architecture & Security Boundaries

### 1. Privilege-Separated `nftables` Helper ([`backend/fw_helper.py`](../backend/fw_helper.py))
- **Pure Python stdlib (`/usr/bin/python3 -I`):** Runs in isolated interpreter mode so privileged execution never imports third-party packages from `.venv` (`scapy`, `joblib`, `sklearn`, `xgboost`, `fastapi`) or user `PYTHONPATH`.
- **Peer credential verification & socket access (`SO_PEERCRED`):** Inspects the connecting Unix domain socket peer UID before parsing requests. Supports `--socket-uid`, `--socket-gid`, `--socket-mode` (`0660`), and `--dir-mode` (`0750`), automatically resolving ownership for a single non-root `--allowed-uid` or `SUDO_UID`/`SUDO_GID` when started under `sudo` (while preserving sticky directories such as `/tmp` and refusing symlinks).
- **Dedicated `nftables` table ownership:** Manages only `table ip securenet` with `set blocked_ips { type ipv4_addr; flags timeout; size <max_blocks>; }` and `chain input { type filter hook input priority filter; policy accept; ip saddr @blocked_ips drop; }`. Unrelated host firewall tables are never flushed or modified.
- **Independent guardrails & lease protection:** Re-validates built-in (`0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, `240.0.0.0/4`) and operator-supplied `--protect` CIDRs, enforces `max_blocks` (default `256`), deduplicates retries via a bounded `op_id` cache, rejects competing `hello` calls while an unexpired lease is active, and requires a matching `lease_id` for explicit `rollback`.
- **Resilient lease watchdog:** Requires periodic `heartbeat` renewals from the unprivileged worker; if the worker crashes or misses its lease deadline, the helper automatically deletes `table ip securenet`, preserving internal tracking and retrying on subsequent ticks if an `nft` deletion temporarily fails.

### 2. Unprivileged Client, Controller & Worker ([`backend/fw_client.py`](../backend/fw_client.py), [`backend/firewall.py`](../backend/firewall.py), [`backend/worker.py`](../backend/worker.py), [`sniffer/main.py`](../sniffer/main.py))
- **Default `dry_run` preserved:** `FirewallController()` defaults to `mode="dry_run"`, `max_blocks=4096`, and zero subprocess/socket activity.
- **Lock-before-lease & fail-stop enforcement:** `ResponseDispatcher` acquires the exclusive `Outbox` lock before starting `FirewallController` so duplicate worker startup cannot touch a healthy lease. When `mode="enforced"`, `FirewallController` requires a `FwHelperClient` and at least one `--protect` CIDR (or `--allow-unprotected-lab` for isolated `netns` testing). Helper errors raise `EnforcementError`, stopping the worker loudly rather than silently downgrading to `dry_run`.
- **Signal-safe shutdown & confirmed reconciliation:** `sniffer.main` handles `SIGTERM` cleanly so `demo_down.sh` triggers orderly dispatcher drain and firewall rollback. On startup and confirmed shutdown rollback in `enforced` mode, `ResponseDispatcher` logs `reconcile` and enqueues `POST /api/sensor/reconcile`; if `nft` rollback fails and `table ip securenet` remains active, `close()` keeps block state intact, withholds rollback reconciliation, and raises `RuntimeError`.

### 3. Backend Wire Contracts, Database & React UI ([`backend/schemas.py`](../backend/schemas.py), [`backend/service.py`](../backend/service.py), [`backend/main.py`](../backend/main.py), [`frontend/src/App.tsx`](../frontend/src/App.tsx))
- **Dual-mode validation:** `BlockIn`, `ProposalIn`, and `FirewallActionIn` validate both `dry_run` (`iptables` proposals) and `enforced` (`nft add/delete element ip securenet blocked_ips ...`) payloads while keeping `BENIGN`, `WEB_ATTACK`, and non-`unified` scopes strictly alert-only.
- **Explicit `ROLLED_BACK` lifecycle state:** `POST /api/sensor/reconcile` transitions non-active enforced blocks for that sensor from `ACTIVE` / `EXPIRY_PENDING` / `UNBLOCK_REQUESTED` to `ROLLED_BACK` and marks any pending `ResponseCommand` rows as `CANCELLED`.
- **Dashboard visibility:** `/api/stats` counts unresolved `ACTIVE`, `EXPIRY_PENDING`, and `UNBLOCK_REQUESTED` rows in `active_blocked_ips` (enforced), `active_simulated_blocks` (dry-run), and `response_mode` (`"dry_run"`, `"enforced"`, or `"mixed"`) until confirmed cleared. The React `Response` view adds the **Rolled back** tab and displays per-block mode metadata.

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

