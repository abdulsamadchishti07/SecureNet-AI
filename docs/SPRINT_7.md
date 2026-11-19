# Sprint 7 — live lab, notifications and defense package

Sprint 6 was landed in commit `912aeee`. Sprint 7 added the bounded live socket
lab, optional notifications in the response worker and the FYP defense package.
Sprint 8 subsequently resolved the live capture buffer loss (`conf.bufsize` 64 KB
-> 4 MB), single-pass `n_jobs=1` RF inference + `0.2s` live sweep, outbox
inter-message throttle, stale pre-unblock flow re-blocking, and bounded cross-flow
burst rules (`rule:auth_burst`, `rule:service_flood`), bringing strict 3-vector
isolated lab acceptance (`--require-all-detected`) to `status: ok` (exit `0`)
while keeping raw ML `event.label` predictions unaltered.

## Three-vector lab

From the repository root:

```bash
./scripts/netns_multi_attack_lab.sh
# Acceptance mode: exit 2 if any vector is missed or misclassified.
./scripts/netns_multi_attack_lab.sh --require-all-detected
```

The launcher always enters a fresh sensor network namespace. Normal users need
unprivileged user namespaces; otherwise run `sudo ./scripts/netns_multi_attack_lab.sh`.
Linux `ip`, `nft`, `ping`, `nsenter`, `unshare`, the project virtual environment,
libpcap/BPF support and the installed manifest-verified unified model are required.
The Python harness refuses an existing namespace with non-loopback interfaces;
its internal traffic commands require the dedicated attacker interface.

The lab creates one private veth pair, a separate attacker namespace, a temporary
SQLite API and a helper. It supplies ephemeral credentials and disables external
notifications. No default route is added. Targets are fixed to `10.210.0.1`:
11 closed TCP ports (`8080–8090`), 30 FTP-style login sessions on port 21 and
200 bounded HTTP flood attempts on port 80 (four workers). These simulate vectors;
they do not exercise an actual SSH password verifier or establish DoS saturation.

Each source must reach a separate echo port and ICMP before its scenario. A
successful block needs an audited helper success, kernel set membership, failed
TCP and ICMP probes, exact block-UUID API unblock and restored traffic. A separate
scan verifies SIGKILL watchdog rollback, startup DB reconciliation and SIGTERM
exit 0. Processes, sockets and temporary state are removed on completion or error.

Results are written to [the JSON report](../reports/sprint7/multi_attack_lab.json).
`--output PATH` selects another report; the default overwrites the last run.
`--scenario-seconds 3..30` changes the observation window. Exit 1 means a harness
or recovery error; exit 0 means all checks ran, possibly with detection gaps;
strict acceptance returns 2 for those gaps. `status` and each scenario's result
are the evidence, not the process exit alone.

Latency uses an attacker-process monotonic timestamp immediately before traffic
and the first failed echo probe confirmed by an audited block. It includes model,
flow finalization, queueing, polling and TCP timeout. It is an upper bound for the
first observed loss, not exact kernel installation time. Misses have JSON `null`
latency. Incomplete long-lived flows can outlast the observation window; emitted
flow counts are reported. Neither throughput capacity nor a latency percentile
can be inferred from this small run.

The lab explicitly uses the Sprint 6 exploratory policy (confidence 0.5, two
flows, 10s window) and 0.1s termination grace. Serving defaults remain 0.90,
three flows, 60s and 5s grace. Predictions use the unchanged serving model;
scenario truth labels are never substituted into events.

## Notifications

[backend/notifier.py](../backend/notifier.py) runs a separate bounded queue/thread
owned by `ResponseDispatcher`, in the **sensor process**. Configuring only an API
container does not activate it. `backend/.env` is loaded for local sensor startup;
explicit sensor environment variables override it. A sensor launched with a
clean environment must receive its notification settings explicitly.

Defaults and limits:

| Setting | Default | Meaning |
| --- | --- | --- |
| `ALERT_NOTIFICATIONS_ENABLED` | `false` | Explicit opt-in |
| `ALERT_INCLUDE_DRY_RUN` | `false` | Include clearly marked simulated new blocks |
| `ALERT_COOLDOWN_SECONDS` | `600` | Per-IP cooldown; accepts 600..86400 |
| `ALERT_MAX_PER_HOUR` | `30` | Sliding hourly limit; accepts 1..30 |
| `ALERT_QUEUE_SIZE` | `64` | Non-blocking queue; accepts 1..1024 |
| `SMTP_HOST`, `SMTP_SENDER`, `ALERT_EMAIL_RECIPIENT` | empty | Complete all three to enable email |
| `SMTP_PORT`, `SMTP_SECURITY` | `587`, `starttls` | `starttls`, `ssl`, or loopback-only `plain` |
| `SMTP_USER`, `SMTP_PASSWORD` | empty | Set both or neither |
| `ALERT_WEBHOOK_URL` | empty | HTTPS; HTTP permitted only on loopback |
| `ALERT_WEBHOOK_FORMAT` | `generic` | `generic`, `slack` (`text`), `discord` (`content`) |

Only a new `blocked` helper acknowledgement or an explicitly included
`would_block` simulation is eligible. Protected/capacity-rejected actions,
repeated existing blocks and policy-only candidates do not notify. Messages
contain mode, test flag, source, threat, sensor, event/block UUID and observation
time; they do not contain packet payloads, credentials or feature vectors.

The worker applies limits immediately before sending. Failed attempts consume
quota, block UUIDs are deduplicated for at least one hour, and active cooldowns
are never evicted to admit more keys. One logical alert can attempt both channels;
each channel remains within the configured logical-alert budget. Channel failures
are isolated, use bounded socket timeouts and produce sanitized warnings. There
are no automatic retries; redirects and ambient HTTP proxies are disabled.
With notifications enabled and no channels configured, throttled log-only output
is used and counted separately from deliveries.

Notifications are best effort and held in memory. Restart resets cooldowns and
quotas; crashes lose queued notifications. They are separate from the durable API
outbox. Shutdown attempts a two-second drain after firewall rollback; queued work
is discarded on timeout, and an in-flight daemon attempt may finish. Stats expose
`queued`, channel `sent`/`failed`, `logged`, `suppressed`, `dropped`, `abandoned`,
`pending` and `in_flight` in the response summary. This is one sensor's budget;
multiple sensor processes do not share a global quota.

Preview without network or DB access:

```bash
.venv/bin/python -m backend.manage test-alert-notification
```

After configuring a chosen channel in the sensor environment, explicitly send
a clearly marked synthetic test:

```bash
ALERT_NOTIFICATIONS_ENABLED=true .venv/bin/python -m backend.manage test-alert-notification --send
```

The CLI returns nonzero for failed, incomplete or abandoned delivery. `logged`
means log-only, not externally delivered. Verify an email in the recipient inbox
or a webhook in the receiver; a successful socket exchange alone does not prove
human receipt. No external delivery was enabled during Sprint 7 verification.

## Defense artifacts and verification

- [FYP defense guide](FYP_DEFENSE.md) and [slide source](FYP_SLIDES.md).
- [SVG/PDF figures](assets/fyp/manifest.json), derived directly from saved reports.
- Regenerate figures with `.venv/bin/python scripts/build_fyp_assets.py` after a lab rerun.
- [Verification record](../reports/sprint7/verification.json) records actual runs and limits.

```bash
.venv/bin/python -m pytest tests/ -q
.venv/bin/python -m pytest browser_tests/ -q
```

Tests use private DBs and local HTTP/SMTP receivers, with external notification
settings disabled by fixtures. Existing dependency deprecation warnings are not
hidden. Original-capture parity, independent real attack data, live brute-force
and DoS recall, and population false-block rates remain open evidence gates.
