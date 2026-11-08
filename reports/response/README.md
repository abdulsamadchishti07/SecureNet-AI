# Response integration evidence — 2026-11-08

The first response chunk is a local dry-run implementation. It generates audit
records and simulated firewall state; the controller has no command executor.
The [response guide](../../docs/RESPONSE_ENGINE.md) contains the offline demo,
configuration, storage behavior, revised sprint sequence and remaining gates.

## Verified results

- **243 pytest cases passed**, including 12 sniffer cases. Existing joblib/NumPy
  deserialization deprecation warnings remain visible.
- The six-packet synthetic fixture produced three completed flows through the
  actual saved unified Random Forest, each labelled PORTSCAN with score
  0.9966566177859643.
- The policy produced `alert`, `alert`, `candidate`; the last event yielded one
  `would_block` proposal for `10.10.0.9`.
- All three events were accepted and recorded; no pending, dropped or unlogged
  events remained after shutdown. The event model checksum matched the bundle.
- Tests cover protected ranges, invalid targets, idempotency, bounded transport,
  controlled-clock expiry, worker/disk failure propagation, immutable validated
  events and the final-publish/shutdown race.
- SHA-256 confirms the 89 historical files in the unified preservation baseline,
  plus the unified bundle and split artifact, remain unchanged. No retraining.

Evidence: [verification.json](verification.json) and the exact synthetic
[audit records](demo_events.json). The JUnit report is generated at
`reports/tests/pytest.xml` and ignored by Git.

The replay used:

```bash
.venv/bin/python scripts/create_response_demo.py runtime/response_demo_offline.pcap
.venv/bin/python -m sniffer.main -r runtime/response_demo_offline.pcap \
  --predict --respond --alert-log runtime/response_verified_alerts.jsonl
```

Local runtime outputs:

- `runtime/response_verified_alerts.jsonl`: append-only events and decisions.
- `runtime/response_verified_predictions.jsonl`: stdout flow predictions.
- `runtime/response_verified_summary.log`: stderr queue/response summary.

These are ignored local artifacts. The saved JSON copies above preserve the
reviewable evidence. The generator refuses to overwrite an existing fixture, and
each replay appends to its chosen alert log.

This demonstration does not validate campaign independence, original-PCAP feature
parity, source-IP attribution, calibrated thresholds or active blocking. No actual
network capture, firewall execution, Redis service, HTTP API, database or dashboard
was added. Simulated blocks last only for the lifetime of their process.
