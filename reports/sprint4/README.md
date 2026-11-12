# Sprint 4 verification

Verified 2026-11-12 (Asia/Karachi). [Guide](../../docs/SPRINT_4.md) and
[capture-clock semantics](../../docs/RESPONSE_CALIBRATION.md).

- Final default regression: **376 passed**, 5262 visible dependency deprecation
  warnings, 66.43 seconds. This includes 49 new cases covering comparison,
  ablation, capture clocks/calibration and API delivery. Existing 327 cases remain.
- Three independent arithmetic synthetic flows agree across all 20 features in
  [the comparison](../parity/extraction_parity.json). Matching original captures
  were unavailable. [The smoke](../parity/extraction_smoke.json) has no reference.
- Six real paired RF/XGBoost fits used one seeded 50,000-row training sample,
  complete 416,291-row validation and 416,290-row test sets. See
  [the experimental findings](../ablation/README.md). Training/evaluation took
  80.42 seconds after split loading. No fitted experimental models were saved.
- Actual saved-model capture-time replay: three PORTSCAN detections, two alerts,
  one simulated block proposal; accepted/processed three, zero dropped/pending/
  unlogged. [Events](replay_events.json), [summary](replay_summary.json).
  The simulator reported one virtual block at shutdown; its state was process-local
  and disappeared when the sensor exited. No API forwarding or database insertion.
- [Twelve sensitivity conditions](../response/calibration.json) use predictions
  from synthetic traffic, with no independent truth or false-block estimate.
- All **115** original dataset/split/model/report files remained byte-identical:
  [preservation baseline](preserved_original_files.json). The pre-existing
  `requirements.txt` change is preserved. `pip check`, compilation and diff checks pass.

`runtime/sprint4/` contains ignored PCAP/reference CSV, predictions and audit files.
[The reference arithmetic](synthetic_reference.json) records the supplied expected
values independently of the extractor. The saved model replay uses the existing
`runtime/response_demo_offline.pcap`; the parity fixture uses separate 100-us probes.
Reports include input/code hashes and explicit evidence scope.

Scapy interface enumeration needs sandbox access even for offline use. Regression
and CLI checks were run with that access; no live packets were captured/transmitted
and no host firewall commands were executed. Fixtures use private temporary
SQLite databases, not the configured PostgreSQL installation. Existing services
were not restarted. An already-running API needs a restart to accept new capture
metadata before sensor API forwarding is used.

Original-capture parity, exact source/exporter provenance, independent campaign
coverage, separately labelled calibration/evaluation and isolated-lab enforcement
remain open gates. These synthetic and existing-split experiments do not satisfy
them. No staging, commit or push was performed.
