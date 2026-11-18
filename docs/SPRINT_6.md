# Sprint 6 — Runtime Hardening, Campaign-Disjoint Evaluation & Ground-Truth Calibration

## Overview

Sprint 6 completes runtime inference/authentication hardening (**Chunk 6.1**), documents the external data gate for original CIC-IDS2017 PCAP parity (**Chunk 6.2**), and delivers reproducible campaign-disjoint multi-host lab evaluation and ground-truth event-time policy calibration (**Chunks 6.3–6.4**).

---

## Chunk 6.1 — Runtime Inference, Integrity & Auth Hardening

- **Pre-Deserialization Model Integrity ([`ml_engine/predictor.py`](../ml_engine/predictor.py), [`ml_engine/models/manifest.json`](../ml_engine/models/manifest.json)):** `_load_model()` verifies the bundle's SHA-256 against `expected_sha256`, `SECURENET_MODEL_SHA256`, or `ml_engine/models/manifest.json` **before** calling `joblib.load()`, failing closed if `manifest.json` is missing for repository model bundles.
- **Per-Flow Inference Error Boundary ([`sniffer/main.py`](../sniffer/main.py)):** `on_flow()` catches unexpected `Exception` failures alongside `FeatureValidationError`, tracks `inference_errors`, and skips malformed/failing flows without aborting packet capture.
- **Login Brute-Force Rate Limiting ([`backend/auth.py`](../backend/auth.py), [`backend/main.py`](../backend/main.py)):** Bounded stdlib `LoginRateLimiter` enforces sliding-window limits on `POST /api/auth/login` (5 failures / 60s per `(client_ip, username)`, 20 failures / 60s per `client_ip`), returning HTTP `429` with `Retry-After` and resetting per-user failures on valid login.

---

## Chunk 6.2 — Original-Capture Parity Gate

Original CIC-IDS2017 PCAPs and pinned reference CSVs with full UTC timestamps are not present in the repository. Consequently, CICFlowMeter feature parity remains externally gated on supplying those inputs to [`scripts/evaluate_pcap_parity.py`](../scripts/evaluate_pcap_parity.py) (see [`docs/SPRINT_4.md`](SPRINT_4.md)).

---

## Chunk 6.3 — Campaign-Disjoint Lab Evaluation & Port Ablation

[`scripts/generate_lab_campaigns.py`](../scripts/generate_lab_campaigns.py) synthesizes three endpoint-disjoint multi-host PCAP campaigns (`train`: `10.201.x.x`, `calibration`: `10.202.x.x`, `evaluation`: `10.203.x.x`) covering `BENIGN` (HTTP + DNS + SSH), `PORTSCAN`, `DOS`, and `BRUTE_FORCE` with **zero shared `(src_ip, dst_ip)` endpoint pairs** across partitions (14 pairs per partition).

Results saved in [`reports/ablation/campaign_disjoint/README.md`](../reports/ablation/campaign_disjoint/README.md) and [`reports/ablation/campaign_disjoint/port_ablation.json`](../reports/ablation/campaign_disjoint/port_ablation.json):

| Condition | Model | Features | Eval Macro F1 | Eval Benign FPR |
| --- | --- | ---: | ---: | ---: |
| `full` | `random_forest` / `xgboost` | 20 | 100.0000% | 0.0000% |
| `no_source_port` | `random_forest` / `xgboost` | 19 | 100.0000% | 0.0000% |
| `no_ports` | `random_forest` / `xgboost` | 18 | 100.0000% | 0.0000% |

---

## Chunk 6.4 — Ground-Truth Policy Calibration & Held-Out Evaluation

Replaying the independent calibration cohort (`calibration.pcap`) through `sniffer.main --predict --respond --clock-mode event_time` using the untouched CIC-IDS2017 `unified_v1` model and sweeping thresholds in [`sniffer/calibration.py`](../sniffer/calibration.py) (`--truth`) selected `confidence=0.5`, `min_flows=2`, `window_seconds=10` ([`reports/response/lab_calibration.json`](../reports/response/lab_calibration.json)).

Single held-out evaluation on `evaluation.pcap` ([`reports/response/lab_heldout_eval.json`](../reports/response/lab_heldout_eval.json)):
- **Benign-triggered false block candidates:** `0`
- **Pre-onset candidates / late rejected events:** `0` / `0`
- **Detected attack sources:** `10.203.2.10`, `10.203.2.11` (`PORTSCAN`, delay `0.38s–0.40s`) and `10.203.4.10`, `10.203.4.11` (`BRUTE_FORCE`, delay `0.64s–0.72s`)
- **Missed attack sources (`sources_without_candidate`):** `10.203.3.10`, `10.203.3.11` (`DOS` — illustrating cross-domain shift between synthetic lab DoS bursts and CIC-IDS2017 `DOS` training patterns)

---

## Interpretation and reproducibility

The three campaigns use different endpoints but the same synthetic traffic
generator. This establishes endpoint separation, not independence from generator
patterns or real attack campaigns. The 100% ablation scores belong to newly fitted
lab classifiers; the serving `unified_v1` bundle was not replaced. Zero observed
false blocks in this small synthetic cohort is not a population false-positive
bound. Replay delays above use capture availability and can include EOF flushing;
they are not measured live kernel mitigation latencies. Runtime defaults remain
`confidence=0.90`, `min_flows=3`, `window_seconds=60`.

Regenerate into explicit disposable work/report directories with
`scripts/generate_lab_campaigns.py --help`; its default report paths overwrite
saved reports. Do not regenerate historical evidence merely to inspect it.

## Evidence Scope Summary

| Evidence Tier | Scope & Claim | Reference |
| --- | --- | --- |
| Within-capture ML (`unified_v1`) | 7-class CIC-IDS2017 RF baseline (endpoint pairs shared across splits) | [`reports/unified/README.md`](../reports/unified/README.md) |
| Synthetic & `netns` enforcement | Real kernel `nftables` drops, manual unblock, `SIGKILL` lease watchdog, DB reconciliation | [`docs/SPRINT_5.md`](SPRINT_5.md) |
| Campaign-disjoint lab & calibration | Zero endpoint overlap across partitions; ground-truth calibration & cross-domain diagnostic | [`reports/ablation/campaign_disjoint/README.md`](../reports/ablation/campaign_disjoint/README.md) |
