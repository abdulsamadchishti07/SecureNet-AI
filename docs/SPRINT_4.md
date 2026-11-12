# Sprint 4 implementation and evidence

Implemented 2026-11-12 (Asia/Karachi). Extraction comparison, port sensitivity and
capture-time policy replay are available. The original-capture, independent-data
and response calibration gates remain open; Sprint 5 enforcement is not enabled.

## Differential extraction

```bash
.venv/bin/python scripts/evaluate_pcap_parity.py --pcap matching.pcap \
  --reference reference.csv --reference-exporter 'exporter commit/version' \
  --report reports/parity/new-comparison.json
```

Reference CSVs need all 20 feature columns, `Src IP`/`Dst IP` (dotted IPv4), or the
local reprocessed `Src IP dec`/`Dst IP dec` integer columns. Supply integer
`flow_start_usec` and optionally `flow_end_usec`; otherwise provide explicit
`--timestamp-column`, `--timestamp-format` (strptime with full numeric date and
24-hour time: `%Y %m %d %H %M %S`), and `--timezone` for
naive values. Durations/IAT are microseconds; lengths are transport payload bytes;
rates are per second. Bounds must agree with duration. Nonfinite/negative values,
invalid discrete values and ambiguous/nonexistent local timestamps fail validation.

Local CSV `Timestamp` samples such as `59:50.3` lack date/hour information. They
cannot be safely matched to a PCAP without recovering original full timestamps.
The tool does not infer lost date/hour values. Matching captures, repair history,
reference exporter and exact release checksums still need to be supplied.

Flow identity keeps each port attached to its endpoint and includes protocol.
Direction is checked after unordered endpoint/time matching; reversed orientation
is flagged and never silently corrected. Both start and end must be within
`--time-tolerance-usec` (default 1000). Only mutually unique candidates are accepted.
Overlapping windows remain ambiguous, even if a global optimizer could choose an
assignment. Reports retain candidate/index mappings, unmatched and ambiguous rows,
orientation discrepancies, per-feature mismatch counts and maximum errors.

Counts/ports/protocol/minimum and maximum lengths use exact tolerance by default;
other values use absolute 1e-6 or relative 0.001. A feature fails when both bounds
are exceeded; relative error is `abs(extracted-reference)/(abs(reference)+1e-6)`.
`--tolerances file.json` supplies explicit abs/rel values for all 20 names. Reference
zero values do not hide discrepancies. `agreement` requires a nonempty complete
bijection, correct orientation and no feature discrepancies. It only describes the
supplied pair, not the provenance or validity of that reference.

Without `--reference`, output is `extraction_only`. `--export-flows path.csv`
exports normalized extracted records for inspection; an export from this extractor
is not independent ground truth. Reports include input/code hashes, timing options
and extraction diagnostics for packets, exclusions and late packets after emission.
Existing outputs are protected against overwrite.

[The saved comparison](../reports/parity/extraction_parity.json) uses three
independently hand-calculated synthetic SYN/RST flows. All 20 features agree. It
verifies the tool and simple formulas, not CICFlowMeter parity on original captures.
[The no-reference smoke](../reports/parity/extraction_smoke.json) explicitly makes
no parity claim. Inputs remain under ignored `runtime/sprint4/`.

## Paired port sensitivity

```bash
.venv/bin/python -m ml_engine.ablation --sample-size 50000 --workers 2 \
  --output reports/ablation/new-run/port_ablation.json
```

One deterministic class-covering training sample is reused across full 20-feature,
no-source-port 19-feature and no-ports 18-feature conditions. Validation and test
retain their complete frozen partitions. Label/scaler transforms and class weights
use only the sampled training rows. RF and XGBoost use matched fixed seeds and
hyperparameters, with at most two workers each. There is no test-based selection.
The tool verifies row/group disjointness and preserves original splits/models.

[The completed experiment](../reports/ablation/README.md) uses 50,000 training rows
and all 416,291 validation / 416,290 test rows. It saves per-class recall/F1,
accuracy, macro F1, benign FPR, confusion matrices, deltas, input/code hashes,
training transform statistics and exact sampled provenance. It saves no fitted
models, so experimental feature counts cannot replace the 20-feature serving bundle.
Outputs are confined to fresh locations under `reports/ablation/`.

| Condition | RF test macro F1 | XGBoost test macro F1 |
| --- | ---: | ---: |
| 20 features | 98.6988% | 99.1877% |
| Without source port | 98.9398% | 99.4323% |
| Without either port | 96.8183% | 97.0553% |

Source-port removal raises macro F1 by 0.2410 / 0.2446 percentage points for
RF / XGBoost, while benign FPR changes from 0.1643% to 0.1687% for RF and from
0.0763% to 0.1263% for XGBoost. Dropping both ports reduces macro F1 and increases
benign FPR. This is a one-seed exploratory sensitivity measurement on previously
observed, correlated partitions with a sampled training cohort. It neither proves the cause of earlier scores nor
establishes campaign independence. Independent campaigns and limited web coverage
remain unresolved.

## Capture-time policy sensitivity

[The calibration guide](RESPONSE_CALIBRATION.md) documents capture bounds,
feature availability, watermark/late-event behavior, separate processing time and
runtime monotonic firewall lifetimes. [The saved sensitivity report](../reports/response/calibration.json)
contains twelve threshold/count/window conditions on the existing three-flow
synthetic replay using the saved unified model. Predictions serve as labels;
there is no independent truth or false-block-rate estimate. The default replay
produces two alerts and one simulated proposal with complete capture timing.

Regression and CLI verification details are in [Sprint 4 evidence](../reports/sprint4/README.md).
Original datasets, splits, models and historical report files are checked against
a SHA-256 baseline. No application database migration, model replacement, live
capture, API event insertion, real firewall action, staging, commit or push is part
of this sprint.
