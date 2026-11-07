# Thursday baseline — 2026-11-07

**Interpretation correction (2026-11-07):** each web family has one endpoint pair
shared across train/validation/test. Attempted targets and web subtype coverage
remain unvalidated. See the [validity review](../../docs/ML%20Engine/VALIDITY_REVIEW.md).
Original metric files and model artifacts are unchanged by this note.

Completed Thursday preprocessing, training and held-out evaluation. This is a
separate four-class baseline; it does not replace or combine with Friday's model.

## Label policy and cleaning

| Final class | Retained flows | Retained connection groups |
| --- | ---: | ---: |
| BENIGN | 286,134 | 191,882 |
| PORTSCAN | 68,609 | 64,742 |
| WEB_BRUTE_FORCE | 1,365 | 1,363 |
| WEB_XSS | 673 | 673 |

`Infiltration - Portscan` maps to PORTSCAN. Web brute-force and XSS labels each
include their Attempted variants. Original labels and the attempted flag are
retained as metadata, never classifier inputs. These are attack-family labels,
not confirmation of successful compromise.

From 362,075 source rows:

- Excluded 99 scarce-class rows: Infiltration 36, Infiltration - Attempted 45,
  Web Attack - SQL Injection 13, and its Attempted variant 5.
- Removed 5,191 same-label feature duplicates and four conflicting-label rows.
- Found no invalid numeric rows or duplicate headers.
- Retained 356,781 original flows in 258,451 total connection groups. Some
  connections contain more than one family, so per-class group counts overlap.

## Split and training

| Partition | Original flows | Connection groups |
| --- | ---: | ---: |
| Training | 214,068 | 155,073 |
| Validation | 71,357 | 51,690 |
| Test | 71,356 | 51,688 |

Used stratified connection groups based on bidirectional IP/port endpoints and
protocol. Verified zero overlapping row IDs, connections and feature vectors
between partitions. Every saved split feature row matches its original source
row. IPs and original labels are excluded from the 20 model features.

Scaler and label encoder were fitted on training only. Both models use balanced
training class weights, with no undersampling, SMOTE or synthetic examples.

| Model | Validation macro F1 | Validation benign false-positive rate |
| --- | ---: | ---: |
| Random Forest | 67.6609% | 1.8488% |
| XGBoost | 71.1635% | 1.0712% |

Selected XGBoost on validation macro F1 before accessing test metrics. No tuning
was performed after evaluating this test partition.

## Held-out results and interpretation

| Test metric | Result |
| --- | ---: |
| Accuracy | 99.0064% |
| Macro F1 | 70.9019% |
| Benign false-positive rate | 1.0205% |
| Errors / original flows | 709 / 71,356 |

| Class | Precision | Recall | F1 | Test examples |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 99.89% | 98.98% | 99.43% | 57,227 |
| PORTSCAN | 99.90% | 99.96% | 99.93% | 13,722 |
| WEB_BRUTE_FORCE | 32.89% | 73.26% | 45.40% | 273 |
| WEB_XSS | 27.71% | 64.93% | 38.84% | 134 |

Overall accuracy hides poor web-class precision. Of 57,227 benign test flows,
584 were flagged as attacks: 376 WEB_BRUTE_FORCE, 194 WEB_XSS and 14 PORTSCAN.
Web families are also confused with each other (33 brute-force examples predicted
XSS; 32 XSS examples predicted brute force). This baseline needs further work
before relying on its web-family predictions.

Web support is dominated by attempted labels. The test set has 259 attempted and
14 base-label brute-force examples, plus 130 attempted and four base-label XSS
examples. All 18 base-label web examples were classified correctly, but this
sample is much too small to establish reliable performance on that subgroup.
`evaluation.json` records the subgroup counts and predictions explicitly.

This is within-Thursday connection-group evaluation. Hosts/campaigns may recur
across splits. Timestamps lack full date/hour information, so this is not a
chronological evaluation. Dataset provenance still needs documentation and live
validation remains pending. Excluded families are outside this model's coverage.

## Evidence and usage

- `data_audit.json`: source checksum, label policy, exclusions, cleaning and split counts.
- `training.json`: validation results, parameters, environment, source-code/split checksums.
- `evaluation.json`: full held-out results, confusion matrix and original-label breakdown.
- `confusion_matrix.png`: visual confusion matrix.
- `verification.json`: actual data-isolation, scaler and inference checks.
- `preserved_friday.json`: checksums for 23 Friday artifacts/reports, verified unchanged.
- `tests/test_thursday_pipeline.py`: four new tests; all nine project tests pass.

New artifacts: `ml_engine/models/thursday_v1/inference_bundle.pkl`, with matching
XGBoost/scaler/encoder/schema. Verified Thursday inference on 40 validation flows
and Friday inference on 20 flows in the same process, without cache mixing.

From the project folder, display results with:

```bash
.venv/bin/python -m ml_engine.evaluate --dataset thursday
xdg-open reports/thursday/confusion_matrix.png
```

Programmatic inference: `predict(features, dataset="thursday")`. Default inference
and commands still select Friday. No combined classifier or live service was built.

Next resolve provenance, Attempted target semantics, independent evaluation and
matching-capture feature parity as described in the validity review. Do not tune
against these observed test scores. A later unified model requires joint cross-day
duplicate/campaign handling and independent evidence.
