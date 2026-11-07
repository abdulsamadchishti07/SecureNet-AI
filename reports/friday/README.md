# Friday corrected baseline — 2026-11-07

**Interpretation correction (2026-11-07):** these are exploratory within-capture,
connection-held-out scores, not evidence of independent-campaign or live detection.
See the [validity review](../../docs/ML%20Engine/VALIDITY_REVIEW.md).
Original metric files and model artifacts are unchanged by this note.

Completed preprocessing, training and held-out evaluation using the local Friday
dataset. The earlier artifacts remain unchanged in `ml_engine/models/`; the
corrected artifacts are in `ml_engine/models/friday_v2/`.

## Data isolation

| Partition | Original flows | Connection groups |
| --- | ---: | ---: |
| Training | 327,283 | 237,756 |
| Validation | 109,094 | 79,253 |
| Test | 109,094 | 79,254 |

Removed 2,086 repeated feature vectors from 547,557 raw flows. No invalid or
conflicting-label rows were found. Connections use canonical bidirectional
IP/port endpoints plus protocol. IP identities are not classifier inputs.

There are zero shared row IDs, connection groups or feature vectors between
partitions. Scaling uses training rows only; class balancing uses training-only
weights. No undersampling, SMOTE or synthetic rows were used.

## Model selection and results

| Model | Validation macro F1 | Validation benign false-positive rate |
| --- | ---: | ---: |
| Random Forest | 99.9295% | 0.0314% |
| XGBoost | 99.9625% | 0.0192% |

Selected XGBoost using validation macro F1, then evaluated it on the untouched test
set. The test set did not determine the winner.

| Test metric | Result |
| --- | ---: |
| Accuracy | 99.9890% |
| Macro F1 | 99.9927% |
| Benign false-positive rate | 0.0122% |
| Errors / total flows | 12 / 109,094 |

Seven benign flows were labelled PORTSCAN; five PORTSCAN flows were labelled
BENIGN. BOTNET and DDOS had no errors in this test partition, with 959 and 19,029
examples respectively.

## Verification and evidence

- `data_audit.json`: cleaning counts, source checksum, partition counts and limitations.
- `legacy_baseline.json`: prior artifact checksums and historically leaky metrics.
- `training.json`: validation reports, model parameters, dependency versions,
  code checksums and split artifact checksum.
- `evaluation.json`: selected model's complete held-out test report and confusion matrix.
- `confusion_matrix.png`: test confusion matrix, ordered BENIGN/BOTNET/DDOS/PORTSCAN.
- `verification.json`: actual partition overlap checks, scaler statistics, legacy
  preservation and inference checks.
- `tests/test_friday_pipeline.py`: five passing regression/integration tests.

The predictor uses the selected XGBoost bundle with matching transformations.
Forty validation flows were checked for agreement between single, batch and direct
bundle predictions. Scaler mean and variance match the original training data.

This remains a within-Friday connection-group evaluation. Hosts and attack
campaigns may recur across partitions, and ports can encode dataset-specific
patterns. Timestamps lack full date/hour information, so this is not a temporal
evaluation. Exact source provenance and independent-day/live validation remain
open work. These scores do not establish live blocking readiness.
