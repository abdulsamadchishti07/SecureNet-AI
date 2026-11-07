# Tuesday baseline — 2026-11-07

**Interpretation correction (2026-11-07):** FTP and SSH each have one endpoint pair
shared across train/validation/test. The 99.9984% score does not establish campaign
generalization. See the [validity review](../../docs/ML%20Engine/VALIDITY_REVIEW.md).
Original metric files and model artifacts are unchanged by this note.

Completed preprocessing, training and held-out evaluation using only the local
`dataset/raw/tuesday.csv`. Tuesday is a separate three-class model, not a combined
weekday classifier or a replacement for previous baselines.

## Labels and preparation

| Final class | Raw source labels | Retained original flows | Connection groups |
| --- | --- | ---: | ---: |
| BENIGN | BENIGN | 312,948 | 204,681 |
| FTP_BRUTE_FORCE | FTP-Patator, including Attempted | 3,984 | 3,973 |
| SSH_BRUTE_FORCE | SSH-Patator, including Attempted | 2,988 | 2,979 |

Original labels and attempted status remain metadata and appear in subgroup
evaluation. They are not classifier inputs; a family verdict does not establish
successful authentication or compromise. No source labels were excluded.

The raw CSV has 322,078 rows: 315,106 BENIGN, 3,972 FTP-Patator, 12 FTP-Patator -
Attempted, 2,961 SSH-Patator and 27 SSH-Patator - Attempted. Removed 2,158 duplicate
BENIGN feature rows. Found no conflicting-label rows, invalid numeric rows or
repeated headers. Retained 319,920 original flows in 211,633 connection groups.

| Partition | Original flows | Connection groups |
| --- | ---: | ---: |
| Training | 191,952 | 126,980 |
| Validation | 63,984 | 42,327 |
| Test | 63,984 | 42,326 |

The existing 20-feature schema and stratified bidirectional connection-group
split strategy are unchanged. Verified zero shared row IDs, connections or model
inputs between partitions. Every saved feature row matches its source CSV row.
Fit scaler/encoder on training only; both models use balanced training class
weights. No synthetic rows, SMOTE or undersampling were used.

## Model selection and test results

| Model | Validation macro F1 | Validation benign false-positive rate |
| --- | ---: | ---: |
| Random Forest | 100.0000% | 0.0000% |
| XGBoost | 99.9438% | 0.0032% |

Selected Random Forest using validation macro F1. Test data did not determine
the winner. Evaluated the selected model once, without subsequent tuning.

| Test metric | Result |
| --- | ---: |
| Accuracy | 99.9984% |
| Macro F1 | 99.9718% |
| Benign false-positive rate | 0.0000% (0 / 62,589) |
| Errors / original flows | 1 / 63,984 |

| Class | Precision | Recall | F1 | Test support |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 99.9984% | 100.0000% | 99.9992% | 62,589 |
| FTP_BRUTE_FORCE | 100.0000% | 100.0000% | 100.0000% | 797 |
| SSH_BRUTE_FORCE | 100.0000% | 99.8328% | 99.9163% | 598 |

The single error is a base-label SSH-Patator flow classified BENIGN. All 797 FTP
flows and 62,589 benign flows were classified correctly. The attempted-label test
subgroups contain only three FTP and six SSH examples; their correct predictions
do not establish reliable performance on new attempts.

These are within-Tuesday connection-group results. Hosts/campaigns can recur,
ports may encode dataset-specific patterns, and timestamps lack full date/hour
information. Provenance and independent/live validation remain open. Zero false
positives in this partition does not imply zero live false positives.

## Evidence, preservation and usage

All 20 tests pass (16 ML tests plus four existing sniffer tests). Verified scaler
mean/variance against original training and inference on 30 Tuesday validation
flows. Checked previous models in the same process on 20 Friday, 20 Thursday and
25 Wednesday flows; all four caches remain separate. Checksums verified 59 prior
model/report/processed/sniffer files unchanged.

- `data_audit.json`: source checksum, mappings, support and partition counts.
- `training.json`: validation results, parameters, environment and source/split hashes.
- `evaluation.json`: full held-out metrics and original-label breakdown.
- `verification.json`: data-isolation, source-row, scaler and inference checks.
- `preserved_previous_runs.json`: preservation checksums before Tuesday work.
- `confusion_matrix.png`: ordered BENIGN, FTP_BRUTE_FORCE, SSH_BRUTE_FORCE.

Model bundle: `ml_engine/models/tuesday_v1/inference_bundle.pkl`. Splits:
`dataset/processed/tuesday_splits.pkl`. These runtime files are ignored by Git.

From the project directory:

```bash
.venv/bin/python -m ml_engine.evaluate --dataset tuesday
xdg-open reports/tuesday/confusion_matrix.png
```

Inference: `predict(features, dataset="tuesday")`, with all 20 raw features.
Omitting the dataset, including the existing sniffer CLI's `--predict`, still uses
Friday. Archive the Tuesday models, splits and reports before retraining; the
default preprocessing/training paths refuse overwriting an existing trained run.

See [Tuesday documentation](<../../docs/ML Engine/TUESDAY.md>) for detailed
partition support, limits and next steps. Previous-day performance, including
Thursday's web weaknesses, is unaffected by adding this separate model.
