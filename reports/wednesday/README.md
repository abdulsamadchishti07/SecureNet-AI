# Wednesday baseline — 2026-11-07

**Interpretation correction (2026-11-07):** every DoS family has one endpoint pair
shared across train/validation/test. These scores do not establish campaign
generalization. See the [validity review](../../docs/ML%20Engine/VALIDITY_REVIEW.md).
Original metric files and model artifacts are unchanged by this note.

Completed preprocessing, training and held-out evaluation using only the local
`dataset/raw/wednesday.csv`. Wednesday is a separate five-class model. It does
not replace Friday/Thursday or provide a combined weekday classifier.

## Labels and preparation

| Final class | Retained original flows | Connection groups containing the class |
| --- | ---: | ---: |
| BENIGN | 317,045 | 212,655 |
| DOS_GOLDENEYE | 7,647 | 7,574 |
| DOS_HULK | 159,049 | 14,108 |
| DOS_SLOWHTTPTEST | 5,108 | 4,215 |
| DOS_SLOWLORIS | 5,679 | 3,869 |

Each DoS family merges its base and Attempted source labels. Original labels and
attempted status remain metadata, not classifier inputs. Classification denotes
a traffic family, not proof that a victim was compromised.

The raw CSV has 496,640 rows. Excluded all 11 Heartbleed rows explicitly: they
belong to one connection group and cannot support independent grouped partitions.
Removed 2,101 same-label feature duplicates; found no conflicting-label rows,
invalid numeric rows or repeated headers. Retained 494,528 original flows in
226,691 connection groups. Per-class group counts overlap because a connection
can contain multiple classes.

| Partition | Original flows | Connection groups |
| --- | ---: | ---: |
| Training | 296,712 | 136,014 |
| Validation | 98,909 | 45,338 |
| Test | 98,907 | 45,339 |

Used the existing 20 features and deterministic stratified connection-group
splitting. Original rows, connections and identical model inputs have zero overlap
across partitions. Every saved split feature row matches the original source CSV.
Scaler/encoder were fitted only on training. Both models use training-only class
weights; no SMOTE, synthetic rows or undersampling were used.

## Selection and held-out results

| Model | Validation macro F1 | Validation benign false-positive rate |
| --- | ---: | ---: |
| Random Forest | 99.8364% | 0.0063% |
| XGBoost | 99.8719% | 0.0095% |

Selected XGBoost using validation macro F1. Random Forest had a slightly lower
validation benign false-positive rate, but macro F1 was the selection criterion.
Evaluated the selected model on test after selection, without subsequent tuning.

| Test metric | Result |
| --- | ---: |
| Accuracy | 99.9808% |
| Macro F1 | 99.8634% |
| Benign false-positive rate | 0.0158% |
| Errors / original flows | 19 / 98,907 |

| Class | Precision | Recall | F1 | Test support |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 99.99% | 99.98% | 99.99% | 63,409 |
| DOS_GOLDENEYE | 99.74% | 99.80% | 99.77% | 1,529 |
| DOS_HULK | 99.98% | 99.99% | 99.99% | 31,811 |
| DOS_SLOWHTTPTEST | 99.61% | 99.71% | 99.66% | 1,022 |
| DOS_SLOWLORIS | 99.91% | 99.91% | 99.91% | 1,136 |

Errors consist of 10 benign flows flagged as attacks, four attacks labelled BENIGN
(three Slowhttptest, one Slowloris), and five cross-family errors (three GoldenEye
predicted Hulk, one Hulk predicted GoldenEye and one Hulk predicted Slowhttptest).

Original-label results are recorded separately. GoldenEye - Attempted had 14/17
correct family predictions; its three errors were classified Hulk. Strong aggregate
scores should not conceal such small-subgroup limitations.

These are within-Wednesday connection-group results. Hosts/campaigns can recur
across splits, timestamp strings lack full date/hour information, and ports may
encode dataset-specific patterns. Provenance and independent/live validation
remain open. Heartbleed is outside coverage; Friday's DDOS is a distinct label.

## Verification and usage

All 17 tests pass (13 ML tests plus four existing sniffer tests). Verified saved
scaler mean/variance against original training rows, Wednesday inference on 50
validation flows, and Friday/Thursday inference on 20 each in one process. Model
caches stay separate. Checksums verified 44 prior artifacts/reports/processed
files/sniffer source files unchanged.

- `data_audit.json`: source checksum, label policy, exclusions and partition counts.
- `training.json`: parameters, environment, code/split hashes and validation reports.
- `evaluation.json`: held-out metrics, confusion matrix and original-label breakdown.
- `verification.json`: actual isolation, source-row, scaler and inference checks.
- `preserved_previous_runs.json`: preservation checksums before Wednesday work.
- `confusion_matrix.png`: ordered BENIGN, DOS_GOLDENEYE, DOS_HULK,
  DOS_SLOWHTTPTEST, DOS_SLOWLORIS.

Model bundle: `ml_engine/models/wednesday_v1/inference_bundle.pkl`. Splits:
`dataset/processed/wednesday_splits.pkl`. Both are ignored by Git.

From the project directory:

```bash
.venv/bin/python -m ml_engine.evaluate --dataset wednesday
xdg-open reports/wednesday/confusion_matrix.png
```

Programmatic inference uses `predict(features, dataset="wednesday")`; supply all
20 raw feature values. Friday remains the default, including the existing sniffer
CLI's `--predict`. Do not select a day based on a predicted attack: a combined
classifier requires a future joint training and cross-day splitting pass.

Training and default Wednesday preprocessing refuse to overwrite an existing
trained Wednesday run. Archive its models, splits and reports before retraining.
Do not repeatedly tune against the already-observed test metrics.

See [Wednesday documentation](<../../docs/ML Engine/WEDNESDAY.md>) for the source
label counts, partition support and next steps.
