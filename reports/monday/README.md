# Monday normal-traffic reference — 2026-11-07

Monday contains only source-labelled BENIGN traffic. It was prepared as a normal
reference and used to measure saved models' false alarms. No Monday classifier,
scaler or label encoder was fitted; no previous model was retrained or selected
using Monday results. Attack recall, attack precision and multiclass F1 are not
measurable from this normal-only reference.

## Data and overlap controls

- Raw: 371,621 BENIGN rows; no attack labels.
- Removed 2,024 repeated feature vectors; no invalid numeric rows, conflicting
  labels, deliberate label exclusions or repeated headers.
- Clean reference: 369,597 original flows in 249,108 connection groups.
- Same 20 raw features as the existing weekday classifiers. No synthetic samples
  or train/validation/test partitions were generated for Monday.

The full-reference measurements can include examples/connections seen in previous
weekday runs. A second, common evaluation cohort excludes any Monday row whose
normalized numeric feature vector OR canonical bidirectional IP/port/protocol key
matches any prior train, validation or test partition across all four saved models.

| Common-cohort accounting | Flows |
| --- | ---: |
| Clean Monday reference | 369,597 |
| Feature-vector overlap with previous runs | 1,582 |
| Connection-key overlap with previous runs | 179,945 |
| Union excluded (overlap categories intersect) | 180,318 |
| Same eligible cohort for all four models | 189,279 |

Connection keys omit dates. A key reused on another day may represent a different
physical connection; these exclusions are intentionally conservative. The strict
cohort is a filtered population, not a representative random sample or proof of
independent hosts/campaigns. Numeric fingerprints normalize types and signed zero.
Source/reference checksums, overlap counts and eligible row IDs are preserved.

## False-alarm results

| Saved model | Selected classifier | Full FP / 369,597 | Full FPR | Common FP / 189,279 | Common FPR |
| --- | --- | ---: | ---: | ---: | ---: |
| Friday | XGBoost | 57 | 0.0154% | 57 | 0.0301% |
| Thursday | XGBoost | 3,208 | 0.8680% | 3,154 | 1.6663% |
| Wednesday | XGBoost | 148 | 0.0400% | 147 | 0.0777% |
| Tuesday | Random Forest | 0 | 0.0000% | 0 | 0.0000% |

Common-cohort false-positive predictions:

- Friday: 55 BOTNET, two DDOS.
- Thursday: 103 PORTSCAN, 2,059 WEB_BRUTE_FORCE, 992 WEB_XSS.
- Wednesday: 26 DOS_GOLDENEYE, 46 DOS_HULK, 21 DOS_SLOWHTTPTEST, 54 DOS_SLOWLORIS.
- Tuesday: none.

Thursday again has substantial web-family false alarms. Full and common rates
have different denominators/populations; changing the cohort does not change a
model. Tuesday's zero observed false alarms does not establish a universally best
classifier: the models cover different attack families, Monday contains no attack
examples, and zero observed false positives does not guarantee zero live ones.
All results assume the source BENIGN annotations are correct.

## Artifacts and verification

- `data_audit.json`: cleaning counts, role, source checksum, code hashes and environment.
- `false_alarm_evaluation.json`: cohort policy, per-model prior exposure, bundle/split
  checksums, full/common false alarms and predicted-label distributions.
- `verification.json`: original-row, fingerprint/cohort, arithmetic, API and preservation checks.
- `preserved_previous_runs.json`: checksums for 74 previous files, verified unchanged.
- `dataset/processed/cleaned_monday.csv`: raw-valued cleaned normal reference.
- `dataset/processed/monday_reference.pkl`: reference rows, identities/fingerprints and audit.
- `dataset/processed/monday_common_cohort.pkl`: eligible original row IDs and reference checksum.

There is no `monday_splits.pkl` or Monday model bundle. Monday is intentionally
absent from the supervised `--dataset` registry. All 23 tests pass (19 ML/reference
tests plus four sniffer tests), including checks that Monday evaluation never calls
model/scaler fitting, overlap exclusions are shared across compared models and
empty cohorts report an undefined rate rather than a misleading zero.

## Viewing and rerunning

Read this report or the saved JSON without changing any outputs. To recompute
Monday false-alarm results from the saved reference:

```bash
.venv/bin/python -m ml_engine.monday --evaluate-only
```

This reuses all four saved classifiers and rewrites only Monday evaluation/cohort
outputs. The default model list defines this report's shared cohort; a custom
`--models` list changes the cohort and must not be compared as though identical.

Preparation is already complete. After archiving Monday data/reports, a fresh
reference preparation and evaluation uses `python -m ml_engine.monday` with the
project `.venv` interpreter. `--prepare-only` skips model evaluation. Preparation
refuses to overwrite an existing reference artifact.

See [Monday documentation](<../../docs/ML Engine/MONDAY.md>). Future combined-model
work must split/group the original days jointly and use fresh evaluation data
where needed. Do not call this observed Monday reference an untouched holdout
after later training on it. No combined model or live deployment was performed.
