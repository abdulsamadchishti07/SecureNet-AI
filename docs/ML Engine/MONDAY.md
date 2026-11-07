# SecureNet AI — Monday normal-reference evaluation

Completed: 2026-11-07 (Asia/Karachi).

## Why Monday has a different workflow

The actual local `dataset/raw/monday.csv` has 371,621 rows, all labelled BENIGN.
An intrusion classifier trained solely on that label would not learn the attack
classes. Monday was therefore prepared as normal reference data, and existing
weekday models were evaluated on it for false alarms. No model selection, model
training, scaler fitting or encoder fitting used Monday.

Only the base CSV was used; `monday_plus.csv` was not combined. Monday remains
outside the supervised model registry. Use `ml_engine.monday`, not
`ml_engine.train --dataset monday` or `ml_engine.evaluate --dataset monday`.

## Implementation and preparation

Added [monday.py](../../ml_engine/monday.py) for reference preparation,
previous-exposure checks, saved-model inference and false-alarm reports. The shared
`clean_data` function now accepts an explicit dataset configuration so Monday can
reuse cleaning without becoming a supervised model option. Its existing default
weekday behavior is unchanged.

Cleaning removed 2,024 duplicate feature vectors. No invalid numeric rows,
conflicting labels, repeated headers or deliberate label exclusions were found.
The prepared reference has 369,597 original flows in 249,108 bidirectional
IP/port/protocol connection groups. The original raw file was preserved.

The same 20 model features are used, with no synthetic samples or undersampling.
Original row IDs, local group IDs and comparable feature/connection fingerprints
are metadata only. Reference values remain raw; each saved classifier's original
scaler transforms them during inference. No Monday train/validation/test split or
classifier artifact was created.

## Cross-day overlap and common cohort

The saved Friday, Thursday, Wednesday and Tuesday artifacts each have their own
local group numbering. Those numeric IDs cannot be compared across files.
Monday evaluation reconstructs canonical connection keys from each original raw
CSV and split row IDs, then computes comparable fingerprints. Feature fingerprints
normalize numeric dtypes and signed zero across files.

Every previous run's train, validation AND test partitions are considered. Raw
source and split checksums are checked against the saved metadata before exposure
is reconstructed. Model identity, schema, feature count and encoder classes are
also validated. Existing model/scaler objects are applied without fitting.

Two views are reported:

1. **Full cleaned reference:** all 369,597 unique Monday feature rows. This view
   can overlap previous runs and must not be described as overlap-free evaluation.
2. **Common restricted cohort:** exclude a row if its numeric feature vector or
   canonical connection key appears in any partition of any of the four saved
   runs. All four models then use exactly the same remaining rows.

| Accounting | Rows |
| --- | ---: |
| Full cleaned Monday reference | 369,597 |
| Matching feature vectors across earlier runs | 1,582 |
| Matching canonical connections across earlier runs | 179,945 |
| Union excluded | 180,318 |
| Common eligible rows | 189,279 |

Overlap categories intersect; their counts must not be added. Eligible raw row
IDs, a cohort checksum, a reference checksum and per-model exposure counts are
saved so the comparison population can be reproduced.

Connection keys have no date. Reused endpoints/ports on different days may be
different physical connections. The exclusion policy is conservative and changes
the population substantially; it does not establish independent hosts, campaigns,
chronology or live traffic. Similar nonidentical inputs can still exist.

## Measured false positives

All reference labels are BENIGN, so a predicted attack label is a false positive
under those source annotations. The denominator is the relevant cohort's flow
count. Attack recall, attack precision and multiclass F1 are not measured: there
are no attack-labelled examples with which to assess detection.

| Saved weekday model | Classifier | Full false alarms | Full FPR | Common false alarms | Common FPR |
| --- | --- | ---: | ---: | ---: | ---: |
| Friday | XGBoost | 57 / 369,597 | 0.0154% | 57 / 189,279 | 0.0301% |
| Thursday | XGBoost | 3,208 / 369,597 | 0.8680% | 3,154 / 189,279 | 1.6663% |
| Wednesday | XGBoost | 148 / 369,597 | 0.0400% | 147 / 189,279 | 0.0777% |
| Tuesday | Random Forest | 0 / 369,597 | 0.0000% | 0 / 189,279 | 0.0000% |

Common-cohort Thursday false alarms comprise 2,059 WEB_BRUTE_FORCE, 992 WEB_XSS
and 103 PORTSCAN predictions. This reinforces the already-observed Thursday web
precision problem. Friday predicts 55 BOTNET and two DDOS false alarms. Wednesday
predicts 26 GoldenEye, 46 Hulk, 21 Slowhttptest and 54 Slowloris false alarms.

No model changed between the full and restricted views; different rates reflect
different populations and denominators. Tuesday's zero false positives here is
not a guarantee or a universal ranking. The four models have different attack
coverage, and a classifier that always predicted BENIGN could also score zero
false alarms while missing every attack. Normal-only results cannot resolve that.

## Artifacts and tests

- `dataset/processed/cleaned_monday.csv`: cleaned raw features and BENIGN labels.
- `dataset/processed/monday_reference.pkl`: reference rows, fingerprints and audit.
- `dataset/processed/monday_common_cohort.pkl`: eligible source row IDs and reference hash.
- `reports/monday/data_audit.json`: source/schema, cleaning, code hashes and environment.
- `reports/monday/false_alarm_evaluation.json`: full/cohort results, exposure policy
  and previous bundle/split fingerprints.
- `reports/monday/verification.json`: actual-source, cohort, metric arithmetic,
  prediction API and preservation checks.
- `reports/monday/preserved_previous_runs.json`: preservation hashes for 74 files.

The normal-reference checks now live in [test_reference.py](../../tests/test_reference.py)
with shared pytest fixtures, covering BENIGN-only policy, type/direction fingerprints, reference output,
no-fitting behavior, common-cohort union across models, empty-rate handling,
changed-source/split rejection and overwrite guards. The original run had 23 passing
tests; see the [test guide](../../tests/README.md) for the current consolidated suite.

Existing raw datasets, trained models, previous reports/processed data and sniffer
source were preserved. No Monday model directory or bundle was created.

## Commands

Read the saved [Monday report](../../reports/monday/README.md) or
[JSON results](../../reports/monday/false_alarm_evaluation.json) for read-only viewing.
To recompute using the prepared reference and all four existing models:

```bash
.venv/bin/python -m ml_engine.monday --evaluate-only
```

That rewrites Monday evaluation/cohort outputs and does not retrain anything.
The default four-model list produces the cohort above. Selecting fewer models
with `--models` changes overlap exclusions and therefore the comparison cohort.

For a fresh preparation after archiving Monday reference data and reports:

```bash
.venv/bin/python -m ml_engine.monday
```

Or use `--prepare-only` to prepare without evaluating models. Re-preparation
refuses to overwrite `monday_reference.pkl`; do not prepare again just to read
results. All commands assume the project directory and its `.venv` interpreter.

## Remaining work

Monday is ready as a documented normal-data source, not automatically incorporated
into model training. A combined classifier needs joint cross-day cleaning/grouping
and a new evaluation design. Monday has now been inspected for false alarms; if
used later for training, these results no longer describe unseen Monday data for
that new model. Use fresh independent evaluation data for later claims.

Source label quality/provenance, independent host/day/campaign validation and lab
feature parity remain open. Thursday's web false positives remain unresolved.
No universal winner, combined model, live capture change or firewall response was
selected or enabled by this work.
