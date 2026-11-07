# SecureNet AI

**Evaluation status:** the current scores use connection-held-out splits within
captures and share attack endpoint pairs across partitions. Campaign-independent
detection and sniffer feature parity remain unvalidated. Read the
[validity review and revised priorities](<docs/ML Engine/VALIDITY_REVIEW.md>) before
using headline scores or proceeding toward deployment.

Network intrusion detection and response final-year project. The current working
components are offline weekday flow classifiers; live capture and response are
still under development. See `AGENTS.md` for the implementation roadmap.

Detailed ML methodology, weekday results and limitations are in
[the ML engine documentation](<docs/ML Engine/ML_ENGINE.md>).
See the [documentation index](docs/README.md) for other references.

## Tests

Install development dependencies and run the unified pytest suite:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

The [test guide](tests/README.md) describes the shared fixtures and parametrized
preprocessing, training, inference, evaluation, normal-reference and sniffer tests.
All test datasets and model outputs use temporary directories. To produce
one combined test report, add `--junitxml=reports/tests/pytest.xml`. Historical
experiment evidence remains indexed in [reports/README.md](reports/README.md).

## Sniffer (flow extraction)

Groups IPv4 packets into flows and prints each completed
flow's 20 features as a JSON line; `--predict` adds the Friday model verdict
(detection only, nothing is blocked).

```bash
.venv/bin/python -m sniffer.main -r capture.pcap --predict
sudo .venv/bin/python -m sniffer.main -i eth0 -f "not port 22" --predict
```

Single-packet flows are dropped. CICFlowMeter feature parity has not been
validated by replaying matching source captures; the current extractor has known
timeout/termination departures. See the validity review before using predictions.

## Monday normal-reference evaluation

Monday is BENIGN-only, so it has no standalone trained attack classifier. It is
prepared as a normal-data reference and evaluated with the four saved weekday
models to measure false alarms, without fitting or selecting models on Monday.

```bash
.venv/bin/python -m ml_engine.monday --evaluate-only
```

The existing run cleaned 371,621 rows to 369,597 unique flows. Results include the
full reference and a common 189,279-row cohort that excludes numeric inputs or
canonical connections present in any previous train/validation/test partition.
The same restricted rows are used for every model. Monday contains no attack
labels, so attack recall/F1 cannot be assessed. Reused endpoint keys across days
make the connection exclusion conservative.

See [Monday documentation](<docs/ML Engine/MONDAY.md>) and
[the false-alarm report](reports/monday/README.md). Reference data lives in
`dataset/processed/monday_reference.pkl`, eligible row IDs in
`monday_common_cohort.pkl`, and reports in `reports/monday/`. There is no Monday
model bundle or `--dataset monday` supervised option.

After archiving any existing Monday reference/reports, a fresh preparation plus
evaluation uses `.venv/bin/python -m ml_engine.monday`; `--prepare-only` skips
evaluation. Preparation refuses to overwrite an existing reference. To inspect
results without rewriting outputs, open the saved README/JSON directly.

## Tuesday training pipeline

Tuesday reuses the corrected 20-feature pipeline with grouped partitions,
training-only transformations and balanced training class weights.

| Model label | Raw labels |
| --- | --- |
| `BENIGN` | BENIGN |
| `FTP_BRUTE_FORCE` | FTP-Patator, including Attempted |
| `SSH_BRUTE_FORCE` | SSH-Patator, including Attempted |

All source families are supported; no labels are deliberately excluded. Original
labels and attempted status remain metadata and appear in the evaluation report.
The family verdict does not establish a successful login or compromise.

To see the trained Tuesday model's results:

```bash
.venv/bin/python -m ml_engine.evaluate --dataset tuesday
xdg-open reports/tuesday/confusion_matrix.png
```

For a new run after archiving any existing Tuesday models, splits and reports:

```bash
.venv/bin/python -m ml_engine.preprocess --dataset tuesday
.venv/bin/python -m ml_engine.train --dataset tuesday
.venv/bin/python -m ml_engine.evaluate --dataset tuesday
```

Artifacts live in `ml_engine/models/tuesday_v1/`,
`dataset/processed/tuesday_splits.pkl` and `reports/tuesday/`. Programmatic
inference uses `predict(features, dataset="tuesday")`. Previous runs are preserved,
and omitting the dataset still means Friday. No combined weekday model or change
to the sniffer's default model is implied. See `reports/tuesday/README.md` and
`docs/ML Engine/TUESDAY.md` for the measured results and limits.

## Wednesday training pipeline

Wednesday uses the same 20 features, grouped train/validation/test partitions,
training-only scaling and class weights as the corrected Friday/Thursday runs.

| Model label | Raw labels |
| --- | --- |
| `BENIGN` | BENIGN |
| `DOS_GOLDENEYE` | DoS GoldenEye, including Attempted |
| `DOS_HULK` | DoS Hulk, including Attempted |
| `DOS_SLOWHTTPTEST` | DoS Slowhttptest, including Attempted |
| `DOS_SLOWLORIS` | DoS Slowloris, including Attempted |

Heartbleed is explicitly excluded: the source has only 11 rows in one connection
group, insufficient for an independent grouped train/validation/test evaluation.
Original labels/attempted status remain metadata. `DOS_*` labels describe attack
families, not proof of successful compromise. Friday's `DDOS` is a separate label.

For a new run after archiving any existing Wednesday artifacts and reports:

```bash
.venv/bin/python -m ml_engine.preprocess --dataset wednesday
.venv/bin/python -m ml_engine.train --dataset wednesday
.venv/bin/python -m ml_engine.evaluate --dataset wednesday
```

To see existing results, run only the evaluation command or open
`reports/wednesday/README.md`. View its confusion matrix with:

```bash
xdg-open reports/wednesday/confusion_matrix.png
```

Wednesday writes `dataset/processed/wednesday_splits.pkl`,
`ml_engine/models/wednesday_v1/` and `reports/wednesday/`. It does not replace
Friday/Thursday artifacts. Programmatic inference uses
`predict(features, dataset="wednesday")`; omitting the dataset still selects
Friday. The existing sniffer CLI's `--predict` continues to use Friday.

## Thursday training pipeline

Thursday uses the same 20 features and connection-group split strategy as Friday,
with an explicit label policy in `ml_engine/datasets.py`:

| Model label | Raw labels |
| --- | --- |
| `BENIGN` | BENIGN |
| `PORTSCAN` | Infiltration - Portscan |
| `WEB_BRUTE_FORCE` | Web Attack - Brute Force, including Attempted |
| `WEB_XSS` | Web Attack - XSS, including Attempted |

This baseline explicitly excludes Infiltration (including Attempted) and Web
Attack - SQL Injection (including Attempted), because of limited support. Audits
record every excluded label/count; unknown labels cause an error. Attempted and
base labels are merged for attack-family classification, with the original labels
retained as split metadata and reported separately in evaluation. They do not
establish whether a victim was compromised.

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m ml_engine.preprocess --dataset thursday
.venv/bin/python -m ml_engine.train --dataset thursday
.venv/bin/python -m ml_engine.evaluate --dataset thursday
xdg-open reports/thursday/confusion_matrix.png
```

Preprocessing/training are needed for a new run only. To see existing results,
run just the evaluation command or read `reports/thursday/README.md`.

Thursday writes `dataset/processed/thursday_splits.pkl`,
`ml_engine/models/thursday_v1/`, and `reports/thursday/`. It never replaces Friday's
artifacts. Training refuses to replace an existing corrected run; archive its
model directory and reports before retraining. Thursday preprocessing also refuses
to replace the default splits while a trained Thursday run exists.

For programmatic predictions, supply all raw selected features:

```python
from ml_engine import predict

# features is a dictionary containing all 20 selected feature values.
result = predict(features, dataset="thursday")
```

Omitting `dataset` continues to use Friday. These are separate day-specific
classifiers, not a combined model that recognizes every weekday's attacks. Do not
choose a day based on a predicted attack; a unified classifier requires a future
joint training/splitting pass across the selected days.

## Friday training pipeline

Place the local Friday CSV in `dataset/raw/friday.csv`. The expected variant has
the 20 feature names listed in `ml_engine/preprocess.py`, `Label`, `Src IP dec`,
and `Dst IP dec`. IPs are used only to keep related connections in one partition;
they are not classifier inputs. The exact dataset variant/provenance still needs
to be documented.

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m ml_engine.preprocess
.venv/bin/python -m ml_engine.train
.venv/bin/python -m ml_engine.evaluate
```

The corrected pipeline:

1. Normalizes Friday's four labels and removes invalid rows, repeated model
   inputs and conflicting-label inputs.
2. Reserves approximately 60% training, 20% validation and 20% test data using
   stratified groups. Repeated or reverse-direction connections with the same
   endpoints, ports and protocol cannot cross partitions. Exact feature-vector
   duplicates are removed before splitting, even across different endpoints.
3. Fits the scaler and label encoder on original training rows only. Uses class
   weighting for both models, with no SMOTE, synthetic examples or undersampling.
4. Trains Random Forest and XGBoost, selecting the winner using validation macro
   F1. Test metrics never determine the winner.
5. Evaluates the selected model on the original, unresampled test partition.

Processed CSV values are **raw, not scaled**. Training consumes the versioned
`dataset/processed/friday_splits.pkl` artifact rather than that CSV, preventing
accidental use of an old scaled/resampled CSV.

New artifacts are stored in `ml_engine/models/friday_v2/`. Existing legacy models
in `ml_engine/models/` are preserved. Training refuses to overwrite a nonempty
corrected run directory; archive that directory and its reports before a new run.
Reprocessing changes the split artifact and requires retraining; evaluation checks
that it matches the artifact used for training.

The predictor loads `friday_v2/inference_bundle.pkl`, which contains the selected
model, scaler, label encoder and schema together. Supply all 20 raw feature values;
missing, nonfinite or negative inputs are rejected. Empty batches return `[]`.

Reports in `reports/friday/` include cleaning/split counts, source checksum,
training environment, validation metrics, test metrics and a confusion matrix.

This is a within-Friday connection-group evaluation. It does not establish
performance on independent hosts, attack campaigns, future days or live traffic.
The local timestamps lack full date/hour information, so they are not used for a
chronological split. Separate lab validation is required before automatic blocking.
