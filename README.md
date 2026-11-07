# SecureNet AI

Network intrusion detection and response final-year project. The current working
component is an offline Friday flow classifier; live capture and response are
still under development. See `AGENTS.md` for the implementation roadmap.

## Friday training pipeline

Place the local Friday CSV in `dataset/raw/friday.csv`. The expected variant has
the 20 feature names listed in `ml_engine/preprocess.py`, `Label`, `Src IP dec`,
and `Dst IP dec`. IPs are used only to keep related connections in one partition;
they are not classifier inputs. The exact dataset variant/provenance still needs
to be documented.

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
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
