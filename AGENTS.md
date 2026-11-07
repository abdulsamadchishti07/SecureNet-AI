# SecureNet AI — Agent Handoff

Last updated: 2026-11-07 (Asia/Karachi).

## User intent and current authorization

The user is building SecureNet AI, a final-year network intrusion detection and
response project. The current priority is to repair and retrain the Friday ML
pipeline before integrating live traffic.

The user first requested analysis and a plan, then authorized fixing Friday's data
leakage and running the corrected pipeline. That run is now complete. Keep
scope on the Friday ML milestone; live capture, backend and response remain future
work. Do not overwrite unrelated user changes.

The original analysis was read-only. The implementation now changes the ML
pipeline, adds focused tests/reports, and keeps legacy artifacts in their original
locations. See the latest change-log entry and reports for completion status.

## Project context

- Read `Claude.md` for the original project description if more context is needed.
- Intended pipeline: packet capture → bidirectional flow features → ML inference
  → backend decisions → storage, alerts, firewall response → dashboard.
- Python ML prototype exists. Backend, frontend, and deployment remain planned.
- Friday classes: BENIGN, BOTNET, DDOS, PORTSCAN.
- Current feature schema: `ml_engine/preprocess.py::SELECTED_COLUMNS` (20 features).
- Dataset source/provenance should be documented accurately: `Claude.md` describes
  CICIDS2017, while `docs/ML Engine/Friday.docx` names UNSW Canberra. Do not assume
  the exact downloaded variant or feature definitions without checking.

## Repository map and actual state

| Path | State / purpose |
| --- | --- |
| `ml_engine/preprocess.py` | Friday cleaning/deduplication and grouped 60/20/20 raw-valued splits |
| `ml_engine/train.py` | Training-only scaling, class weights, RF/XGBoost, validation model selection |
| `ml_engine/evaluate.py` | Selected model's held-out test metrics and confusion matrix |
| `ml_engine/predictor.py` | Atomic bundle loading; selected model; validated single/batch inputs |
| `ml_engine/__init__.py` | Lazily imports public entry points |
| `sniffer/capture.py` | `start_capture()` is a placeholder |
| `sniffer/extractor.py` | `extract_features(packet)` is a placeholder |
| `sniffer/publisher.py` | Redis publishing placeholder |
| `sniffer/rules.py` | Rule evaluation placeholder |
| `sniffer/main.py` | Only prints a startup message |
| `dataset/raw/` | Local CSVs for all five weekdays, including `_plus` variants |
| `dataset/processed/` | Raw cleaned CSV and schema-v2 `friday_splits.pkl` |
| `ml_engine/models/` | Preserved legacy artifacts; corrected run lives in `friday_v2/` |
| `requirements.txt` | Unpinned ML dependencies plus Scapy |
| `README.md` | Setup/run commands, split strategy, artifact paths and limitations |
| `docs/ML Engine/Friday.docx` | Actually plain text; read as text, not a Word ZIP |
| `tests/test_friday_pipeline.py` | Five regression/integration tests |
| `reports/friday/` | Baseline checksums, data audit, training/evaluation results, verification, PNG |

No backend, database integration, firewall response, notifications, dashboard,
or Docker setup exists yet.

## Current corrected Friday run — completed 2026-11-07

- 547,557 raw rows; removed 2,086 same-label feature duplicates. No invalid or
  conflicting-label rows were found in the actual run. Retained 545,471 flows.
- Split on canonical bidirectional IP/port/protocol connection groups. Same
  connection, original row, or identical model input cannot cross partitions.
- Train: 327,283; validation: 109,094; test: 109,094 original rows.
- No undersampling or SMOTE. Both models use training-only balanced class weights.
  A comparison against alternative balancing methods remains future work.
- Scaler and encoder fitted only on original training rows. Full-data verification
  matched scaler mean/variance to training-only statistics.
- Validation macro F1: RF 0.999295; XGBoost 0.999625. Selected XGBoost on validation.
- Selected XGBoost test accuracy: 0.9998900031165784; macro F1:
  0.999926666204674; benign false-positive rate: 0.00012217257749232057.
- Test errors: 7 benign flows flagged PORTSCAN, 5 PORTSCAN flows labelled BENIGN.
- Test recalls: BOTNET 1.0 (959 examples), DDOS 1.0 (19,029 examples), PORTSCAN
  0.9998428167243005 (31,810 examples). These are dataset results, not live guarantees.
- Predictor was checked on 40 validation flows, including every class. Batch,
  single and direct bundle predictions agree; missing features are rejected;
  empty batches return `[]`.
- All five automated tests pass. `git diff --check` passes. SHA-256 checks verified
  that legacy artifacts remain unchanged.
- New model bundle: `ml_engine/models/friday_v2/inference_bundle.pkl`. Predictor
  uses this bundle; there is no fallback to old leaky models.
- New artifacts are ignored by Git; reports/tests/code are reviewable source.
- Training refuses to overwrite a nonempty `friday_v2/` directory. Archive that
  run AND reports before future retraining. Reprocessing replaces the split
  artifact; evaluation refuses a split checksum different from training's.
- Remaining limitations: no independent-host/campaign/day or live evaluation.
  Timestamp strings lack full date/hour information; chronological splitting was
  not attempted. Ports may encode dataset-specific patterns. Exact dataset
  provenance still needs documentation. Do not tune repeatedly on this test set.
- Next work should be chosen with the user: further inference hardening/environment
  pinning or packet/flow extraction. Do not start backend/firewall work implicitly.

## Verified baseline (2026-11-07)

These are historical observations from this review; recheck when relevant rather
than treating them as permanent environment facts.

- All Python modules parsed successfully using `ast.parse`.
- Use `.venv/bin/python` for project commands. The system interpreter lacked
  several ML dependencies; the local virtual environment had them.
- `.venv` contained NumPy, pandas, scikit-learn, imbalanced-learn, XGBoost, joblib,
  matplotlib and seaborn, but not Scapy.
- `.venv/bin/python -m pip check` reported no broken installed requirements.
  This does not establish that every entry in `requirements.txt` is installed.
- Local Friday CSV: 89 columns; selected feature headers match the code.
- Raw label counts:
  - BENIGN: 288,544
  - Portscan: 159,066
  - DDoS: 95,144
  - Botnet - Attempted: 4,067
  - Botnet: 736
- Saved encoder classes: BENIGN, BOTNET, DDOS, PORTSCAN.
- Saved scaler: 20 features, 636,264 fitted samples.
- Saved test data: 127,253 rows, 20 features, approximately balanced classes.
- Both saved models loaded and predicted successfully.
- Recomputed on the saved test set without rewriting artifacts:
  - RF accuracy: 0.9999449914736784; macro F1: 0.9999449911648594.
  - XGBoost accuracy: 0.9999764249172908; macro F1: 0.9999764247319753.
- One raw flow produced a BENIGN prediction.
- `predict({})` returned a prediction rather than rejecting missing features.
- `predict_batch([])` raised a 2D-array shape ValueError.

The saved scores are reproducible but are NOT reliable evidence of generalization:
the current pipeline leaks information across the train/test boundary.

## Findings to address

Historical findings below describe the ORIGINAL pipeline. Items 1, 2, 4, 5, 6
and 8 were addressed in the corrected run; generic SMOTE was removed (item 3).
Item 7 now rejects missing/nonfinite/negative inputs and handles empty batches;
complete per-feature domain validation remains future work. Items 9 and 10
remain partially or wholly open; tests and README have been added, dependencies
are recorded but not pinned. See current-run status above before repeating work.

1. **Evaluation leakage:** `preprocess.py` applies SMOTE and fits StandardScaler
   before `train.py` splits the resulting data. Related real/synthetic examples
   can cross the split, and scaler statistics include held-out data. Split the
   original cleaned data before fitted transformations or resampling. Inspect
   duplicate/related flows and choose appropriate grouping or chronological
   boundaries using the available raw metadata.
2. **Balancing differs from comments/spec:** default `SMOTE(random_state=42)`
   balances all minority classes to the largest class, not just BOTNET to 50,000.
   The saved scaler sample count matches 4 × 159,066. Documentation's roughly
   200,000-row target is inconsistent with current behavior.
3. **SMOTE geometry and feature validity:** SMOTE currently uses unscaled
   features, letting large-range features dominate distances. Generic interpolation
   can also produce fractional ports, protocol identifiers, and flag values.
   Compare class weighting and a deliberate resampling strategy; do not apply
   generic SMOTE blindly.
4. **Model selection disconnected from inference:** evaluation prints the macro
   F1 winner, but prediction always loads `random_forest.pkl`.
5. **Artifact consistency:** preprocessing independently overwrites scaler and
   encoder. Their modification dates were newer than the model dates. This is
   a consistency risk, not proof that the current artifacts are mismatched.
   Bundle/version all inference components and metadata together.
6. **Partial model loading:** `_load_model()` assigns `_model` before loading
   scaler/encoder, yet its early return checks only `_model`. A failed later load
   can leave inference partially initialized. Load atomically.
7. **Input validation:** missing features silently become zero; empty batches
   fail. Validate required feature names, numeric values, finiteness, shape, and
   appropriate ranges, and explicitly define empty-batch behavior.
8. **Inference dependency coupling:** package imports pull in training, SMOTE,
   XGBoost, and plotting dependencies even for RF inference. Separate runtime
   schema/artifact definitions from training modules.
9. **Live feature parity:** extraction must reproduce direction, units, lengths,
   rates, flag semantics, and flow expiry rules of the actual training dataset.
   This remains unimplemented and unvalidated.
10. **Reproducibility/documentation:** pin a verified dependency environment,
    provide usable setup instructions, focused tests, and dataset provenance.

## Proposed implementation plan

Chunks 1–5 form the Friday model milestone. Baseline preservation, corrected
splits and the first retraining/evaluation run are completed. Class weighting
is the initial balancing choice; comparative balancing experiments and full
inference hardening/environment pinning are not complete. Chunks 6–9 are future work.

### Chunk 1 — Preserve the baseline

- Record dependency versions, dataset counts/checksums, feature schema, and metrics.
- Preserve existing models, scaler, encoder and test data together before replacing
  anything; use isolated/versioned output directories.
- Done when the previous version can be reproduced and compared.

### Chunk 2 — Correct data preparation

- Audit labels, invalid/nonfinite values, feature ranges, duplicates and provenance.
- Reserve original validation/test data before balancing or fitting transforms.
- Assess related-flow leakage and grouped/chronological split feasibility.
- Retain useful split metadata without feeding identities into the classifier.
- Done when split boundaries and exclusions are documented and held-out data is
  untouched by fitted preprocessing/resampling.

### Chunk 3 — Fix class balancing

- Compare class weighting with a controlled training-only resampling strategy.
- Use explicit targets and preserve meaningful categorical/discrete feature values.
- Keep validation/test data representative of the intended evaluation population.
- Done when the chosen method and class counts are explicit and justified.

### Chunk 4 — Retrain and evaluate Friday

- Train RF and XGBoost under the corrected pipeline.
- Select using validation macro F1, attack recall, and benign false-positive rate.
- Evaluate the selected configuration once on the untouched test set.
- Save per-class precision/recall/F1, confusion matrices, split metadata, training
  configuration, and relevant timing/resource measurements.
- Done when there is an honest, reproducible baseline; lower scores than the old
  leaky evaluation are acceptable.

### Chunk 5 — Harden inference

- Bundle the selected model, transformations, encoder, ordered schema and metadata.
- Validate inputs, define empty-batch behavior, and make loading atomic.
- Separate inference imports from training/evaluation dependencies.
- Pin the working environment and add focused tests for meaningful failure cases,
  artifact consistency, feature order, and single/batch prediction agreement.
- Done when inference is repeatable and invalid inputs fail clearly.

### Chunk 6 — Implement flow extraction

- Implement capture, bidirectional flow tracking, expiry and the 20 features.
- Specify units and feature definitions using the actual dataset generation method.
- Validate against recorded traffic before relying on live capture.
- Done when packet recordings yield consistent, valid model inputs.

### Chunk 7 — Validate live detection

- Connect extraction to inference in the isolated lab, initially detection-only.
- Measure false alerts, missed attacks, latency, throughput and memory use.
- Done when live/recorded traffic provides evidence beyond dataset evaluation.

### Chunk 8 — Build backend and response

- Implement FastAPI, authentication, persistent alerts, event delivery and notifications.
- Add firewall response with allowlists, expiry, audit records and manual unblock.
- Test response behavior in the lab before enabling automatic blocking.
- Done when detection-to-response actions are controlled and traceable.

### Chunk 9 — Dashboard and deployment

- Build live alerts, statistics, blocked-IP management and forensic views.
- Add deployment configuration, health checks, secrets configuration and setup docs.
- Done when the end-to-end demonstration is reproducible.

Expand to Tuesday, Wednesday and Thursday after the Friday milestone using the
corrected pipeline, with separate decisions for rare classes and attack coverage.

## Working conventions

- Read this handoff first; inspect relevant source before edits rather than repeating
  the entire initial review. Refresh historical observations as needed.
- Preserve raw datasets, existing artifacts and unrelated user modifications.
- Initial git status before this file: modified `dataset/processed/.gitkeep`,
  modified `dataset/raw/.gitkeep`, untracked `Claude.md`.
- CSVs and pickle models are ignored by Git; a clean Git status does not prove
  local datasets or artifacts are absent.
- Do not launch full preprocessing/training simply to inspect the project: those
  commands overwrite existing outputs. Use explicit isolated outputs when authorized.
- Do not interpret high saved test scores as proof the system is ready for blocking.
- After each implemented chunk, append a concise dated entry below with changes,
  checks/results, remaining issues and the next step. Never mark planned work done
  without evidence.

## Change log

- 2026-11-07: Completed read-only project analysis and saved this handoff/plan.
  No implementation chunks completed. Await the user's next implementation instruction.
- 2026-11-07: User authorized fixing Friday leakage and running it. Reworked
  preprocessing into duplicate-free, connection-grouped train/validation/test
  splits; replaced SMOTE/undersampling with training-only class weights; fitted
  transforms on training only; selected XGBoost on validation; completed held-out
  evaluation. Added a matching inference bundle, input checks, lazy package imports,
  overwrite/checksum guards, five passing tests, README and reports. Preserved all
  legacy artifact checksums and unrelated `.gitkeep`/`Claude.md` changes. See
  `reports/friday/README.md` and `verification.json` for results. No live capture,
  packet collection, firewall changes or backend work was performed.
