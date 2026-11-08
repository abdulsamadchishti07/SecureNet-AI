# Test suite

Install development dependencies and run the suite from the project root:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Tests are organized by software responsibility. Dataset policies are cases in
`conftest.py`, so the same assertions run against all supported classifier scopes.
Adding a policy requires one set of expected labels, rather than another test file.

| File | Responsibility |
| --- | --- |
| `conftest.py` | Expected policy cases, flow factory, temporary paths, clean caches and small-model fixtures |
| `test_preprocessing.py` | Label mapping/exclusions, duplicates/conflicts, raw values and deterministic connection splits |
| `test_training.py` | Training-only transforms, validation selection, publication and overwrite/isolation guards |
| `test_inference.py` | Invalid inputs, feature order, single/batch/direct agreement and bundle identity |
| `test_evaluation.py` | Per-class/original-label reporting and changed/mismatched artifact rejection |
| `test_reference.py` | Normal-only evaluation, no fitting, numeric/connection hashes and shared overlap exclusions |
| `test_sniffer.py` | Synthetic TCP/UDP feature and flow-lifecycle regressions |
| `test_unification.py` | Global multi-source conflicts/grouping, source parity, training-only caps and unified default inference |
| `test_response.py` | Immutable events, queue overflow, policy gates, audit/shutdown behavior and worker failure propagation |
| `test_firewall.py` | Simulated rule proposals, protected ranges, duplicate blocks and controlled-clock expiry; real command execution forbidden |

Every test receives an isolated temporary project root and inference caches.
Integration fixtures use small real Random Forest and XGBoost estimators. They
write only temporary synthetic datasets, artifacts and reports; installed models
and the original CSVs are unnecessary. No live interface or external service is used.
The verified environment currently emits joblib/NumPy deprecation warnings during
model deserialization; these warnings are visible and do not fail the suite.

Run one area or request a single combined machine-readable test report:

```bash
.venv/bin/python -m pytest tests/test_inference.py -q
.venv/bin/python -m pytest -q --junitxml=reports/tests/pytest.xml
```

Historical experiment reports remain indexed in [reports/README.md](../reports/README.md).
Passing these regression checks does not establish campaign independence, correct
Attempted semantics or CICFlowMeter parity. See the
[validity review](../docs/ML%20Engine/VALIDITY_REVIEW.md).
