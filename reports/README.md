# Reports

The unified pytest suite can write one JUnit report to `reports/tests/pytest.xml`:

```bash
.venv/bin/python -m pytest -q --junitxml=reports/tests/pytest.xml
```

Generated test output is ignored by Git. Test implementation and shared fixtures
live in [tests/](../tests/README.md).

Completed experiment evidence is preserved separately below. The names identify
historical source captures and runs; all use the shared pipeline and test suite.
Moving or deleting these records would disrupt saved paths and checksum manifests.
Test filenames/counts in those records describe the suite at the time of each
experiment; current responsibility-based modules are listed in the test guide.
Interpret scores using the [validity review](../docs/ML%20Engine/VALIDITY_REVIEW.md).

| Evidence | Purpose |
| --- | --- |
| [Sprint 3 dashboard](sprint3/README.md) | PostgreSQL setup, reference-based dashboard, browser workflows and real-model offline control demo |
| [Backend hardening](backend_hardening/README.md) | Auth/RBAC, validation/idempotency, durable delivery, lifecycle and database verification |
| [Response integration](response/README.md) | Local dry-run consumer, offline synthetic demo and regression evidence |
| [Unified](unified/README.md) | Current seven-class experiment, global splits, training-only benign cap and limitations |
| [Friday](friday/README.md) | Leakage-correction baseline and original artifact checksums |
| [Thursday](thursday/README.md) | Web/port-scan experiment and limitations |
| [Wednesday](wednesday/README.md) | DoS-family experiment |
| [Tuesday](tuesday/README.md) | FTP/SSH-family experiment |
| [Monday](monday/README.md) | Normal-only reference and saved-model false alarms |
| [Validity audit](validity_review/findings.json) | Endpoint overlap and hypothetical OR-ensemble findings |
