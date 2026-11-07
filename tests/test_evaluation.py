"""Held-out reporting and refusal of mismatched or changed run artifacts."""

import numpy as np
import pytest

from ml_engine import datasets, evaluate


def test_evaluation_reports_all_classes_and_original_labels(trained_run):
    run = trained_run
    result = evaluate.evaluate_model(dataset=run.config.name)
    test = run.payload["splits"]["test"]
    assert result["test_rows"] == len(test)
    assert np.shape(result["confusion_matrix"]) == (len(run.config.classes),) * 2
    assert set(result["classification_report"]) >= set(run.config.classes)
    assert set(result["original_label_results"]) == set(test._original_label)


def test_changed_splits_are_rejected(trained_run):
    with trained_run.config.splits_path.open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError, match="changed since training"):
        evaluate.evaluate_model(dataset=trained_run.config.name)


def test_other_dataset_bundle_is_rejected(trained_run):
    other = next(name for name in datasets.DATASETS if name != trained_run.config.name)
    with pytest.raises(ValueError, match="Bundle dataset"):
        evaluate.evaluate_model(dataset=other, bundle_path=trained_run.bundle_path)
