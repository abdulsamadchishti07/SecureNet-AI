"""Normal-only reference evaluation, overlap filtering and no-fitting contract."""

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from ml_engine import datasets, monday
from ml_engine.preprocess import SELECTED_COLUMNS, clean_data


@pytest.fixture
def reference_run(trained_run):
    raw = trained_run.raw
    exact = raw.iloc[[0]].assign(**{"Src IP dec": 999})
    same_connection = raw.iloc[[1]].copy()
    same_connection["Flow Duration"] += 123
    fresh = raw.iloc[[2, 8]].copy()
    fresh["Src IP dec"], fresh["Dst IP dec"] = 777, 778
    fresh["Src Port"] += 40000
    reference = pd.concat([exact, same_connection, fresh, fresh.iloc[[0]]], ignore_index=True)
    reference["Label"] = "BENIGN"
    reference.to_csv(monday.MONDAY.raw_csv, index=False)
    trained_run.reference_audit = monday.prepare_monday()
    trained_run.fresh = fresh
    return trained_run


@pytest.fixture
def frozen_reference(reference_run, monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("Normal-reference evaluation attempted to fit an estimator")
    # The dependency creates the saved model before fitting is forbidden.
    for estimator in (StandardScaler, LabelEncoder, RandomForestClassifier, XGBClassifier):
        monkeypatch.setattr(estimator, "fit", fail)
    return reference_run


def test_hashes_normalize_numeric_types_and_reverse_connections(valid_features):
    row = {**valid_features, "Src IP dec": 100, "Dst IP dec": 200,
           "Src Port": 1234, "Dst Port": 443, "Protocol": 6,
           "Flow Duration": 0, "Label": "BENIGN"}
    frame = pd.DataFrame([row])
    numeric = frame.copy()
    numeric[SELECTED_COLUMNS] = numeric[SELECTED_COLUMNS].astype(float)
    numeric["Flow Duration"] = -0.0
    np.testing.assert_array_equal(monday.feature_hashes(frame), monday.feature_hashes(numeric))
    reverse = frame.copy()
    for left, right in (("Src IP dec", "Dst IP dec"), ("Src Port", "Dst Port")):
        reverse[left], reverse[right] = frame[right], frame[left]
    np.testing.assert_array_equal(monday.connection_hashes(frame), monday.connection_hashes(reverse))


def test_normal_reference_rejects_attack_labels_and_has_no_classifier(valid_features):
    frame = pd.DataFrame([{**valid_features, "Src IP dec": 100, "Dst IP dec": 200,
                           "Label": "FTP-Patator"}])
    with pytest.raises(ValueError, match="Unexpected Monday labels"):
        clean_data(frame, config=monday.MONDAY)
    with pytest.raises(ValueError, match="Unknown dataset"):
        datasets.get_dataset("monday")


def test_reference_defaults_preserve_the_original_weekday_comparison():
    assert set(monday.DEFAULT_MODEL_DAYS) == {"friday", "thursday", "wednesday", "tuesday"}
    assert "unified" not in monday.DEFAULT_MODEL_DAYS


def test_preparing_reference_deduplicates_without_publishing_a_model(reference_run):
    assert reference_run.reference_audit["clean_rows"] == 4
    assert reference_run.reference_audit["same_label_duplicates_removed"] == 1
    assert not monday.MONDAY.models_dir.exists()
    with pytest.raises(FileExistsError):
        monday.prepare_monday()


def test_saved_model_evaluation_excludes_both_overlap_types_without_fitting(frozen_reference):
    day = frozen_reference.config.name
    report = monday.evaluate_monday(model_days=[day])
    cohort = report["common_cohort"]
    assert cohort["eligible_rows"] == 2
    assert cohort["excluded_feature_overlap_rows"] == 1
    assert cohort["excluded_connection_overlap_rows"] == 1
    saved = joblib.load(monday.MONDAY.processed_dir / "monday_common_cohort.pkl")
    np.testing.assert_array_equal(saved["eligible_row_ids"], [2, 3])
    assert report["models"][day]["full_reference"]["rows"] == 4
    assert report["models"][day]["common_cohort"]["rows"] == 2
    assert "macro_f1" not in report


def test_all_compared_models_use_the_same_union_filtered_cohort(frozen_reference, monkeypatch):
    day = frozen_reference.config.name
    other = next(name for name in datasets.DATASETS if name != day)
    original_loader = monday.load_existing_run
    known_features = monday.feature_hashes(frozen_reference.fresh.iloc[[0]])

    def exposure_loader(name):
        if name == day:
            return original_loader(name)
        # This fixture isolates cohort union logic from model training policy.
        return frozen_reference.bundle, {
            "feature_hashes": known_features,
            "connection_hashes": np.array([], dtype=np.uint64),
            "partitions_considered": ["train"],
            "bundle_sha256": "fixture", "splits_sha256": "fixture",
        }

    monkeypatch.setattr(monday, "load_existing_run", exposure_loader)
    report = monday.evaluate_monday(model_days=[day, other])
    assert report["common_cohort"]["eligible_rows"] == 1
    assert all(result["common_cohort"]["rows"] == 1 for result in report["models"].values())


def test_changed_reference_source_is_rejected(reference_run):
    with monday.MONDAY.raw_csv.open("a") as stream:
        stream.write("\n")
    with pytest.raises(ValueError, match="Monday source changed"):
        monday.evaluate_monday(model_days=[reference_run.config.name])


def test_changed_prior_splits_are_rejected(trained_run):
    with trained_run.config.splits_path.open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError, match="splits changed"):
        monday.load_existing_run(trained_run.config.name)


@pytest.mark.parametrize("labels, expected_rate", [([], None), (["BENIGN", "FTP_BRUTE_FORCE"], 0.5)],
                         ids=["empty", "mixed"])
def test_false_alarm_metrics_handle_empty_and_nonempty_inputs(labels, expected_rate):
    result = monday.false_alarm_metrics(np.array(labels, dtype=str))
    assert result["rows"] == len(labels)
    assert result["false_positive_rate"] == expected_rate
