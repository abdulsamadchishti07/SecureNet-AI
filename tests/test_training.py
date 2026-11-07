"""Training-only transforms, model publication and artifact safety checks."""

import joblib
import numpy as np
import pytest

from ml_engine import datasets, train
from ml_engine.preprocess import SELECTED_COLUMNS, SCHEMA_VERSION, preprocess_data


def test_transforms_fit_only_original_training_rows(dataset_case, splits):
    splits["validation"].loc[:, "Flow Duration"] = 1e12
    splits["test"].loc[:, "Flow Duration"] = 1e15
    scaler, encoder = train.fit_training_transforms(splits["train"])
    values = splits["train"][SELECTED_COLUMNS].to_numpy(dtype=float)
    assert scaler.n_samples_seen_ == len(values)
    np.testing.assert_allclose(scaler.mean_, values.mean(axis=0))
    np.testing.assert_allclose(scaler.var_, values.var(axis=0))
    before = scaler.mean_.copy()
    for name in ("validation", "test"):
        scaler.transform(splits[name][SELECTED_COLUMNS].to_numpy())
    np.testing.assert_array_equal(scaler.mean_, before)
    assert list(encoder.classes_) == list(dataset_case.classes)


def test_published_bundle_matches_validation_selection_and_training_statistics(trained_run):
    run = trained_run
    metadata, bundle = run.metadata, run.bundle
    original_train = run.payload["splits"]["train"][SELECTED_COLUMNS].to_numpy(dtype=float)
    assert metadata["dataset"] == run.config.name
    winner = max(metadata["validation"], key=lambda name: metadata["validation"][name]["macro_f1"])
    assert metadata["selected_model"] == winner
    assert bundle["scaler"].n_samples_seen_ == len(original_train)
    np.testing.assert_allclose(bundle["scaler"].mean_, original_train.mean(axis=0))
    assert set(bundle["label_encoder"].classes_) == set(run.config.classes)
    selected = joblib.load(run.config.models_dir / f"{winner}.pkl")
    scaled = bundle["scaler"].transform(original_train)
    np.testing.assert_array_equal(bundle["model"].predict(scaled), selected.predict(scaled))


def test_training_refuses_to_overwrite_a_saved_run(trained_run):
    with pytest.raises(FileExistsError):
        train.train_model(dataset=trained_run.config.name)


def test_other_dataset_splits_are_rejected_before_fitting(dataset_case, tmp_path, monkeypatch):
    other = next(name for name in datasets.DATASETS if name != dataset_case.name)
    path = tmp_path / "wrong_splits.pkl"
    joblib.dump({"schema_version": SCHEMA_VERSION, "dataset": other}, path)

    def forbidden_fit(*args, **kwargs):
        pytest.fail("Mismatched artifacts reached transform fitting")

    monkeypatch.setattr(train, "fit_training_transforms", forbidden_fit)
    with pytest.raises(ValueError, match="Split dataset"):
        train.train_model(dataset=dataset_case.name, splits_path=path)


@pytest.mark.parametrize("dataset_name", ("thursday", "wednesday", "tuesday"))
def test_reprocessing_refuses_to_replace_a_trained_split(dataset_name, dataset_cases, train_dataset):
    # Friday's missing preprocessing guard is an existing production limitation.
    case = next(case for case in dataset_cases if case.name == dataset_name)
    train_dataset(case)
    with pytest.raises(FileExistsError):
        preprocess_data(dataset=dataset_name)


def test_training_keeps_other_dataset_artifacts_separate(trained_run):
    for name in datasets.DATASETS:
        if name != trained_run.config.name:
            other = datasets.get_dataset(name)
            assert not other.models_dir.exists()
            assert not other.reports_dir.exists()
            assert not other.splits_path.exists()
