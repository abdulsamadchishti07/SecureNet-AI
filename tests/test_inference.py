"""Inference input contracts, feature ordering and bundle identity checks."""

import shutil

import numpy as np
import pytest

from ml_engine import datasets, predictor
from ml_engine.preprocess import SELECTED_COLUMNS


def test_single_batch_and_direct_predictions_agree(trained_run):
    run = trained_run
    frame = run.payload["splits"]["validation"].groupby("Label").head(2)
    flows = frame[SELECTED_COLUMNS].to_dict("records")
    results = predictor.predict_batch(flows, dataset=run.config.name)
    values = run.bundle["scaler"].transform(frame[SELECTED_COLUMNS].to_numpy())
    direct = run.bundle["label_encoder"].inverse_transform(run.bundle["model"].predict(values).astype(int))
    assert len(results) == len(flows)
    assert [result["label"] for result in results] == list(direct)
    for flow, result in zip(flows, results):
        assert result == predictor.predict(flow, dataset=run.config.name)
        assert result == predictor.predict(dict(reversed(list(flow.items()))), dataset=run.config.name)
        assert set(result["probabilities"]) == set(run.config.classes)
        assert sum(result["probabilities"].values()) == pytest.approx(1.0)


@pytest.fixture
def forbid_model_loading(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("Invalid or empty input reached model loading")
    monkeypatch.setattr(predictor, "_load_model", fail)


def test_empty_batches_return_without_loading_models(dataset_case, forbid_model_loading):
    assert predictor.predict_batch([], dataset=dataset_case.name) == []


def test_missing_features_are_rejected_before_loading(dataset_case, forbid_model_loading):
    with pytest.raises(ValueError, match="missing required features"):
        predictor.predict({}, dataset=dataset_case.name)


@pytest.mark.parametrize("bad_value", [np.nan, np.inf, -1, "invalid", [1, 2]],
                         ids=["nan", "infinity", "negative", "text", "nonscalar"])
def test_invalid_values_are_rejected_before_loading(dataset_case, valid_features, bad_value, forbid_model_loading):
    valid_features["Flow Duration"] = bad_value
    with pytest.raises(ValueError):
        predictor.predict(valid_features, dataset=dataset_case.name)


def test_unknown_dataset_is_rejected_even_for_empty_batches(forbid_model_loading):
    with pytest.raises(ValueError, match="Unknown dataset"):
        predictor.predict_batch([], dataset="unknown")


def test_mismatched_bundle_does_not_initialize_inference(trained_run):
    other = next(name for name in datasets.DATASETS if name != trained_run.config.name)
    destination = datasets.get_dataset(other).models_dir / "inference_bundle.pkl"
    destination.parent.mkdir(parents=True)
    shutil.copyfile(trained_run.bundle_path, destination)
    flow = trained_run.raw.iloc[0][SELECTED_COLUMNS].to_dict()
    with pytest.raises(ValueError, match="Bundle dataset"):
        predictor.predict(flow, dataset=other)
    assert predictor._bundle is None
    assert predictor._weekday_bundles == {}
