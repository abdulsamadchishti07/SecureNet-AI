"""Classify flows with the validation-selected model and its matching transforms."""

import os
from collections.abc import Mapping

import joblib
import numpy as np

from ml_engine.datasets import get_dataset, DEFAULT_INFERENCE_DATASET
from ml_engine.preprocess import SELECTED_COLUMNS, SCHEMA_VERSION

MODELS_DIR = get_dataset("friday").models_dir
BUNDLE_PATH = os.path.join(MODELS_DIR, "inference_bundle.pkl")
_bundle = None
_weekday_bundles = {}


class FeatureValidationError(ValueError):
    """Invalid flow input; separate from model/scaler/artifact failures."""


def _load_model(dataset=DEFAULT_INFERENCE_DATASET):
    """Publish cached state only after all bundle components are validated."""
    global _bundle
    config = get_dataset(dataset)
    cached = _bundle if dataset == "friday" else _weekday_bundles.get(dataset)
    if cached is None:
        bundle_path = BUNDLE_PATH if dataset == "friday" else config.models_dir / "inference_bundle.pkl"
        if not os.path.exists(bundle_path):
            raise FileNotFoundError(
                f"{dataset.title()} model missing. Run preprocessing and training first."
            )
        bundle = joblib.load(bundle_path)
        metadata = bundle["metadata"]
        if metadata.get("dataset", "friday") != dataset:
            raise ValueError("Bundle dataset does not match requested inference dataset")
        if metadata["schema_version"] != SCHEMA_VERSION or metadata["feature_names"] != SELECTED_COLUMNS:
            raise ValueError("Incompatible inference schema")
        for name in ("model", "scaler"):
            if bundle[name].n_features_in_ != len(SELECTED_COLUMNS):
                raise ValueError(f"Incompatible {name} feature count")
        if list(bundle["label_encoder"].classes_) != metadata["classes"]:
            raise ValueError("Label encoder does not match bundle metadata")
        if set(metadata["classes"]) != set(config.classes):
            raise ValueError("Bundle classes do not match requested dataset")
        if dataset == "friday":
            _bundle = bundle
        else:
            _weekday_bundles[dataset] = bundle
        cached = bundle
    return cached


def _feature_matrix(features_list):
    rows = []
    for index, features in enumerate(features_list):
        if not isinstance(features, Mapping):
            raise FeatureValidationError(f"Flow {index} must be a feature mapping")
        missing = [column for column in SELECTED_COLUMNS if column not in features]
        if missing:
            raise FeatureValidationError(f"Flow {index} missing required features: {missing}")
        if any(isinstance(features[column], (bool, str)) for column in SELECTED_COLUMNS):
            raise FeatureValidationError("Flow features must be numeric")
        rows.append([features[column] for column in SELECTED_COLUMNS])
    try:
        matrix = np.asarray(rows, dtype=float)
    except (TypeError, ValueError) as exc:
        raise FeatureValidationError("Flow features must be numeric") from exc
    if matrix.shape != (len(rows), len(SELECTED_COLUMNS)) or not np.isfinite(matrix).all():
        raise FeatureValidationError("Flow features must be finite numeric scalars")
    if (matrix < 0).any():
        raise FeatureValidationError("Flow features must be nonnegative")
    return matrix


def predict_batch(features_list, dataset=DEFAULT_INFERENCE_DATASET):
    """Return predictions in input order; an empty batch returns an empty list."""
    get_dataset(dataset)
    features_list = list(features_list)
    if not features_list:
        return []
    matrix = _feature_matrix(features_list)
    bundle = _load_model(dataset)
    model, scaler, encoder = bundle["model"], bundle["scaler"], bundle["label_encoder"]
    scaled = scaler.transform(matrix)
    predictions = model.predict(scaled)
    probabilities = model.predict_proba(scaled)
    class_names = encoder.inverse_transform(model.classes_.astype(int))
    labels = encoder.inverse_transform(predictions.astype(int))
    results = []
    for label, row in zip(labels, probabilities):
        label = str(label)
        probability_map = {str(name): float(p) for name, p in zip(class_names, row)}
        results.append({
            "label": label,
            "confidence": probability_map[label],
            "probabilities": probability_map,
        })
    return results


def predict(features, dataset=DEFAULT_INFERENCE_DATASET):
    """Classify one flow containing all 20 raw-valued selected features."""
    return predict_batch([features], dataset=dataset)[0]
