"""Classify flows with the validation-selected model and its matching transforms."""

import os
from collections.abc import Mapping

import joblib
import numpy as np

from ml_engine.preprocess import SELECTED_COLUMNS, MODELS_DIR, SCHEMA_VERSION

BUNDLE_PATH = os.path.join(MODELS_DIR, "inference_bundle.pkl")
_bundle = None


def _load_model():
    """Publish cached state only after all bundle components are validated."""
    global _bundle
    if _bundle is None:
        if not os.path.exists(BUNDLE_PATH):
            raise FileNotFoundError(
                "Corrected Friday model missing. Run preprocessing and training first."
            )
        bundle = joblib.load(BUNDLE_PATH)
        metadata = bundle["metadata"]
        if metadata["schema_version"] != SCHEMA_VERSION or metadata["feature_names"] != SELECTED_COLUMNS:
            raise ValueError("Incompatible Friday inference schema")
        for name in ("model", "scaler"):
            if bundle[name].n_features_in_ != len(SELECTED_COLUMNS):
                raise ValueError(f"Incompatible {name} feature count")
        if list(bundle["label_encoder"].classes_) != metadata["classes"]:
            raise ValueError("Label encoder does not match bundle metadata")
        _bundle = bundle
    return _bundle


def _feature_matrix(features_list):
    rows = []
    for index, features in enumerate(features_list):
        if not isinstance(features, Mapping):
            raise ValueError(f"Flow {index} must be a feature mapping")
        missing = [column for column in SELECTED_COLUMNS if column not in features]
        if missing:
            raise ValueError(f"Flow {index} missing required features: {missing}")
        rows.append([features[column] for column in SELECTED_COLUMNS])
    try:
        matrix = np.asarray(rows, dtype=float)
    except (TypeError, ValueError) as exc:
        raise ValueError("Flow features must be numeric") from exc
    if matrix.shape != (len(rows), len(SELECTED_COLUMNS)) or not np.isfinite(matrix).all():
        raise ValueError("Flow features must be finite numeric scalars")
    if (matrix < 0).any():
        raise ValueError("Flow features must be nonnegative")
    return matrix


def predict_batch(features_list):
    """Return predictions in input order; an empty batch returns an empty list."""
    features_list = list(features_list)
    if not features_list:
        return []
    matrix = _feature_matrix(features_list)
    bundle = _load_model()
    model, scaler, encoder = bundle["model"], bundle["scaler"], bundle["label_encoder"]
    scaled = scaler.transform(matrix)
    predictions = model.predict(scaled)
    probabilities = model.predict_proba(scaled)
    class_names = encoder.inverse_transform(model.classes_.astype(int))
    results = []
    for prediction, row in zip(predictions, probabilities):
        label = str(encoder.inverse_transform([int(prediction)])[0])
        probability_map = {str(name): float(p) for name, p in zip(class_names, row)}
        results.append({
            "label": label,
            "confidence": probability_map[label],
            "probabilities": probability_map,
        })
    return results


def predict(features):
    """Classify one flow containing all 20 raw-valued selected features."""
    return predict_batch([features])[0]
