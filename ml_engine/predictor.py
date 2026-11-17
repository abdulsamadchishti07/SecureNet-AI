"""Classify flows with the validation-selected model and its matching transforms."""

import hmac
import json
import os
from collections.abc import Mapping
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import joblib
import numpy as np

from ml_engine.datasets import get_dataset, DEFAULT_INFERENCE_DATASET
from ml_engine.preprocess import SELECTED_COLUMNS, SCHEMA_VERSION

MODELS_DIR = get_dataset("friday").models_dir
BUNDLE_PATH = os.path.join(MODELS_DIR, "inference_bundle.pkl")
_REPO_MODELS_DIR = Path(__file__).resolve().parent / "models"
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_bundle = None
_weekday_bundles = {}


class FeatureValidationError(ValueError):
    """Invalid flow input; separate from model/scaler/artifact failures."""


def _validate_sha256(value, source):
    if not isinstance(value, str) or len(value) != 64 or not all(ch in _HEX_CHARS for ch in value):
        raise ValueError(f"Invalid SHA-256 digest in {source}")
    return value.lower()


def _pinned_bundle_sha256(expected_sha256=None):
    if expected_sha256 is not None:
        return _validate_sha256(expected_sha256, "expected_sha256")
    env_hash = os.environ.get("SECURENET_MODEL_SHA256", "").strip()
    if env_hash:
        return _validate_sha256(env_hash, "SECURENET_MODEL_SHA256")
    return None


def _expected_bundle_sha256(dataset, bundle_path, expected_sha256=None):
    pinned = _pinned_bundle_sha256(expected_sha256)
    if pinned is not None:
        return pinned
    # Select trust from the configured path, before following file/directory
    # symlinks. An external target must not supply its own manifest or opt out.
    models_root = Path(os.path.abspath(bundle_path)).parent.parent
    manifest_path = models_root / "manifest.json"
    if not manifest_path.is_file():
        if models_root == _REPO_MODELS_DIR:
            raise ValueError(f"Missing model integrity manifest: {manifest_path}")
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entry = manifest["bundles"][dataset]["sha256"]
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ValueError(f"Invalid model integrity manifest for {dataset}: {exc}") from exc
    return _validate_sha256(entry, str(manifest_path))


def _load_model(dataset=DEFAULT_INFERENCE_DATASET, *, expected_sha256=None):
    """Publish cached state only after checksum verification and schema validation."""
    global _bundle
    config = get_dataset(dataset)
    cached = _bundle if dataset == "friday" else _weekday_bundles.get(dataset)
    if cached is not None:
        expected = _pinned_bundle_sha256(expected_sha256)
        if expected is not None and not hmac.compare_digest(cached["_artifact_sha256"], expected):
            raise ValueError(f"Model bundle integrity check failed for {dataset}")
        return cached
    if cached is None:
        bundle_path = BUNDLE_PATH if dataset == "friday" else config.models_dir / "inference_bundle.pkl"
        if not os.path.exists(bundle_path):
            raise FileNotFoundError(
                f"{dataset.title()} model missing. Run preprocessing and training first."
            )
        # Verify the exact serialized bytes against the trusted manifest or pinned hash
        # before pickle deserialization; also retain the digest for event provenance.
        with open(bundle_path, "rb") as artifact:
            serialized = artifact.read()
        actual_sha256 = sha256(serialized).hexdigest()
        expected = _expected_bundle_sha256(dataset, bundle_path, expected_sha256)
        if expected is not None and not hmac.compare_digest(actual_sha256, expected):
            raise ValueError(f"Model bundle integrity check failed for {dataset}")
        bundle = joblib.load(BytesIO(serialized))
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
        bundle["_artifact_sha256"] = actual_sha256
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
