"""Inference input contracts, feature ordering and bundle identity checks."""

import json
import os
from pathlib import Path
import shutil
from hashlib import sha256

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


@pytest.mark.parametrize("bad_value", [np.nan, np.inf, -1, "invalid", [1, 2], "1", True],
                         ids=["nan", "infinity", "negative", "text", "nonscalar", "numeric-string", "boolean"])
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


def test_fingerprint_identifies_loaded_bytes_even_after_file_changes(trained_run):
    expected = sha256(trained_run.bundle_path.read_bytes()).hexdigest()
    loaded = predictor._load_model(trained_run.config.name)
    assert loaded["_artifact_sha256"] == expected
    trained_run.bundle_path.write_bytes(b"changed on disk after loading")
    assert predictor._load_model(trained_run.config.name) is loaded
    assert loaded["_artifact_sha256"] == expected


def test_tampered_bundle_rejected_before_joblib_deserialization(trained_run, monkeypatch):
    import json
    import joblib

    manifest_path = trained_run.bundle_path.parent.parent / "manifest.json"
    expected = sha256(trained_run.bundle_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps({
        "schema_version": 1,
        "bundles": {trained_run.config.name: {"path": "inference_bundle.pkl", "sha256": expected}},
    }))
    trained_run.bundle_path.write_bytes(b"corrupted pickle payload")

    monkeypatch.setattr(joblib, "load", lambda *a, **kw: pytest.fail("joblib.load ran on unverified bytes"))
    with pytest.raises(ValueError, match="integrity check failed"):
        predictor._load_model(trained_run.config.name)

    manifest_path.unlink()
    monkeypatch.setenv("SECURENET_MODEL_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="integrity check failed"):
        predictor._load_model(trained_run.config.name)


def test_repo_manifest_covers_registered_datasets():
    repo_models = Path(predictor.__file__).resolve().parent / "models"
    manifest = json.loads((repo_models / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert set(manifest["bundles"]) == set(datasets.DATASETS)
    for name, entry in manifest["bundles"].items():
        assert entry["path"] == f"{datasets.DATASETS[name].run_directory}/inference_bundle.pkl"
        assert len(bytes.fromhex(entry["sha256"])) == 32


@pytest.mark.skipif(os.getenv("SECURENET_VERIFY_INSTALLED_MODELS") != "1",
                    reason="Set SECURENET_VERIFY_INSTALLED_MODELS=1 to verify local saved bundles")
def test_installed_inference_bundles_match_manifest():
    repo_models = Path(predictor.__file__).resolve().parent / "models"
    manifest = json.loads((repo_models / "manifest.json").read_text(encoding="utf-8"))
    for name, entry in manifest["bundles"].items():
        bundle_file = repo_models / entry["path"]
        assert bundle_file.is_file(), f"Missing bundle for {name}: {bundle_file}"
        assert sha256(bundle_file.read_bytes()).hexdigest() == entry["sha256"]


@pytest.mark.parametrize("symlink_kind", ["file", "directory"])
@pytest.mark.parametrize("trusted_manifest_exists", [True, False], ids=["pinned", "missing-manifest"])
def test_registered_symlinks_cannot_change_manifest_trust(
        dataset_case, isolated_project, monkeypatch, symlink_kind, trusted_manifest_exists):
    config = datasets.get_dataset(dataset_case.name)
    models_root = config.models_dir.parent
    models_root.mkdir(parents=True)
    monkeypatch.setattr(predictor, "_REPO_MODELS_DIR", models_root)
    monkeypatch.delenv("SECURENET_MODEL_SHA256", raising=False)

    external_root = isolated_project / "external"
    external_dir = external_root / "candidate"
    external_dir.mkdir(parents=True)
    external_bundle = external_dir / "inference_bundle.pkl"
    external_bundle.write_bytes(b"unverified bytes must never reach joblib")
    # Even a matching manifest supplied by the external target must be ignored.
    (external_root / "manifest.json").write_text(json.dumps({"bundles": {
        config.name: {"sha256": sha256(external_bundle.read_bytes()).hexdigest()}}}))
    if trusted_manifest_exists:
        (models_root / "manifest.json").write_text(json.dumps({"bundles": {
            config.name: {"sha256": "0" * 64}}}))
    if symlink_kind == "file":
        config.models_dir.mkdir()
        (config.models_dir / "inference_bundle.pkl").symlink_to(external_bundle)
    else:
        config.models_dir.symlink_to(external_dir, target_is_directory=True)

    monkeypatch.setattr(predictor.joblib, "load",
                        lambda *a, **kw: pytest.fail("Unverified symlink reached deserialization"))
    message = "integrity check failed" if trusted_manifest_exists else "Missing model integrity manifest"
    with pytest.raises(ValueError, match=message):
        predictor._load_model(config.name)


def test_cached_bundle_enforces_current_explicit_and_environment_pins(trained_run, monkeypatch):
    name = trained_run.config.name
    loaded = predictor._load_model(name)
    digest = loaded["_artifact_sha256"]
    assert predictor._load_model(name, expected_sha256=digest.upper()) is loaded
    with pytest.raises(ValueError, match="integrity check failed"):
        predictor._load_model(name, expected_sha256="0" * 64)
    with pytest.raises(ValueError, match="Invalid SHA-256"):
        predictor._load_model(name, expected_sha256="invalid")
    monkeypatch.setenv("SECURENET_MODEL_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="integrity check failed"):
        predictor._load_model(name)
    # An explicit pin retains precedence over the process-wide pin.
    assert predictor._load_model(name, expected_sha256=digest) is loaded
    monkeypatch.setenv("SECURENET_MODEL_SHA256", digest)
    assert predictor._load_model(name) is loaded
    monkeypatch.setenv("SECURENET_MODEL_SHA256", "invalid")
    with pytest.raises(ValueError, match="Invalid SHA-256"):
        predictor._load_model(name)
