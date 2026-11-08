"""Fit transforms on training data; select a weekday model on validation only."""

import json
import os
import platform
import time
from importlib.metadata import version
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from ml_engine.datasets import get_dataset, dataset_argument

from ml_engine.preprocess import (
    SELECTED_COLUMNS, LABEL_COLUMN, MODELS_DIR, SPLITS_PATH, SCHEMA_VERSION,
    REPORTS_DIR, sha256_file,
)

RF_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest.pkl")
XGB_MODEL_PATH = os.path.join(MODELS_DIR, "xgboost.pkl")
BUNDLE_PATH = os.path.join(MODELS_DIR, "inference_bundle.pkl")


def fit_training_transforms(train):
    """Only original training rows determine feature/label transforms."""
    scaler = StandardScaler().fit(train[SELECTED_COLUMNS].to_numpy(dtype=float))
    encoder = LabelEncoder().fit(train[LABEL_COLUMN])
    return scaler, encoder


def score_predictions(y_true, y_pred, class_names):
    labels = np.arange(len(class_names))
    benign = class_names.index("BENIGN")
    mask = y_true == benign
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "benign_false_positive_rate": float(np.mean(y_pred[mask] != benign)),
        "classification_report": classification_report(
            y_true, y_pred, labels=labels, target_names=class_names,
            output_dict=True, zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
    }


def train_model(dataset="friday", splits_path=None, models_dir=None, reports_dir=None):
    config = get_dataset(dataset)
    splits_path = Path(splits_path or (SPLITS_PATH if dataset == "friday" else config.splits_path))
    output = Path(models_dir or (MODELS_DIR if dataset == "friday" else config.models_dir))
    reports_dir = Path(reports_dir or (REPORTS_DIR if dataset == "friday" else config.reports_dir))
    bundle_path = (
        Path(BUNDLE_PATH) if dataset == "friday" and models_dir is None
        else output / "inference_bundle.pkl"
    )
    if not splits_path.exists():
        raise FileNotFoundError("Run python -m ml_engine.preprocess first")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"Preserve or rename existing run before retraining: {output}")
    payload = joblib.load(splits_path)
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Legacy processed data rejected; rerun preprocessing")
    if payload.get("dataset", "friday") != dataset:
        raise ValueError("Split dataset does not match requested training dataset")
    if payload["audit"]["feature_names"] != SELECTED_COLUMNS:
        raise ValueError("Split feature schema does not match training schema")
    train = payload["splits"]["train"]
    validation = payload["splits"]["validation"]
    if any(set(part[LABEL_COLUMN]) != set(config.classes) for part in payload["splits"].values()):
        raise ValueError("Split classes do not match the dataset label policy")
    scaler, encoder = fit_training_transforms(train)
    X_train = scaler.transform(train[SELECTED_COLUMNS].to_numpy(dtype=float))
    X_validation = scaler.transform(validation[SELECTED_COLUMNS].to_numpy(dtype=float))
    y_train = encoder.transform(train[LABEL_COLUMN])
    y_validation = encoder.transform(validation[LABEL_COLUMN])
    classes = list(encoder.classes_)
    workers = min(config.max_workers, os.cpu_count() or 1)
    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=200, max_depth=25, min_samples_split=5,
            min_samples_leaf=2, max_features="sqrt", random_state=42,
            n_jobs=workers, class_weight="balanced",
        ),
        "xgboost": XGBClassifier(
            n_estimators=200, max_depth=10, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8, random_state=42,
            n_jobs=workers, eval_metric="mlogloss",
        ),
    }
    scores = {}
    for name, model in models.items():
        print(f"Training {name}: {len(train):,} original rows, {workers} workers ...", flush=True)
        started = time.monotonic()
        kwargs = {"sample_weight": compute_sample_weight("balanced", y_train)} if name == "xgboost" else {}
        model.fit(X_train, y_train, **kwargs)
        scores[name] = score_predictions(y_validation, model.predict(X_validation), classes)
        scores[name]["training_seconds"] = time.monotonic() - started
        print(f"{name}: validation macro F1={scores[name]['macro_f1']:.6f}, "
              f"benign FPR={scores[name]['benign_false_positive_rate']:.6f}", flush=True)
    winner = max(scores, key=lambda name: scores[name]["macro_f1"])
    metadata = {
        "dataset": dataset,
        "schema_version": SCHEMA_VERSION,
        "selected_model": winner,
        "selection_metric": "validation macro F1 (test set not used for selection)",
        "balancing": (
            "training-only BENIGN subsampling and balanced class weights; no synthetic rows"
            if "training_sampling" in payload["audit"]
            else "training-only balanced class weights; no resampling or synthetic rows"
        ),
        "feature_names": SELECTED_COLUMNS,
        "classes": classes,
        "scaler_fit_rows": int(scaler.n_samples_seen_),
        "data_audit": payload["audit"],
        "split_artifact_sha256": sha256_file(splits_path),
        "python": platform.python_version(),
        "dependencies": {name: version(name) for name in (
            "numpy", "pandas", "scikit-learn", "xgboost", "joblib",
        )},
        "code_sha256": {name: sha256_file(Path(__file__).parent / name)
                        for name in ("datasets.py", "preprocess.py", "train.py", "predictor.py", "evaluate.py")},
        "model_parameters": {name: {
            key: repr(value) if isinstance(value, float) and not np.isfinite(value) else value
            for key, value in model.get_params().items()
        } for name, model in models.items()},
        "validation": scores,
    }
    output.mkdir(parents=True, exist_ok=True)
    for name, model in models.items():
        joblib.dump(model, output / f"{name}.pkl")
    joblib.dump(scaler, output / "scaler.pkl")
    joblib.dump(encoder, output / "label_encoder.pkl")
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    # Publish all inference components together after both fits succeed.
    temporary_bundle = output / "inference_bundle.pending.pkl"
    joblib.dump({
        "model": models[winner], "scaler": scaler, "label_encoder": encoder,
        "metadata": metadata,
    }, temporary_bundle)
    temporary_bundle.replace(bundle_path)
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "training.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Selected {winner} using validation only. Artifacts: {output}", flush=True)
    return metadata


if __name__ == "__main__":
    train_model(dataset=dataset_argument(__doc__))
