"""Prepare Monday normal traffic and evaluate saved models' false alarms.

Monday has no attack labels. This module never fits or selects a classifier.
"""

import argparse
import hashlib
import json
import platform
from importlib.metadata import version
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml_engine.datasets import DATASETS, DatasetConfig, get_dataset
from ml_engine.preprocess import (
    LABEL_COLUMN, METADATA_COLUMNS, SELECTED_COLUMNS, SCHEMA_VERSION,
    clean_data, sha256_file,
)

MONDAY = DatasetConfig("monday", "monday_reference_only", ("BENIGN",), {})


def feature_hashes(frame):
    """Normalize numeric dtypes before cross-file equality fingerprints."""
    numeric = frame[SELECTED_COLUMNS].astype(float)
    numeric[numeric == 0] = 0.0  # numeric -0.0 and 0.0 are the same input
    return pd.util.hash_pandas_object(
        numeric, index=False
    ).to_numpy(dtype=np.uint64)


def connection_hashes(frame):
    source = frame["Src IP dec"].astype("int64").astype(str) + ":" + frame["Src Port"].astype("int64").astype(str)
    target = frame["Dst IP dec"].astype("int64").astype(str) + ":" + frame["Dst Port"].astype("int64").astype(str)
    forward = source <= target
    keys = source.where(forward, target) + "|" + target.where(forward, source)
    keys += "|" + frame["Protocol"].astype("int64").astype(str)
    return pd.util.hash_pandas_object(keys, index=False).to_numpy(dtype=np.uint64)


def read_source(path):
    required = SELECTED_COLUMNS + METADATA_COLUMNS + [LABEL_COLUMN]
    raw = pd.read_csv(path, usecols=lambda c: c.strip() in required, low_memory=False)
    raw.columns = raw.columns.str.strip()
    return raw


def prepare_monday(config=MONDAY):
    reference_path = config.processed_dir / "monday_reference.pkl"
    if reference_path.exists():
        raise FileExistsError("Archive Monday reference data and reports before reprocessing")
    raw = read_source(config.raw_csv)
    frame, audit = clean_data(raw, config=config)
    # Group IDs are local to a file; retain comparable, canonical fingerprints.
    original_rows = raw.iloc[frame["_row_id"]]
    frame["_connection_hash"] = connection_hashes(original_rows)
    frame["_feature_hash"] = feature_hashes(frame)
    audit.update({
        "dataset": "monday", "role": "normal-only reference; no model training",
        "schema_version": SCHEMA_VERSION, "feature_names": SELECTED_COLUMNS,
        "source_sha256": sha256_file(config.raw_csv),
        "python": platform.python_version(),
        "dependencies": {name: version(name) for name in (
            "numpy", "pandas", "scikit-learn", "joblib",
        )},
        "code_sha256": {name: sha256_file(Path(__file__).parent / name)
                        for name in ("monday.py", "preprocess.py", "datasets.py")},
        "limitations": [
            "BENIGN only: cannot measure attack recall, attack precision or multiclass F1.",
            "False positives assume the dataset's BENIGN annotations are correct.",
            "Not an independent-host or live-traffic evaluation; dataset provenance remains open.",
            "Connection keys omit dates and may conservatively match different days' reused endpoints.",
        ],
    })
    config.processed_dir.mkdir(parents=True, exist_ok=True)
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    frame[SELECTED_COLUMNS + [LABEL_COLUMN]].to_csv(config.processed_dir / "cleaned_monday.csv", index=False)
    joblib.dump({"schema_version": SCHEMA_VERSION, "dataset": "monday",
                 "audit": audit, "reference": frame}, reference_path)
    (config.reports_dir / "data_audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    print(json.dumps(audit, indent=2), flush=True)
    return audit


def load_existing_run(day):
    config = get_dataset(day)
    bundle_path = config.models_dir / "inference_bundle.pkl"
    if not bundle_path.exists():
        raise FileNotFoundError(f"Saved {day} model missing: {bundle_path}")
    bundle = joblib.load(bundle_path)
    metadata = bundle["metadata"]
    if metadata.get("dataset", "friday") != day:
        raise ValueError("Saved model dataset identity mismatch")
    if metadata["schema_version"] != SCHEMA_VERSION or metadata["feature_names"] != SELECTED_COLUMNS:
        raise ValueError("Saved model feature schema mismatch")
    if set(metadata["classes"]) != set(config.classes):
        raise ValueError("Saved model classes do not match configured dataset")
    if list(bundle["label_encoder"].classes_) != metadata["classes"]:
        raise ValueError("Saved model encoder classes do not match metadata")
    for component in ("model", "scaler"):
        if bundle[component].n_features_in_ != len(SELECTED_COLUMNS):
            raise ValueError(f"Saved {component} feature count mismatch")
    if sha256_file(config.splits_path) != metadata["split_artifact_sha256"]:
        raise ValueError(f"Saved {day} splits changed since training")
    payload = joblib.load(config.splits_path)
    if payload.get("schema_version") != SCHEMA_VERSION or payload.get("dataset", "friday") != day:
        raise ValueError("Saved split schema/dataset identity mismatch")
    if sha256_file(config.raw_csv) != payload["audit"]["source_sha256"]:
        raise ValueError(f"Saved {day} raw source changed since preparation")
    source = read_source(config.raw_csv)
    parts = list(payload["splits"].values())
    previous = pd.concat(parts, ignore_index=True)
    return bundle, {
        "feature_hashes": np.unique(feature_hashes(previous)),
        "connection_hashes": np.unique(connection_hashes(source.iloc[previous["_row_id"]])),
        "partitions_considered": list(payload["splits"]),
        "bundle_sha256": sha256_file(bundle_path),
        "splits_sha256": metadata["split_artifact_sha256"],
    }


def prediction_labels(bundle, frame):
    names = []
    # Bound inference memory and avoid creating all models' probability matrices.
    for start in range(0, len(frame), 20_000):
        values = frame.iloc[start:start + 20_000][SELECTED_COLUMNS].to_numpy(dtype=float)
        encoded = bundle["model"].predict(bundle["scaler"].transform(values))
        names.append(bundle["label_encoder"].inverse_transform(encoded.astype(int)))
    return np.concatenate(names) if names else np.array([], dtype=str)


def false_alarm_metrics(labels):
    if len(labels) == 0:
        return {"rows": 0, "false_positives": 0, "false_positive_rate": None,
                "predicted_label_counts": {}}
    counts = pd.Series(labels).value_counts().sort_index().to_dict()
    false_positives = int((labels != "BENIGN").sum())
    return {"rows": len(labels), "false_positives": false_positives,
            "false_positive_rate": false_positives / len(labels),
            "predicted_label_counts": counts}


def evaluate_monday(config=MONDAY, model_days=None):
    model_days = list(DATASETS) if model_days is None else list(model_days)
    if not model_days or len(model_days) != len(set(model_days)):
        raise ValueError("Choose at least one distinct saved model")
    reference_path = config.processed_dir / "monday_reference.pkl"
    payload = joblib.load(reference_path)
    if payload.get("dataset") != "monday" or payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Not a supported Monday reference artifact")
    if sha256_file(config.raw_csv) != payload["audit"]["source_sha256"]:
        raise ValueError("Monday source changed after preparation")
    frame = payload["reference"]
    if set(frame[LABEL_COLUMN]) != {"BENIGN"}:
        raise ValueError("Monday false-alarm evaluation requires BENIGN-only inputs")
    feature_overlap = np.zeros(len(frame), dtype=bool)
    group_overlap = np.zeros(len(frame), dtype=bool)
    exposures = {}
    bundles = {}
    for day in model_days:
        print(f"Checking previous {day} exposure ...", flush=True)
        bundles[day], prior = load_existing_run(day)
        features = np.isin(frame["_feature_hash"].to_numpy(), prior["feature_hashes"])
        groups = np.isin(frame["_connection_hash"].to_numpy(), prior["connection_hashes"])
        feature_overlap |= features
        group_overlap |= groups
        exposures[day] = {
            "feature_overlap_rows": int(features.sum()),
            "connection_overlap_rows": int(groups.sum()),
            "either_overlap_rows": int((features | groups).sum()),
            **{key: prior[key] for key in ("partitions_considered", "bundle_sha256", "splits_sha256")},
        }
    # One common strict cohort makes the four model results comparable.
    eligible = ~(feature_overlap | group_overlap)
    selected = frame.loc[eligible]
    result = {
        "dataset": "monday", "role": "false-alarm evaluation only; no fitting or selection",
        "source_sha256": payload["audit"]["source_sha256"],
        "reference_sha256": sha256_file(reference_path),
        "full_reference_rows": len(frame),
        "common_cohort": {
            "models_considered": model_days, "eligible_rows": len(selected),
            "excluded_feature_overlap_rows": int(feature_overlap.sum()),
            "excluded_connection_overlap_rows": int(group_overlap.sum()),
            "excluded_either_overlap_rows": int((~eligible).sum()),
            "cohort_row_ids_sha256": hashlib.sha256(
                selected["_row_id"].to_numpy(dtype="<i8").tobytes()
            ).hexdigest(),
            "policy": "exclude exact numeric inputs or canonical connections in any prior train/validation/test partition",
        },
        "prior_exposure": exposures,
        "limitations": payload["audit"]["limitations"] + [
            "Full-reference results can overlap previous runs; common-cohort results use explicit exclusions.",
            "Excluding overlap changes the evaluation population; neither cohort proves live performance.",
            "No attack labels: do not compare attack recall or select a universal winning classifier from this result.",
        ],
        "models": {},
    }
    for day in model_days:
        print(f"Evaluating saved {day} model on Monday ...", flush=True)
        bundle = bundles[day]
        labels = prediction_labels(bundle, frame)
        result["models"][day] = {
            "selected_model": bundle["metadata"]["selected_model"],
            "full_reference": false_alarm_metrics(labels),
            "common_cohort": false_alarm_metrics(labels[eligible]),
        }
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    (config.reports_dir / "false_alarm_evaluation.json").write_text(json.dumps(result, indent=2) + "\n")
    joblib.dump({"eligible_row_ids": selected["_row_id"].to_numpy(),
                 "reference_sha256": result["reference_sha256"]},
                config.processed_dir / "monday_common_cohort.pkl")
    print(json.dumps(result, indent=2), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--prepare-only", action="store_true")
    action.add_argument("--evaluate-only", action="store_true")
    parser.add_argument("--models", nargs="+", choices=tuple(DATASETS), default=list(DATASETS))
    args = parser.parse_args()
    if not args.evaluate_only:
        prepare_monday()
    if not args.prepare_only:
        evaluate_monday(model_days=args.models)


if __name__ == "__main__":
    main()
