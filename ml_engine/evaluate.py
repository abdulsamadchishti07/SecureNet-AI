"""Evaluate a validation-selected weekday model on original held-out flows."""

import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from ml_engine.preprocess import SELECTED_COLUMNS, LABEL_COLUMN, SPLITS_PATH, REPORTS_DIR, sha256_file
from ml_engine.train import BUNDLE_PATH, score_predictions
from ml_engine.datasets import get_dataset, dataset_argument


def evaluate_model(dataset="friday", bundle_path=None, splits_path=None, reports_dir=None):
    config = get_dataset(dataset)
    bundle_path = Path(bundle_path or (
        BUNDLE_PATH if dataset == "friday" else config.models_dir / "inference_bundle.pkl"
    ))
    splits_path = Path(splits_path or (SPLITS_PATH if dataset == "friday" else config.splits_path))
    report_dir = Path(reports_dir or (REPORTS_DIR if dataset == "friday" else config.reports_dir))
    if not bundle_path.exists():
        raise FileNotFoundError("Run python -m ml_engine.train first")
    bundle = joblib.load(bundle_path)
    metadata = bundle["metadata"]
    if metadata.get("dataset", "friday") != dataset:
        raise ValueError("Bundle dataset does not match requested evaluation dataset")
    if sha256_file(splits_path) != metadata["split_artifact_sha256"]:
        raise ValueError("Split artifact changed since training; evaluation refused")
    payload = joblib.load(splits_path)
    if payload.get("dataset", "friday") != dataset:
        raise ValueError("Split dataset does not match requested evaluation dataset")
    test = payload["splits"]["test"]
    scaler = bundle["scaler"]
    encoder = bundle["label_encoder"]
    X_test = scaler.transform(test[SELECTED_COLUMNS].to_numpy(dtype=float))
    y_test = encoder.transform(test[LABEL_COLUMN])
    prediction = bundle["model"].predict(X_test)
    classes = list(encoder.classes_)
    result = {
        "dataset": dataset,
        "selected_model": metadata["selected_model"],
        "selection": metadata["selection_metric"],
        "test_rows": len(test),
        "test_class_counts": test[LABEL_COLUMN].value_counts().sort_index().to_dict(),
        "limitations": metadata["data_audit"]["limitations"],
        **score_predictions(y_test, prediction, classes),
    }
    if "_original_label" in test:
        result["original_label_results"] = {}
        original_labels = test["_original_label"].to_numpy()
        for label in sorted(set(original_labels)):
            mask = original_labels == label
            predicted_names = encoder.inverse_transform(prediction[mask].astype(int))
            result["original_label_results"][label] = {
                "support": int(mask.sum()),
                "family_accuracy": float(np.mean(prediction[mask] == y_test[mask])),
                "predicted_label_counts": {name: int((predicted_names == name).sum()) for name in classes},
            }
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n")
    plt.figure(figsize=(8, 6))
    sns.heatmap(np.array(result["confusion_matrix"]), annot=True, fmt="d", cmap="Blues",
                xticklabels=classes, yticklabels=classes)
    plt.xlabel("Predicted label")
    plt.ylabel("True label")
    plt.title(f"{dataset.title()} held-out test — {metadata['selected_model']}")
    plt.tight_layout()
    plt.savefig(report_dir / "confusion_matrix.png", dpi=150)
    plt.close()
    print(json.dumps(result, indent=2), flush=True)
    return result


if __name__ == "__main__":
    evaluate_model(dataset=dataset_argument(__doc__))
