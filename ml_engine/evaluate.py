"""Evaluate the validation-selected Friday model on original held-out flows."""

import json
import os
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from ml_engine.preprocess import SELECTED_COLUMNS, LABEL_COLUMN, SPLITS_PATH, REPORTS_DIR, sha256_file
from ml_engine.train import BUNDLE_PATH, score_predictions


def evaluate_model():
    if not os.path.exists(BUNDLE_PATH):
        raise FileNotFoundError("Run python -m ml_engine.train first")
    bundle = joblib.load(BUNDLE_PATH)
    metadata = bundle["metadata"]
    if sha256_file(SPLITS_PATH) != metadata["split_artifact_sha256"]:
        raise ValueError("Split artifact changed since training; evaluation refused")
    payload = joblib.load(SPLITS_PATH)
    test = payload["splits"]["test"]
    scaler = bundle["scaler"]
    encoder = bundle["label_encoder"]
    X_test = scaler.transform(test[SELECTED_COLUMNS].to_numpy(dtype=float))
    y_test = encoder.transform(test[LABEL_COLUMN])
    prediction = bundle["model"].predict(X_test)
    classes = list(encoder.classes_)
    result = {
        "selected_model": metadata["selected_model"],
        "selection": metadata["selection_metric"],
        "test_rows": len(test),
        "test_class_counts": test[LABEL_COLUMN].value_counts().sort_index().to_dict(),
        "limitations": metadata["data_audit"]["limitations"],
        **score_predictions(y_test, prediction, classes),
    }
    report_dir = Path(REPORTS_DIR)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n")
    plt.figure(figsize=(8, 6))
    sns.heatmap(np.array(result["confusion_matrix"]), annot=True, fmt="d", cmap="Blues",
                xticklabels=classes, yticklabels=classes)
    plt.xlabel("Predicted label")
    plt.ylabel("True label")
    plt.title(f"Friday held-out test — {metadata['selected_model']}")
    plt.tight_layout()
    plt.savefig(report_dir / "confusion_matrix.png", dpi=150)
    plt.close()
    print(json.dumps(result, indent=2), flush=True)
    return result


if __name__ == "__main__":
    evaluate_model()
