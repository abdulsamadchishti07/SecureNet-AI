"""
Evaluate trained models on the test set.

Generates for each model (Random Forest + XGBoost):
  - Classification report (precision, recall, F1 per class)
  - Confusion matrix (saved as PNG)
  - Overall accuracy comparison
"""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server/headless use
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)
import joblib

from ml_engine.preprocess import MODELS_DIR, LABEL_ENCODER_PATH
from ml_engine.train import RF_MODEL_PATH, XGB_MODEL_PATH, TEST_DATA_PATH


# Confusion matrix save paths
RF_CM_PATH = os.path.join(MODELS_DIR, "confusion_matrix_rf.png")
XGB_CM_PATH = os.path.join(MODELS_DIR, "confusion_matrix_xgb.png")


def plot_confusion_matrix(y_true, y_pred, labels, title, save_path):
    """Generate and save a confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=labels,
        yticklabels=labels,
    )
    plt.title(title, fontsize=14, fontweight="bold")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved confusion matrix → {save_path}")


def evaluate_single_model(model, X_test, y_test, label_names, model_name):
    """Evaluate a single model and print metrics."""
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")

    print(f"\n{'─' * 60}")
    print(f"  {model_name} — Results")
    print(f"{'─' * 60}")
    print(f"  Accuracy:          {acc:.4f}")
    print(f"  F1 (macro):        {f1_macro:.4f}")
    print(f"  F1 (weighted):     {f1_weighted:.4f}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=label_names, digits=4))

    return y_pred, acc, f1_macro


def evaluate_model():
    """Evaluate both Random Forest and XGBoost models."""

    print("=" * 60)
    print("  SecureNet AI — Model Evaluation")
    print("=" * 60)

    # -----------------------------------------------------------------------
    # Load test data and models
    # -----------------------------------------------------------------------
    if not os.path.exists(TEST_DATA_PATH):
        print(f"ERROR: Test data not found at {TEST_DATA_PATH}")
        print("       Run train.py first!")
        return

    print("\nLoading test data and models ...")
    test_data = joblib.load(TEST_DATA_PATH)
    X_test = test_data["X_test"]
    y_test = test_data["y_test"]
    print(f"  Test samples: {len(X_test):,}")

    le = joblib.load(LABEL_ENCODER_PATH)
    label_names = list(le.classes_)
    print(f"  Classes: {label_names}")

    # -----------------------------------------------------------------------
    # Evaluate Random Forest
    # -----------------------------------------------------------------------
    print("\nEvaluating Random Forest ...")
    rf_model = joblib.load(RF_MODEL_PATH)
    rf_pred, rf_acc, rf_f1 = evaluate_single_model(
        rf_model, X_test, y_test, label_names, "Random Forest (Primary)"
    )
    plot_confusion_matrix(
        y_test, rf_pred, label_names,
        "Random Forest — Confusion Matrix", RF_CM_PATH
    )

    # -----------------------------------------------------------------------
    # Evaluate XGBoost
    # -----------------------------------------------------------------------
    print("\nEvaluating XGBoost ...")
    xgb_model = joblib.load(XGB_MODEL_PATH)
    xgb_pred, xgb_acc, xgb_f1 = evaluate_single_model(
        xgb_model, X_test, y_test, label_names, "XGBoost (Comparison)"
    )
    plot_confusion_matrix(
        y_test, xgb_pred, label_names,
        "XGBoost — Confusion Matrix", XGB_CM_PATH
    )

    # -----------------------------------------------------------------------
    # Side-by-side comparison
    # -----------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  Model Comparison")
    print("=" * 60)
    print(f"  {'Metric':<20} {'Random Forest':>15} {'XGBoost':>15}")
    print(f"  {'-'*20} {'-'*15} {'-'*15}")
    print(f"  {'Accuracy':<20} {rf_acc:>15.4f} {xgb_acc:>15.4f}")
    print(f"  {'F1 (macro)':<20} {rf_f1:>15.4f} {xgb_f1:>15.4f}")

    winner = "Random Forest" if rf_f1 >= xgb_f1 else "XGBoost"
    print(f"\nBest model (by F1 macro): {winner}")
    print("=" * 60)
    print("\nEvaluation complete!")


if __name__ == "__main__":
    evaluate_model()
