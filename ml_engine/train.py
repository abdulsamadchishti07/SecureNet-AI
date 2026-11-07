"""
Train ML models on the preprocessed CICIDS2017 Friday dataset.

Models:
  - Primary:    Random Forest Classifier
  - Comparison: XGBoost Classifier

Both models are saved to ml_engine/models/ for later evaluation and prediction.
"""

import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
import joblib
import time

from ml_engine.preprocess import (
    SELECTED_COLUMNS,
    LABEL_COLUMN,
    MODELS_DIR,
    PROCESSED_CSV,
    LABEL_ENCODER_PATH,
)


# Model save paths
RF_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest.pkl")
XGB_MODEL_PATH = os.path.join(MODELS_DIR, "xgboost.pkl")
TEST_DATA_PATH = os.path.join(MODELS_DIR, "test_data.pkl")


def train_model():
    """Train Random Forest (primary) and XGBoost (comparison) models."""

    # -----------------------------------------------------------------------
    # Load cleaned data
    # -----------------------------------------------------------------------
    print("=" * 60)
    print("  SecureNet AI — Model Training")
    print("=" * 60)

    if not os.path.exists(PROCESSED_CSV):
        print(f"ERROR: Cleaned data not found at {PROCESSED_CSV}")
        print("       Run preprocess.py first!")
        return

    print(f"\n[1/5] Loading cleaned data from {PROCESSED_CSV} ...")
    df = pd.read_csv(PROCESSED_CSV)
    print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")

    X = df[SELECTED_COLUMNS].values
    y_labels = df[LABEL_COLUMN].values

    # -----------------------------------------------------------------------
    # Encode labels
    # -----------------------------------------------------------------------
    print("[2/5] Encoding labels ...")
    le = joblib.load(LABEL_ENCODER_PATH)
    y = le.transform(y_labels)
    print(f"  Classes: {list(le.classes_)}")

    # -----------------------------------------------------------------------
    # Train/test split (80/20, stratified)
    # -----------------------------------------------------------------------
    print("[3/5] Splitting data (80% train / 20% test, stratified) ...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train):,} rows")
    print(f"  Test:  {len(X_test):,} rows")

    # Save test data for evaluation
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump({"X_test": X_test, "y_test": y_test}, TEST_DATA_PATH)

    # -----------------------------------------------------------------------
    # Train Random Forest (Primary Model)
    # -----------------------------------------------------------------------
    print("\n[4/5] Training Random Forest (primary model) ...")
    rf_start = time.time()

    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    rf_model.fit(X_train, y_train)
    rf_time = time.time() - rf_start

    rf_train_acc = rf_model.score(X_train, y_train)
    rf_test_acc = rf_model.score(X_test, y_test)
    print(f"  Training time:  {rf_time:.1f}s")
    print(f"  Train accuracy: {rf_train_acc:.4f}")
    print(f"  Test accuracy:  {rf_test_acc:.4f}")

    joblib.dump(rf_model, RF_MODEL_PATH)
    print(f"  Saved → {RF_MODEL_PATH}")

    # -----------------------------------------------------------------------
    # Train XGBoost (Comparison Model)
    # -----------------------------------------------------------------------
    print("\n[5/5] Training XGBoost (comparison model) ...")
    xgb_start = time.time()

    xgb_model = XGBClassifier(
        n_estimators=200,
        max_depth=10,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        use_label_encoder=False,
        eval_metric="mlogloss",
    )
    xgb_model.fit(X_train, y_train)
    xgb_time = time.time() - xgb_start

    xgb_train_acc = xgb_model.score(X_train, y_train)
    xgb_test_acc = xgb_model.score(X_test, y_test)
    print(f"  Training time:  {xgb_time:.1f}s")
    print(f"  Train accuracy: {xgb_train_acc:.4f}")
    print(f"  Test accuracy:  {xgb_test_acc:.4f}")

    joblib.dump(xgb_model, XGB_MODEL_PATH)
    print(f"  Saved → {XGB_MODEL_PATH}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  Training Summary")
    print("=" * 60)
    print(f"  {'Model':<20} {'Train Acc':>10} {'Test Acc':>10} {'Time':>8}")
    print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*8}")
    print(f"  {'Random Forest':<20} {rf_train_acc:>10.4f} {rf_test_acc:>10.4f} {rf_time:>7.1f}s")
    print(f"  {'XGBoost':<20} {xgb_train_acc:>10.4f} {xgb_test_acc:>10.4f} {xgb_time:>7.1f}s")
    print("=" * 60)
    print("\nTraining complete! Models saved to ml_engine/models/")


if __name__ == "__main__":
    train_model()
