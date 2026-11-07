"""
Real-time prediction using the trained Random Forest model.

Loads the primary model (Random Forest) and scaler once,
then exposes a predict() function for the sniffer pipeline.
"""

import os
import numpy as np
import joblib

from ml_engine.preprocess import (
    SELECTED_COLUMNS,
    MODELS_DIR,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
)
from ml_engine.train import RF_MODEL_PATH


# ---------------------------------------------------------------------------
# Lazy-loaded globals — initialized on first predict() call
# ---------------------------------------------------------------------------
_model = None
_scaler = None
_label_encoder = None


def _load_model():
    """Load the trained model, scaler, and label encoder into memory."""
    global _model, _scaler, _label_encoder

    if _model is not None:
        return  # Already loaded

    if not os.path.exists(RF_MODEL_PATH):
        raise FileNotFoundError(
            f"Trained model not found at {RF_MODEL_PATH}. "
            "Run train.py first!"
        )

    _model = joblib.load(RF_MODEL_PATH)
    _scaler = joblib.load(SCALER_PATH)
    _label_encoder = joblib.load(LABEL_ENCODER_PATH)


def predict(features):
    """
    Classify a single network flow.

    Parameters
    ----------
    features : dict
        Dictionary with the 20 selected feature names as keys.
        Example:
            {
                "Src Port": 443,
                "Dst Port": 52341,
                "Protocol": 6,
                "Flow Duration": 120000,
                ...
            }

    Returns
    -------
    dict
        {
            "label": str,         # e.g. "DDOS", "BENIGN", "PORTSCAN", "BOTNET"
            "confidence": float,  # probability of predicted class (0.0 - 1.0)
            "probabilities": dict # per-class probabilities
        }
    """
    _load_model()
    assert _scaler is not None
    assert _model is not None
    assert _label_encoder is not None

    # Build feature vector in the correct column order
    feature_vector = np.array(
        [features.get(col, 0) for col in SELECTED_COLUMNS]
    ).reshape(1, -1)

    # Scale features using the same scaler from preprocessing
    feature_scaled = _scaler.transform(feature_vector)

    # Predict
    prediction_encoded = _model.predict(feature_scaled)[0]
    probabilities = _model.predict_proba(feature_scaled)[0]

    # Decode label
    predicted_label = _label_encoder.inverse_transform([prediction_encoded])[0]
    confidence = float(np.max(probabilities))

    # Build per-class probability dict
    prob_dict = {
        _label_encoder.inverse_transform([i])[0]: float(p)
        for i, p in enumerate(probabilities)
    }

    return {
        "label": predicted_label,
        "confidence": confidence,
        "probabilities": prob_dict,
    }


def predict_batch(features_list):
    """
    Classify multiple network flows at once.

    Parameters
    ----------
    features_list : list[dict]
        List of feature dictionaries (same format as predict()).

    Returns
    -------
    list[dict]
        List of prediction results.
    """
    _load_model()
    assert _scaler is not None
    assert _model is not None
    assert _label_encoder is not None

    # Build feature matrix
    X = np.array([
        [f.get(col, 0) for col in SELECTED_COLUMNS]
        for f in features_list
    ])

    # Scale
    X_scaled = _scaler.transform(X)

    # Predict
    predictions = _model.predict(X_scaled)
    probabilities = _model.predict_proba(X_scaled)

    results = []
    for pred, probs in zip(predictions, probabilities):
        label = _label_encoder.inverse_transform([pred])[0]
        prob_dict = {
            _label_encoder.inverse_transform([i])[0]: float(p)
            for i, p in enumerate(probs)
        }
        results.append({
            "label": label,
            "confidence": float(np.max(probs)),
            "probabilities": prob_dict,
        })

    return results
