"""
Preprocess CICIDS2017 Friday dataset for ML training.

12-step pipeline:
  1. Load friday.csv, keep only selected 20 feature columns + Label
  2. Drop duplicate header rows (Label == "Label")
  3. Merge Botnet + Botnet - Attempted → BOTNET
  4. Drop rows with infinite values
  5. Drop rows with null/missing values
  6. Undersample BENIGN to 50,000 rows
  7. Keep all Portscan rows
  8. Keep all DDoS rows
  9. Keep all BOTNET rows (~4,803)
  10. Combine into one DataFrame
  11. Apply SMOTE to balance BOTNET up to match others
  12. Scale features with StandardScaler, save scaler + cleaned data
"""

import os
import sys
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
import joblib


# ---------------------------------------------------------------------------
# Column selection — 20 features + Label (from the Friday.docx spec)
# ---------------------------------------------------------------------------
SELECTED_COLUMNS = [
    "Src Port",              # Column 2
    "Dst Port",              # Column 4
    "Protocol",              # Column 5
    "Flow Duration",         # Column 7
    "Total Fwd Packet",      # Column 8
    "Total Bwd packets",     # Column 9
    "Flow Bytes/s",          # Column 20
    "Flow Packets/s",        # Column 21
    "Flow IAT Mean",         # Column 22
    "Fwd Packets/s",         # Column 44
    "Bwd Packets/s",         # Column 45
    "Packet Length Min",     # Column 46
    "Packet Length Max",     # Column 47
    "Packet Length Mean",    # Column 48
    "FIN Flag Count",        # Column 51
    "SYN Flag Count",        # Column 52
    "RST Flag Count",        # Column 53
    "PSH Flag Count",        # Column 54
    "ACK Flag Count",        # Column 55
    "Average Packet Size",   # Column 60
]

LABEL_COLUMN = "Label"

# Paths (relative to project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RAW_CSV = os.path.join(PROJECT_ROOT, "dataset", "raw", "friday.csv")
PROCESSED_CSV = os.path.join(PROJECT_ROOT, "dataset", "processed", "cleaned_friday.csv")
MODELS_DIR = os.path.join(PROJECT_ROOT, "ml_engine", "models")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

BENIGN_SAMPLE_SIZE = 50_000


def preprocess_data():
    """Run the full 12-step preprocessing pipeline."""

    # -----------------------------------------------------------------------
    # Step 1 — Load friday.csv, keep only selected columns
    # -----------------------------------------------------------------------
    print("[Step 1] Loading friday.csv ...")
    df = pd.read_csv(RAW_CSV, low_memory=False)

    # Strip whitespace from column names (CICIDS headers have leading spaces)
    df.columns = df.columns.str.strip()

    # Verify all selected columns exist
    missing_cols = [c for c in SELECTED_COLUMNS if c not in df.columns]
    if missing_cols:
        sys.exit(f"ERROR: Missing columns in CSV: {missing_cols}")

    df = df[SELECTED_COLUMNS + [LABEL_COLUMN]]
    print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")

    # -----------------------------------------------------------------------
    # Step 2 — Drop duplicate header rows
    # -----------------------------------------------------------------------
    print("[Step 2] Dropping duplicate header rows ...")
    mask = df[LABEL_COLUMN].str.strip() == "Label"
    dropped = mask.sum()
    df = df[~mask].copy()
    print(f"  Dropped {dropped} header-duplicate rows")

    # -----------------------------------------------------------------------
    # Step 3 — Merge Botnet labels
    # -----------------------------------------------------------------------
    print("[Step 3] Merging Botnet labels ...")
    df[LABEL_COLUMN] = df[LABEL_COLUMN].str.strip()
    df[LABEL_COLUMN] = df[LABEL_COLUMN].replace({
        "Botnet": "BOTNET",
        "Botnet - Attempted": "BOTNET",
    })
    # Normalize remaining labels to uppercase
    df[LABEL_COLUMN] = df[LABEL_COLUMN].replace({
        "BENIGN": "BENIGN",
        "Portscan": "PORTSCAN",
        "DDoS": "DDOS",
    })
    print(f"  Labels after merge: {df[LABEL_COLUMN].value_counts().to_dict()}")

    # -----------------------------------------------------------------------
    # Step 4 — Drop infinite values
    # -----------------------------------------------------------------------
    print("[Step 4] Dropping infinite values ...")
    # Convert all feature columns to numeric first
    for col in SELECTED_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    inf_mask = np.isinf(df[SELECTED_COLUMNS]).any(axis=1)
    inf_count = inf_mask.sum()
    df = df[~inf_mask].copy()
    print(f"  Dropped {inf_count:,} rows with infinite values")

    # -----------------------------------------------------------------------
    # Step 5 — Drop null / missing values
    # -----------------------------------------------------------------------
    print("[Step 5] Dropping null values ...")
    null_count = df.isnull().any(axis=1).sum()
    df = df.dropna().copy()
    print(f"  Dropped {null_count:,} rows with null values")

    # -----------------------------------------------------------------------
    # Steps 6-9 — Undersample BENIGN, keep all others, combine
    # -----------------------------------------------------------------------
    print("[Step 6-9] Balancing classes ...")

    df_benign = df[df[LABEL_COLUMN] == "BENIGN"]
    df_portscan = df[df[LABEL_COLUMN] == "PORTSCAN"]
    df_ddos = df[df[LABEL_COLUMN] == "DDOS"]
    df_botnet = df[df[LABEL_COLUMN] == "BOTNET"]

    print(f"  Before balancing:")
    print(f"    BENIGN:   {len(df_benign):>10,}")
    print(f"    PORTSCAN: {len(df_portscan):>10,}")
    print(f"    DDOS:     {len(df_ddos):>10,}")
    print(f"    BOTNET:   {len(df_botnet):>10,}")

    # Step 6 — Undersample BENIGN to 50,000
    if len(df_benign) > BENIGN_SAMPLE_SIZE:
        df_benign = df_benign.sample(n=BENIGN_SAMPLE_SIZE, random_state=42)

    # Steps 7-9 — Keep all Portscan, DDoS, Botnet rows
    df_combined = pd.concat(
        [df_benign, df_portscan, df_ddos, df_botnet],
        ignore_index=True,
    )
    print(f"  After undersampling BENIGN: {len(df_combined):,} total rows")
    print(f"  Class distribution:")
    for label, count in df_combined[LABEL_COLUMN].value_counts().items():
        print(f"    {label}: {count:>10,}")

    # -----------------------------------------------------------------------
    # Step 10 — Apply SMOTE to balance BOTNET
    # -----------------------------------------------------------------------
    print("[Step 10] Applying SMOTE ...")

    X = df_combined[SELECTED_COLUMNS].values
    y_labels = df_combined[LABEL_COLUMN].values

    # Encode labels to integers for SMOTE
    le = LabelEncoder()
    y_encoded = le.fit_transform(y_labels)

    # SMOTE target: bring minority class up to match the smallest of the
    # majority classes (BENIGN = 50,000)
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y_encoded)  # type: ignore

    # Decode labels back
    y_labels_resampled = le.inverse_transform(y_resampled)

    print(f"  After SMOTE: {len(X_resampled):,} total rows")
    from collections import Counter
    dist = Counter(y_labels_resampled)
    for label, count in sorted(dist.items()):
        print(f"    {label}: {count:>10,}")

    # -----------------------------------------------------------------------
    # Step 11 — Scale features with StandardScaler
    # -----------------------------------------------------------------------
    print("[Step 11] Scaling features ...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_resampled)

    # -----------------------------------------------------------------------
    # Step 12 — Save everything
    # -----------------------------------------------------------------------
    print("[Step 12] Saving ...")

    # Build final DataFrame
    df_final = pd.DataFrame(X_scaled, columns=SELECTED_COLUMNS)
    df_final[LABEL_COLUMN] = y_labels_resampled

    # Ensure directories exist
    os.makedirs(os.path.dirname(PROCESSED_CSV), exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Save cleaned CSV
    df_final.to_csv(PROCESSED_CSV, index=False)
    print(f"  Saved cleaned data to {PROCESSED_CSV}")
    print(f"    Rows:    {len(df_final):,}")
    print(f"    Columns: {len(df_final.columns)}")
    print(f"    Nulls:   {df_final.isnull().sum().sum()}")

    # Save scaler and label encoder for later use by predictor
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le, LABEL_ENCODER_PATH)
    print(f"  Saved scaler to {SCALER_PATH}")
    print(f"  Saved label encoder to {LABEL_ENCODER_PATH}")

    print("\nPreprocessing complete!")
    return df_final


if __name__ == "__main__":
    preprocess_data()
