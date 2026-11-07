"""Clean Friday flows and reserve grouped, unresampled holdouts.

This stage never fits a scaler or balances classes. Training owns those steps.
"""

import hashlib
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold


SELECTED_COLUMNS = [
    "Src Port", "Dst Port", "Protocol", "Flow Duration",
    "Total Fwd Packet", "Total Bwd packets", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min",
    "Packet Length Max", "Packet Length Mean", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size",
]
LABEL_COLUMN = "Label"
CLASSES = ("BENIGN", "BOTNET", "DDOS", "PORTSCAN")
METADATA_COLUMNS = ["Src IP dec", "Dst IP dec"]
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RAW_CSV = os.path.join(PROJECT_ROOT, "dataset", "raw", "friday.csv")
PROCESSED_CSV = os.path.join(PROJECT_ROOT, "dataset", "processed", "cleaned_friday.csv")
SPLITS_PATH = os.path.join(PROJECT_ROOT, "dataset", "processed", "friday_splits.pkl")
# Keep the previous, leaky baseline in models/ untouched.
MODELS_DIR = os.path.join(PROJECT_ROOT, "ml_engine", "models", "friday_v2")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "friday")
SCHEMA_VERSION = 2
RANDOM_STATE = 42


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def clean_data(raw):
    """Remove invalid rows, identical inputs and conflicting labels."""
    df = raw.copy()
    df.columns = df.columns.str.strip()
    required = SELECTED_COLUMNS + [LABEL_COLUMN] + METADATA_COLUMNS
    missing = sorted(set(required) - set(df.columns))
    if missing:
        raise ValueError(f"Missing Friday columns: {missing}")
    df = df[required].copy()
    df["_row_id"] = np.arange(len(df))
    audit = {"raw_rows": len(df)}
    labels = df[LABEL_COLUMN].astype("string").str.strip()
    headers = labels.eq("Label").fillna(False)
    audit["duplicate_header_rows"] = int(headers.sum())
    df = df.loc[~headers].copy()
    df[LABEL_COLUMN] = labels.loc[~headers].replace({
        "Botnet": "BOTNET", "Botnet - Attempted": "BOTNET",
        "Portscan": "PORTSCAN", "DDoS": "DDOS",
    })
    unknown = set(df[LABEL_COLUMN].dropna()) - set(CLASSES)
    if unknown:
        raise ValueError(f"Unexpected Friday labels (not silently discarded): {unknown}")
    for column in SELECTED_COLUMNS + METADATA_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce")
    invalid = (
        ~np.isfinite(df[SELECTED_COLUMNS + METADATA_COLUMNS]).all(axis=1)
        | df[LABEL_COLUMN].isna()
        | (df[SELECTED_COLUMNS + METADATA_COLUMNS] < 0).any(axis=1)
    )
    audit["invalid_rows"] = int(invalid.sum())
    df = df.loc[~invalid].copy()
    before = len(df)
    df = df.drop_duplicates(SELECTED_COLUMNS + [LABEL_COLUMN])
    audit["same_label_duplicates_removed"] = before - len(df)
    # Identical inputs with different labels are ambiguous: exclude all of them.
    ambiguous = df.duplicated(SELECTED_COLUMNS, keep=False)
    audit["conflicting_label_rows_removed"] = int(ambiguous.sum())
    df = df.loc[~ambiguous].copy()
    if df.empty or set(df[LABEL_COLUMN]) != set(CLASSES):
        raise ValueError("Cleaning must leave examples of all four Friday classes")
    # Canonical endpoints keep reverse and repeated connections together.
    # IPs are split metadata only, never classifier features.
    source = df["Src IP dec"].astype("int64").astype(str) + ":" + df["Src Port"].astype("int64").astype(str)
    target = df["Dst IP dec"].astype("int64").astype(str) + ":" + df["Dst Port"].astype("int64").astype(str)
    forward = source <= target
    keys = source.where(forward, target) + "|" + target.where(forward, source)
    keys += "|" + df["Protocol"].astype("int64").astype(str)
    df["_group_id"] = pd.factorize(keys, sort=True)[0]
    df = df.drop(columns=METADATA_COLUMNS).reset_index(drop=True)
    audit["clean_rows"] = len(df)
    audit["class_counts"] = df[LABEL_COLUMN].value_counts().sort_index().to_dict()
    audit["connection_groups"] = int(df["_group_id"].nunique())
    return df, audit


def split_data(df):
    """Approximately 60/20/20, stratified with disjoint connection groups."""
    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    remaining, test = next(outer.split(df, df[LABEL_COLUMN], df["_group_id"]))
    development = df.iloc[remaining]
    inner = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=RANDOM_STATE)
    train, validation = next(inner.split(
        development, development[LABEL_COLUMN], development["_group_id"]
    ))
    splits = {
        "train": development.iloc[train].copy(),
        "validation": development.iloc[validation].copy(),
        "test": df.iloc[test].copy(),
    }
    seen_groups = set()
    for name, part in splits.items():
        if set(part[LABEL_COLUMN]) != set(CLASSES):
            raise ValueError(f"{name} does not contain all classes; revisit grouping")
        groups = set(part["_group_id"])
        if groups & seen_groups:
            raise ValueError("Connection leakage between partitions")
        seen_groups.update(groups)
    return splits


def preprocess_data(raw_csv=RAW_CSV, processed_dir=None, reports_dir=REPORTS_DIR):
    """Persist raw-valued partitions without overwriting inference transforms."""
    processed_dir = Path(processed_dir or Path(PROCESSED_CSV).parent)
    processed_dir.mkdir(parents=True, exist_ok=True)
    raw = pd.read_csv(raw_csv, usecols=lambda c: c.strip() in (
        SELECTED_COLUMNS + METADATA_COLUMNS + [LABEL_COLUMN]
    ), low_memory=False)
    df, audit = clean_data(raw)
    print(f"Cleaned {len(df):,} flows; splitting connection groups ...", flush=True)
    splits = split_data(df)
    audit.update({
        "schema_version": SCHEMA_VERSION,
        "source_sha256": sha256_file(raw_csv),
        "feature_names": SELECTED_COLUMNS,
        "random_state": RANDOM_STATE,
        "split_method": "stratified connection groups, approximately 60/20/20",
        "limitations": [
            "Not an independent-host or chronological evaluation.",
            "Timestamp values lack full date/hour information; no temporal split used.",
            "Related attack campaigns can remain across connection groups.",
        ],
        "splits": {name: {
            "rows": len(part),
            "class_counts": part[LABEL_COLUMN].value_counts().sort_index().to_dict(),
            "groups": int(part["_group_id"].nunique()),
        } for name, part in splits.items()},
    })
    payload = {"schema_version": SCHEMA_VERSION, "audit": audit, "splits": splits}
    df[SELECTED_COLUMNS + [LABEL_COLUMN]].to_csv(processed_dir / "cleaned_friday.csv", index=False)
    joblib.dump(payload, processed_dir / "friday_splits.pkl")
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    (Path(reports_dir) / "data_audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    print(json.dumps(audit, indent=2), flush=True)
    print("Saved raw-valued splits. No scaling, undersampling, or SMOTE performed.", flush=True)
    return payload


if __name__ == "__main__":
    preprocess_data()
