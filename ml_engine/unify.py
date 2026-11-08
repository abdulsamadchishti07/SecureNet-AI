"""Combine original weekday CSVs into an experimental seven-class detector run.

Global cleaning/grouping precedes the split. Only original training BENIGN rows
are subsampled; validation and test retain their cleaned source prevalence.
"""

import argparse
from collections import Counter
import gc
import json
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd

from ml_engine.datasets import get_dataset
from ml_engine.preprocess import (
    LABEL_COLUMN, METADATA_COLUMNS, RANDOM_STATE, SCHEMA_VERSION, SELECTED_COLUMNS,
    connection_keys, deduplicate_flows, normalize_rows, sha256_file, split_data,
)


def limit_training_benign(frame, cap, seed=RANDOM_STATE):
    """Sample across source days without changing any held-out population."""
    if cap < 1:
        raise ValueError("Training benign cap must be positive")
    benign = frame.loc[frame[LABEL_COLUMN].eq("BENIGN")]
    if len(benign) <= cap:
        return frame.copy(), np.array([], dtype=np.int64)
    rng = np.random.default_rng(seed)
    days = sorted(benign["_source_day"].unique())
    chosen = []
    for index, day in enumerate(days):
        candidates = benign.index[benign["_source_day"].eq(day)].to_numpy()
        quota = cap // len(days) + (index < cap % len(days))
        chosen.extend(rng.choice(candidates, min(quota, len(candidates)), replace=False))
    # If a source cannot fill its equal quota, use remaining training-only rows.
    if len(chosen) < cap:
        remaining = benign.index.difference(chosen).to_numpy()
        chosen.extend(rng.choice(remaining, cap - len(chosen), replace=False))
    keep = ~frame[LABEL_COLUMN].eq("BENIGN") | frame.index.isin(chosen)
    return frame.loc[keep].copy(), frame.loc[~keep, "_row_id"].to_numpy(dtype=np.int64)


def prepare_unified(raw_dir=None, processed_dir=None, reports_dir=None,
                    benign_train_cap=150_000, chunksize=100_000):
    config = get_dataset("unified")
    raw_dir = Path(raw_dir or config.raw_csv.parent)
    output = Path(processed_dir or config.processed_dir)
    reports = Path(reports_dir or config.reports_dir)
    if chunksize < 1 or benign_train_cap < 1:
        raise ValueError("Chunk size and training benign cap must be positive")
    targets = (output / "unified_splits.pkl", output / "cleaned_unified.csv")
    if any(path.exists() for path in targets) or (reports.exists() and any(reports.iterdir())):
        raise FileExistsError("Archive existing unified data and reports before preprocessing")
    if config.models_dir.exists() and any(config.models_dir.iterdir()):
        raise FileExistsError("Archive the trained unified run before preprocessing")
    sources = {day: raw_dir / f"{day}.csv" for day in config.source_days}
    for path in sources.values():
        if not path.is_file():
            raise FileNotFoundError(f"Required source missing: {path}")

    started = time.monotonic()
    frames, source_audit, offset = [], {}, 0
    original_categories = sorted(set(config.label_mapping) | set(config.classes) | set(config.excluded_labels))
    for day, path in sources.items():
        counts = Counter()
        raw_labels, excluded_labels = Counter(), Counter()
        local_offset = 0
        checksum = sha256_file(path)
        for raw in pd.read_csv(path, usecols=lambda name: name.strip() in (
                SELECTED_COLUMNS + METADATA_COLUMNS + [LABEL_COLUMN]),
                chunksize=chunksize, low_memory=False):
            raw.columns = raw.columns.str.strip()
            raw["_source_day"] = day
            raw["_source_row_id"] = np.arange(local_offset, local_offset + len(raw))
            frame, audit = normalize_rows(raw, config)
            frame["_row_id"] += offset + local_offset
            local_offset += len(raw)
            for key in ("raw_rows", "duplicate_header_rows", "invalid_rows", "excluded_rows"):
                counts[key] += audit[key]
            raw_labels.update(audit["raw_label_counts"])
            excluded_labels.update(audit["excluded_label_counts"])
            frame[LABEL_COLUMN] = pd.Categorical(frame[LABEL_COLUMN], categories=config.classes)
            frame["_original_label"] = pd.Categorical(frame["_original_label"], categories=original_categories)
            frame["_source_day"] = pd.Categorical(frame["_source_day"], categories=config.source_days)
            frames.append(frame)
        # Reject concurrent source edits rather than publishing ambiguous provenance.
        if sha256_file(path) != checksum:
            raise ValueError(f"Source changed during ingestion: {path}")
        source_audit[day] = {"path": str(path), "source_sha256": checksum, **dict(counts),
                             "raw_label_counts": dict(raw_labels),
                             "excluded_label_counts": dict(excluded_labels)}
        offset += local_offset
        print(f"Read {day}: {local_offset:,} original rows", flush=True)

    frame = pd.concat(frames, ignore_index=True)
    frames.clear()
    del raw
    frame, duplicate_audit = deduplicate_flows(frame)
    if set(frame[LABEL_COLUMN]) != set(config.classes):
        raise ValueError("Global cleaning must retain all seven classes")
    keys = connection_keys(frame)
    frame["_connection_hash"] = pd.util.hash_pandas_object(keys, index=False).to_numpy(dtype=np.uint64)
    frame["_group_id"] = pd.factorize(keys, sort=True)[0]
    del keys

    # Endpoint diagnostics explicitly show that five-tuples are not campaign IDs.
    left, right = frame["Src IP dec"], frame["Dst IP dec"]
    frame["_endpoint_pair"] = pd.util.hash_pandas_object(pd.DataFrame({
        "left": np.minimum(left.to_numpy(), right.to_numpy()),
        "right": np.maximum(left.to_numpy(), right.to_numpy()),
    }), index=False).to_numpy(dtype=np.uint64)
    del left, right
    frame = frame.drop(columns=METADATA_COLUMNS).reset_index(drop=True)
    audit = {
        "dataset": "unified", "schema_version": SCHEMA_VERSION,
        "status": "experimental within-capture baseline; not production validated",
        "sources": source_audit, "raw_rows": offset, **duplicate_audit,
        **{key: sum(info[key] for info in source_audit.values())
           for key in ("excluded_rows", "invalid_rows", "duplicate_header_rows")},
        "clean_rows": len(frame), "class_counts": frame[LABEL_COLUMN].value_counts().sort_index().to_dict(),
        "label_mapping": config.label_mapping, "excluded_label_policy": list(config.excluded_labels),
        "attempted_policy": "BENIGN for supported Attempted labels; excluded families take precedence",
        "feature_names": SELECTED_COLUMNS, "random_state": RANDOM_STATE,
        "connection_groups": int(frame["_group_id"].nunique()),
        "class_group_counts": frame.groupby(LABEL_COLUMN, observed=True)["_group_id"].nunique().to_dict(),
        "split_method": "global stratified connection groups, approximately 60/20/20 before training-only subsampling",
        "limitations": [
            "Connection groups are not independent campaigns or hosts; endpoint overlap is reported explicitly.",
            "Sources, including Monday and previous test populations, have already been inspected in earlier experiments.",
            "Exact regenerated dataset release and extractor parity remain unverified.",
            "Coarse WEB_ATTACK has limited non-Attempted support; no payload-semantic guarantee.",
            "Source ports remain features; port ablation and independent lab evaluation remain pending.",
            "No live or firewall readiness claim; metrics reflect this cleaned source population only.",
        ],
    }
    print(f"Globally cleaned {len(frame):,} rows; splitting connections ...", flush=True)
    parts = split_data(frame, classes=config.classes)
    before_sampling = {name: len(part) for name, part in parts.items()}
    parts["train"], dropped = limit_training_benign(parts["train"], benign_train_cap)
    if set(parts["train"][LABEL_COLUMN]) != set(config.classes):
        raise ValueError("Training cap removed a required class")
    audit["training_sampling"] = {
        "policy": "BENIGN only, training only, near-equal source-day quotas with availability redistribution",
        "benign_cap": benign_train_cap, "discarded_training_benign_rows": len(dropped),
        "original_partition_rows": before_sampling,
        "training_benign_by_source": parts["train"].loc[parts["train"][LABEL_COLUMN].eq("BENIGN"),
                                                        "_source_day"].value_counts().sort_index().to_dict(),
    }
    audit["splits"] = {}
    for name, part in parts.items():
        audit["splits"][name] = {
            "rows": len(part), "groups": int(part["_group_id"].nunique()),
            "class_counts": part[LABEL_COLUMN].value_counts().sort_index().to_dict(),
            "source_counts": part["_source_day"].value_counts().sort_index().to_dict(),
            "original_label_counts": part["_original_label"].value_counts().sort_index().to_dict(),
        }
    audit["endpoint_overlap"] = {}
    for label in config.classes:
        per_part = {name: set(part.loc[part[LABEL_COLUMN].eq(label), "_endpoint_pair"])
                    for name, part in parts.items()}
        all_pairs = set.union(*per_part.values())
        shared = {pair for pair in all_pairs if sum(pair in pairs for pairs in per_part.values()) > 1}
        audit["endpoint_overlap"][label] = {"pairs": len(all_pairs), "pairs_shared_across_partitions": len(shared)}

    output.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    frame[SELECTED_COLUMNS + [LABEL_COLUMN, "_source_day", "_source_row_id"]].to_csv(targets[1], index=False)
    del frame
    gc.collect()
    audit["preprocessing_seconds"] = time.monotonic() - started
    payload = {"schema_version": SCHEMA_VERSION, "dataset": "unified", "audit": audit,
               "splits": parts, "discarded_training_row_ids": dropped}
    temporary = output / "unified_splits.pending.pkl"
    joblib.dump(payload, temporary)
    temporary.replace(targets[0])
    (reports / "data_audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    print(json.dumps(audit, indent=2), flush=True)
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path)
    parser.add_argument("--processed-dir", type=Path)
    parser.add_argument("--reports-dir", type=Path)
    parser.add_argument("--benign-train-cap", type=int, default=150_000)
    parser.add_argument("--chunksize", type=int, default=100_000)
    prepare_unified(**vars(parser.parse_args()))
