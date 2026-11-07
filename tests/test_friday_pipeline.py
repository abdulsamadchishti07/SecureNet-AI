"""Regression checks for held-out data isolation and inference contracts."""

import itertools
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from ml_engine import predictor, train, evaluate
from ml_engine.preprocess import (
    SELECTED_COLUMNS, CLASSES, clean_data, split_data, preprocess_data,
)


def example_flows():
    rows = []
    for label_index, label in enumerate(CLASSES):
        for group in range(30):
            for direction in range(2):
                row = {column: float(1 + label_index * 1000 + group * 2 + direction)
                       for column in SELECTED_COLUMNS}
                row.update({
                    "Src IP dec": 100 + label_index,
                    "Dst IP dec": 200 + label_index,
                    "Src Port": 10000 + group, "Dst Port": 443, "Protocol": 6,
                    "Label": label,
                })
                if direction:
                    row["Src IP dec"], row["Dst IP dec"] = row["Dst IP dec"], row["Src IP dec"]
                    row["Src Port"], row["Dst Port"] = row["Dst Port"], row["Src Port"]
                rows.append(row)
    return pd.DataFrame(rows)


class FridayPipelineTests(unittest.TestCase):
    def test_connections_and_feature_duplicates_cannot_cross_splits(self):
        raw = example_flows()
        repeated = raw.iloc[[0]].copy()
        repeated["Src IP dec"] = 999
        cleaned, audit = clean_data(pd.concat([raw, repeated], ignore_index=True))
        self.assertEqual(audit["same_label_duplicates_removed"], 1)
        self.assertEqual(cleaned.loc[0, "_group_id"], cleaned.loc[1, "_group_id"])
        splits = split_data(cleaned)
        self.assertEqual(sum(map(len, splits.values())), len(cleaned))
        for left, right in itertools.combinations(splits.values(), 2):
            self.assertFalse(set(left["_row_id"]) & set(right["_row_id"]))
            self.assertFalse(set(left["_group_id"]) & set(right["_group_id"]))
            left_inputs = set(map(tuple, left[SELECTED_COLUMNS].to_numpy()))
            right_inputs = set(map(tuple, right[SELECTED_COLUMNS].to_numpy()))
            self.assertFalse(left_inputs & right_inputs)
        again = split_data(cleaned)
        for name in splits:
            pd.testing.assert_frame_equal(splits[name], again[name])

    def test_conflicting_labels_and_nonfinite_inputs_are_excluded(self):
        raw = example_flows()
        conflict = raw.iloc[[0]].copy()
        conflict["Label"] = "DDOS"
        invalid = raw.iloc[[2]].copy()
        invalid["Flow Bytes/s"] = np.inf
        cleaned, audit = clean_data(pd.concat([raw, conflict, invalid], ignore_index=True))
        self.assertEqual(audit["conflicting_label_rows_removed"], 2)
        self.assertEqual(audit["invalid_rows"], 1)
        self.assertNotIn(0, cleaned["_row_id"].tolist())
        with self.assertRaisesRegex(ValueError, "Unexpected Friday labels"):
            clean_data(raw.assign(Label="UNEXPECTED"))

    def test_scaler_does_not_fit_heldout_values(self):
        cleaned, _ = clean_data(example_flows())
        splits = split_data(cleaned)
        splits["validation"].loc[:, "Flow Duration"] = 1e12
        splits["test"].loc[:, "Flow Duration"] = 1e15
        scaler, encoder = train.fit_training_transforms(splits["train"])
        self.assertEqual(scaler.n_samples_seen_, len(splits["train"]))
        np.testing.assert_allclose(
            scaler.mean_, splits["train"][SELECTED_COLUMNS].mean().to_numpy()
        )
        before = scaler.mean_.copy()
        for name in ("validation", "test"):
            scaler.transform(splits[name][SELECTED_COLUMNS].to_numpy())
        np.testing.assert_array_equal(scaler.mean_, before)
        self.assertEqual(list(encoder.classes_), list(CLASSES))

    def test_small_pipeline_publishes_selected_bundle_and_rejects_changed_splits(self):
        # Real fits with small forests keep this an executable integration check.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv = root / "friday.csv"
            example_flows().to_csv(csv, index=False)
            payload = preprocess_data(csv, root / "processed", root / "reports")
            self.assertFalse((root / "models").exists())
            splits_path = root / "processed" / "friday_splits.pkl"
            bundle_path = root / "models" / "inference_bundle.pkl"
            make_model = lambda **kwargs: RandomForestClassifier(n_estimators=5, random_state=42)
            with patch.multiple(train, SPLITS_PATH=str(splits_path),
                                MODELS_DIR=str(root / "models"), BUNDLE_PATH=str(bundle_path),
                                REPORTS_DIR=str(root / "reports")), \
                 patch.object(train, "RandomForestClassifier", side_effect=make_model), \
                 patch.object(train, "XGBClassifier", side_effect=make_model):
                metadata = train.train_model()
                with self.assertRaises(FileExistsError):
                    train.train_model()
            bundle = joblib.load(bundle_path)
            self.assertEqual(bundle["scaler"].n_samples_seen_, len(payload["splits"]["train"]))
            np.testing.assert_allclose(
                bundle["scaler"].mean_,
                payload["splits"]["train"][SELECTED_COLUMNS].mean().to_numpy(),
            )
            winner = max(metadata["validation"], key=lambda k: metadata["validation"][k]["macro_f1"])
            self.assertEqual(metadata["selected_model"], winner)
            with patch.multiple(predictor, BUNDLE_PATH=str(bundle_path), _bundle=None):
                flow = example_flows().iloc[0][SELECTED_COLUMNS].to_dict()
                result = predictor.predict(flow)
                self.assertEqual(result, predictor.predict_batch([flow])[0])
                self.assertEqual(result, predictor.predict(dict(reversed(list(flow.items())))))
                self.assertAlmostEqual(sum(result["probabilities"].values()), 1.0)
            with patch.multiple(evaluate, BUNDLE_PATH=str(bundle_path),
                                SPLITS_PATH=str(splits_path), REPORTS_DIR=str(root / "reports")):
                result = evaluate.evaluate_model()
                self.assertEqual(result["test_rows"], len(payload["splits"]["test"]))
                with splits_path.open("ab") as stream:
                    stream.write(b"changed")
                with self.assertRaisesRegex(ValueError, "changed since training"):
                    evaluate.evaluate_model()

    def test_bad_inputs_do_not_reach_inference(self):
        self.assertEqual(predictor.predict_batch([]), [])
        with self.assertRaisesRegex(ValueError, "missing required features"):
            predictor.predict({})
        for value in (np.nan, np.inf, -1, "invalid", [1, 2]):
            flow = {column: 1 for column in SELECTED_COLUMNS}
            flow["Flow Duration"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                predictor.predict(flow)


if __name__ == "__main__":
    unittest.main()
