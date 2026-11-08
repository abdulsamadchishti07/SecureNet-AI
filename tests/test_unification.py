"""Combined-source data contracts; campaign independence is not implied."""

from itertools import combinations

import joblib
import numpy as np
import pandas as pd
import pytest

from ml_engine import datasets, evaluate, monday, predictor, train
from ml_engine.preprocess import SELECTED_COLUMNS
from ml_engine.unify import limit_training_benign, prepare_unified


@pytest.fixture
def source_csvs(dataset_cases, flow_factory):
    cases = {case.name: case for case in dataset_cases}
    config = datasets.get_dataset("unified")
    config.raw_csv.parent.mkdir(parents=True)
    sources = {}
    for index, day in enumerate(config.source_days):
        case = cases["friday"] if day == "monday" else cases[day]
        raw = flow_factory(case)
        if day == "monday":
            raw = raw.loc[raw.Label.eq("BENIGN")].copy()
        raw["Flow Duration"] += index * 100_000
        raw["Src IP dec"] += index * 1000
        raw["Dst IP dec"] += index * 1000
        sources[day] = raw.reset_index(drop=True)
    return sources


@pytest.fixture
def write_sources(source_csvs):
    def write():
        raw_dir = datasets.get_dataset("unified").raw_csv.parent
        for day, raw in source_csvs.items():
            raw.to_csv(raw_dir / f"{day}.csv", index=False)
    return write


def test_global_conflicts_survive_chunk_boundaries_and_cross_day_connections_stay_together(
        source_csvs, write_sources):
    conflict = source_csvs["monday"].iloc[[0]].copy()
    conflict["Flow Duration"] = 99_999_999
    source_csvs["monday"] = pd.concat([
        source_csvs["monday"], conflict, conflict.assign(Label="Botnet")
    ], ignore_index=True)
    source_csvs["friday"] = pd.concat([source_csvs["friday"], conflict], ignore_index=True)
    # An identical model input from a different file must be removed globally.
    duplicate = source_csvs["friday"].loc[source_csvs["friday"].Label.eq("Botnet")].iloc[[0]]
    source_csvs["tuesday"] = pd.concat([source_csvs["tuesday"], duplicate], ignore_index=True)
    related = source_csvs["tuesday"].iloc[[0]].copy()
    related["Flow Duration"] += 987_654
    related_id = len(source_csvs["friday"])
    source_csvs["friday"] = pd.concat([source_csvs["friday"], related], ignore_index=True)
    write_sources()
    payload = prepare_unified(chunksize=7, benign_train_cap=100_000)
    parts = payload["splits"]
    assert payload["audit"]["same_label_duplicates_removed"] == 2
    assert payload["audit"]["conflicting_label_rows_removed"] == 2
    combined = pd.concat(parts.values())
    assert not combined["Flow Duration"].eq(99_999_999).any()
    relatives = combined.loc[
        (combined._source_day.eq("tuesday") & combined._source_row_id.isin([0, 1]))
        | (combined._source_day.eq("friday") & combined._source_row_id.eq(related_id))
    ]
    assert len(relatives) == 3
    assert relatives._group_id.nunique() == 1
    for part in parts.values():
        for day, rows in part.groupby("_source_day", observed=True):
            expected = source_csvs[day].iloc[rows._source_row_id][SELECTED_COLUMNS].to_numpy()
            np.testing.assert_array_equal(rows[SELECTED_COLUMNS].to_numpy(), expected)
    for left, right in combinations(parts.values(), 2):
        assert set(left._row_id).isdisjoint(right._row_id)
        assert set(left._group_id).isdisjoint(right._group_id)
        assert set(map(tuple, left[SELECTED_COLUMNS].to_numpy())).isdisjoint(
            map(tuple, right[SELECTED_COLUMNS].to_numpy()))


def test_benign_cap_changes_training_only_and_split_assignment_is_repeatable(
        source_csvs, write_sources, tmp_path):
    write_sources()
    complete = prepare_unified(processed_dir=tmp_path / "complete_data",
                               reports_dir=tmp_path / "complete_reports", benign_train_cap=100_000)
    capped = prepare_unified(processed_dir=tmp_path / "capped_data",
                             reports_dir=tmp_path / "capped_reports", benign_train_cap=10)
    for name in ("validation", "test"):
        pd.testing.assert_frame_equal(complete["splits"][name], capped["splits"][name])
    original = complete["splits"]["train"]
    sampled = capped["splits"]["train"]
    assert sampled.Label.eq("BENIGN").sum() == 10
    expected_attacks = original.loc[~original.Label.eq("BENIGN")]
    pd.testing.assert_frame_equal(expected_attacks, sampled.loc[~sampled.Label.eq("BENIGN")])
    assert set(sampled._row_id).isdisjoint(capped["discarded_training_row_ids"])
    assert len(sampled) + len(capped["discarded_training_row_ids"]) == len(original)


def test_training_sampling_fills_small_source_quotas_without_losing_attacks():
    frame = pd.DataFrame({"Label": ["BENIGN"] * 21 + ["DOS"],
                          "_source_day": ["monday"] + ["tuesday"] * 20 + ["wednesday"],
                          "_row_id": np.arange(22)})
    result, dropped = limit_training_benign(frame, 10)
    assert result.Label.eq("BENIGN").sum() == 10
    assert result.Label.eq("DOS").sum() == 1
    assert len(dropped) == 11
    again, again_dropped = limit_training_benign(frame, 10)
    pd.testing.assert_frame_equal(result, again)
    np.testing.assert_array_equal(dropped, again_dropped)
    with pytest.raises(ValueError, match="positive"):
        limit_training_benign(frame, 0)


def test_multisource_pipeline_trains_evaluates_and_defaults_to_unified(
        source_csvs, write_sources, small_estimators):
    write_sources()
    payload = prepare_unified(chunksize=73, benign_train_cap=100)
    config = datasets.get_dataset("unified")
    metadata = train.train_model(dataset="unified")
    bundle = joblib.load(config.models_dir / "inference_bundle.pkl")
    assert metadata["dataset"] == "unified"
    original_train = payload["splits"]["train"]
    assert bundle["scaler"].n_samples_seen_ == len(original_train)
    np.testing.assert_allclose(bundle["scaler"].mean_, original_train[SELECTED_COLUMNS].mean())
    flow = original_train.iloc[0][SELECTED_COLUMNS].to_dict()
    result = predictor.predict(flow)
    assert result == predictor.predict(flow, dataset="unified")
    assert set(result["probabilities"]) == set(config.classes)
    _, exposure = monday.load_existing_run("unified")
    expected = pd.concat(payload["splits"].values())._connection_hash.unique()
    assert set(exposure["connection_hashes"]) == set(expected)
    report = evaluate.evaluate_model(dataset="unified")
    assert report["test_rows"] == len(payload["splits"]["test"])
    assert np.shape(report["confusion_matrix"]) == (7, 7)
    with pytest.raises(FileExistsError):
        prepare_unified()


def test_default_does_not_fall_back_to_a_weekday_model(train_dataset, dataset_cases):
    case = next(case for case in dataset_cases if case.name == "friday")
    run = train_dataset(case)
    with pytest.raises(FileNotFoundError, match="Unified model missing"):
        predictor.predict(run.raw.iloc[0][SELECTED_COLUMNS].to_dict())
