"""Label policies, cleaning, raw-valued artifacts and connection isolation."""

from itertools import combinations

import numpy as np
import pandas as pd
import pytest

from ml_engine import datasets
from ml_engine.preprocess import SELECTED_COLUMNS, clean_data, split_data


def test_policy_examples_cover_the_trainable_registry(dataset_cases):
    assert {case.name for case in dataset_cases} == set(datasets.DATASETS)


def test_label_mapping_exclusions_and_attempt_metadata(dataset_case, raw_flows):
    excluded = [raw_flows.iloc[[0]].assign(Label=label) for label in dataset_case.excluded]
    raw = pd.concat([raw_flows, *excluded], ignore_index=True)
    cleaned, audit = clean_data(raw, dataset=dataset_case.name)
    config = datasets.get_dataset(dataset_case.name)

    assert config.classes == dataset_case.classes
    assert set(config.excluded_labels) == set(dataset_case.excluded)
    assert set(cleaned.Label) == set(dataset_case.classes)
    assert audit["excluded_label_counts"] == {label: 1 for label in dataset_case.excluded}
    assert audit["excluded_rows"] == len(dataset_case.excluded)
    for expected, variants in dataset_case.labels:
        for source in variants:
            rows = cleaned.loc[cleaned._original_label.eq(source)]
            assert not rows.empty, source
            assert set(rows.Label) == {expected}
    expected_attempts = raw_flows.Label.str.contains("Attempted", regex=False).sum()
    assert cleaned._attempted.sum() == expected_attempts
    assert cleaned.loc[cleaned._attempted, "_original_label"].str.endswith("Attempted").all()
    assert audit["class_group_counts"] == {label: 30 for label in dataset_case.classes}


def test_unknown_labels_fail_instead_of_being_dropped(dataset_case, raw_flows):
    with pytest.raises(ValueError, match=f"Unexpected {dataset_case.name.title()} labels"):
        clean_data(raw_flows.assign(Label="UNRECOGNIZED"), dataset=dataset_case.name)


def test_duplicates_conflicting_targets_and_invalid_values_are_excluded(dataset_case, raw_flows):
    # A different source-label alias must still deduplicate after normalization.
    alternate = dataset_case.labels[1][1][-1]
    duplicate = raw_flows.iloc[[60]].assign(Label=alternate, **{"Src IP dec": 999})
    conflict = raw_flows.iloc[[120]].assign(Label="BENIGN")
    invalid = raw_flows.iloc[[2]].assign(**{"Flow Bytes/s": np.inf})
    raw = pd.concat([raw_flows, duplicate, conflict, invalid], ignore_index=True)
    cleaned, audit = clean_data(raw, dataset=dataset_case.name)

    assert audit["same_label_duplicates_removed"] == 1
    assert audit["conflicting_label_rows_removed"] == 2
    assert audit["invalid_rows"] == 1
    assert 120 not in set(cleaned._row_id)
    assert np.isfinite(cleaned[SELECTED_COLUMNS].to_numpy()).all()


def test_connection_partitions_are_disjoint_class_complete_and_repeatable(dataset_case, cleaned_flows, splits):
    assert cleaned_flows.iloc[0]._group_id == cleaned_flows.iloc[1]._group_id
    assert sum(map(len, splits.values())) == len(cleaned_flows)
    for part in splits.values():
        assert set(part.Label) == set(dataset_case.classes)
    for left, right in combinations(splits.values(), 2):
        assert set(left._row_id).isdisjoint(right._row_id)
        assert set(left._group_id).isdisjoint(right._group_id)
        assert set(map(tuple, left[SELECTED_COLUMNS].to_numpy())).isdisjoint(
            map(tuple, right[SELECTED_COLUMNS].to_numpy())
        )
    again = split_data(cleaned_flows, classes=dataset_case.classes)
    for name, part in splits.items():
        pd.testing.assert_frame_equal(part, again[name])


def test_preprocessing_preserves_raw_values_without_creating_models(prepared_run):
    run = prepared_run
    assert not run.config.models_dir.exists()
    for part in run.payload["splits"].values():
        expected = run.raw.iloc[part._row_id][SELECTED_COLUMNS].to_numpy(dtype=float)
        np.testing.assert_array_equal(part[SELECTED_COLUMNS].to_numpy(), expected)
