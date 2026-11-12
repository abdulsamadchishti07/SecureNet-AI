"""Paired sampling, feature isolation and train-only transforms on private splits."""
from hashlib import sha256
import json

import joblib
import numpy as np
import pandas as pd
import pytest

from ml_engine import ablation
from ml_engine.datasets import get_dataset
from ml_engine.preprocess import SELECTED_COLUMNS, SCHEMA_VERSION


def bundle():
    parts = {}
    for part_id, name in enumerate(('train', 'validation', 'test')):
        labels = [label for label in get_dataset('unified').classes for _ in range(5)]
        size = len(labels)
        parts[name] = pd.DataFrame({
            **{column: np.arange(size, dtype=float) + feature + part_id * 1000
               for feature, column in enumerate(SELECTED_COLUMNS)},
            'Label': labels, '_row_id': [part_id * 100 + i for i in range(size)],
            '_source_row_id': list(range(size)), '_source_day': ['monday'] * size,
            '_group_id': [part_id * 100 + i for i in range(size)]})
    return {'dataset': 'unified', 'schema_version': SCHEMA_VERSION,
            'audit': {'feature_names': SELECTED_COLUMNS}, 'splits': parts}


def test_sampling_reproducible_class_covering_and_unique():
    labels = pd.Series(['BENIGN'] * 1000 + ['RARE'] + ['OTHER'] * 20)
    first = ablation.sample_positions(labels, 20)
    np.testing.assert_array_equal(first, ablation.sample_positions(labels, 20))
    assert len(set(first)) == len(first) == 20
    assert set(labels.iloc[first]) == set(labels)
    np.testing.assert_array_equal(ablation.sample_positions(labels, None), np.arange(len(labels)))


@pytest.mark.parametrize('size', [0, -1, 2, 3.5, True])
def test_bad_sampling_fails(size):
    with pytest.raises(ValueError):
        ablation.sample_positions(pd.Series(['A', 'B', 'C']), size)


def assign_column(payload, partition, column, values):
    frame = payload['splits'][partition]
    frame.loc[:, column] = values


@pytest.mark.parametrize('mutation', [
    lambda b: b.update(schema_version=-1),
    lambda b: b['splits']['train'].drop(columns='Src Port', inplace=True),
    lambda b: assign_column(b, 'test', '_group_id', b['splits']['train']['_group_id'].to_numpy()),
    lambda b: assign_column(b, 'validation', 'Flow Bytes/s', float('nan')),
])
def test_invalid_splits_rejected_before_writing(tmp_path, mutation):
    payload = bundle()
    mutation(payload)
    source = tmp_path / 'splits.pkl'
    joblib.dump(payload, source)
    output = tmp_path / 'reports/ablation/port_ablation.json'
    with pytest.raises(ValueError):
        ablation.run_ablation(source, output, project_root=tmp_path)
    assert not output.exists()


def test_paired_runner_preserves_inputs_and_training_only_scaler(tmp_path, monkeypatch):
    payload = bundle()
    source = tmp_path / 'splits.pkl'
    joblib.dump(payload, source)
    digest = sha256(source.read_bytes()).hexdigest()
    fitted = []

    class Model:
        def fit(self, x, y, **kwargs):
            fitted.append((x.copy(), y.copy(), kwargs))
            return self
        def predict(self, x):
            return np.zeros(len(x), dtype=int)
        def get_params(self):
            return {'random_state': 42}

    monkeypatch.setattr(ablation, 'make_models', lambda *a: {'random_forest': Model(), 'xgboost': Model()})
    output = tmp_path / 'reports/ablation/port_ablation.json'
    report = ablation.run_ablation(source, output, sample_size=21, project_root=tmp_path)
    assert [x.shape for x, _, _ in fitted] == [(21, 20), (21, 20), (21, 19), (21, 19), (21, 18), (21, 18)]
    for x, y, _ in fitted:
        np.testing.assert_allclose(x.mean(axis=0), 0, atol=1e-12)
        np.testing.assert_array_equal(y, fitted[0][1])
    assert 'sample_weight' not in fitted[0][2]
    assert len(fitted[1][2]['sample_weight']) == 21
    sample = json.loads((output.parent / 'training_sample.json').read_text())
    selected = payload['splits']['train'].iloc[sample['selected_source_positions']]
    for condition in report['conditions'].values():
        np.testing.assert_allclose(condition['scaler_mean'], selected[condition['feature_names']].mean())
        assert condition['scaler_fit_rows'] == 21
        assert condition['training_row_ids_sha256'] == report['training_sample']['row_ids_sha256']
    assert report['source_partitions']['test']['rows'] == len(payload['splits']['test'])
    assert sha256(source.read_bytes()).hexdigest() == digest
    with pytest.raises(FileExistsError):
        ablation.run_ablation(source, output, sample_size=21, project_root=tmp_path)
    with pytest.raises(ValueError, match='reports/ablation'):
        ablation.run_ablation(source, tmp_path / 'ml_engine/models/unified_v1/x.json', project_root=tmp_path)


def test_small_real_paired_models_run(tmp_path, monkeypatch):
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier
    source = tmp_path / 'splits.pkl'
    joblib.dump(bundle(), source)
    monkeypatch.setattr(ablation, 'make_models', lambda seed, workers: {
        'random_forest': RandomForestClassifier(n_estimators=3, random_state=seed, n_jobs=1, class_weight='balanced'),
        'xgboost': XGBClassifier(n_estimators=3, max_depth=2, random_state=seed, n_jobs=1, eval_metric='mlogloss')})
    report = ablation.run_ablation(source, tmp_path / 'reports/ablation/port_ablation.json', sample_size=21, project_root=tmp_path)
    assert report['status'] == 'completed'
    assert [len(c['feature_names']) for c in report['conditions'].values()] == [20, 19, 18]
    assert all(len(model['test']['confusion_matrix']) == 7 for result in report['conditions'].values() for model in result['models'].values())
