"""Paired RF/XGB port sensitivity on frozen unified partitions, exploratory only.

No serving models are replaced. Only reports and selected-row provenance are saved.
Joblib split input must come from a trusted local source.
"""
import argparse
from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from ml_engine.datasets import get_dataset
from ml_engine.preprocess import SCHEMA_VERSION, SELECTED_COLUMNS, sha256_file
from ml_engine.train import score_predictions

CONDITIONS = {
    'full': list(SELECTED_COLUMNS),
    'no_source_port': [name for name in SELECTED_COLUMNS if name != 'Src Port'],
    'no_ports': [name for name in SELECTED_COLUMNS if name not in ('Src Port', 'Dst Port')],
}


def sample_positions(labels, sample_size, seed=42):
    """Reserve one row/class, distribute remaining capacity proportionally, sample once."""
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**32:
        raise ValueError('seed must be an integer in 0..2**32-1')
    if sample_size is not None and (isinstance(sample_size, bool) or not isinstance(sample_size, int) or sample_size < 1):
        raise ValueError('sample_size must be a positive integer or None')
    classes = sorted(set(labels))
    target = len(labels) if sample_size is None else min(sample_size, len(labels))
    if not classes or target < len(classes):
        raise ValueError('sample_size must cover all classes')
    if target == len(labels):
        return np.arange(target)
    values = np.asarray(labels)
    pools = [np.flatnonzero(values == label) for label in classes]
    capacities = np.array([len(pool) - 1 for pool in pools])
    quota = (target - len(classes)) * capacities / capacities.sum()
    extra = np.floor(quota).astype(int)
    for i in sorted(range(len(classes)), key=lambda i: (-(quota[i] - extra[i]), classes[i]))[:target - len(classes) - int(extra.sum())]:
        extra[i] += 1
    rng = np.random.default_rng(seed)
    return np.sort(np.concatenate([rng.choice(pool, size=1 + extra[i], replace=False) for i, pool in enumerate(pools)]))


def validate_payload(payload):
    if payload.get('schema_version') != SCHEMA_VERSION or payload.get('dataset') != 'unified':
        raise ValueError('Expected current frozen unified splits')
    if payload.get('audit', {}).get('feature_names') != SELECTED_COLUMNS:
        raise ValueError('Split feature contract must match all 20 features')
    parts = payload.get('splits', {})
    if set(parts) != {'train', 'validation', 'test'}:
        raise ValueError('Expected train/validation/test partitions')
    seen_rows, seen_groups = set(), set()
    classes = set(get_dataset('unified').classes)
    for name, frame in parts.items():
        required = {*SELECTED_COLUMNS, 'Label', '_row_id', '_source_row_id', '_source_day', '_group_id'}
        if not isinstance(frame, pd.DataFrame) or frame.empty or required - set(frame.columns):
            raise ValueError(f'{name} missing required features or provenance')
        if frame.columns.duplicated().any() or set(frame['Label']) != classes:
            raise ValueError(f'{name} must contain all classes with unique columns')
        if frame[['_row_id', '_source_row_id', '_source_day', '_group_id']].isna().any().any():
            raise ValueError('Missing row/group provenance')
        # _row_id is global; _source_row_id alone repeats across source days.
        rows = set(frame['_row_id'].astype(str))
        groups = set(frame['_group_id'].astype(str))
        if len(rows) != len(frame) or rows & seen_rows or groups & seen_groups:
            raise ValueError('Frozen partitions have duplicate rows or overlapping connection groups')
        seen_rows.update(rows)
        seen_groups.update(groups)
        values = frame[SELECTED_COLUMNS].to_numpy(dtype=float)
        if not np.isfinite(values).all() or (values < 0).any():
            raise ValueError('Features must be finite and nonnegative')
    return parts


def manifest(frame):
    ids = frame['_row_id'].astype(str).tolist()
    return {'rows': len(frame), 'class_counts': {str(k): int(v) for k, v in frame['Label'].value_counts().sort_index().items()},
            'row_ids_sha256': sha256(json.dumps(ids, separators=(',', ':')).encode()).hexdigest(),
            'groups': int(frame['_group_id'].nunique())}


def make_models(seed, workers):
    return {
        'random_forest': RandomForestClassifier(n_estimators=200, max_depth=25, min_samples_split=5,
            min_samples_leaf=2, max_features='sqrt', random_state=seed, n_jobs=workers, class_weight='balanced'),
        'xgboost': XGBClassifier(n_estimators=200, max_depth=10, learning_rate=0.1, subsample=0.8,
            colsample_bytree=0.8, random_state=seed, n_jobs=workers, eval_metric='mlogloss'),
    }


def write_json(path, data):
    with Path(path).open('x') as stream:
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.write('\n')


def run_ablation(splits_path=None, output='reports/ablation/port_ablation.json', sample_size=50000,
                 seed=42, workers=2, project_root=None):
    root = Path(project_root or Path(__file__).resolve().parents[1]).resolve()
    output = Path(output)
    output = (output if output.is_absolute() else root / output).resolve()
    allowed = (root / 'reports/ablation').resolve()
    if allowed not in output.parents:
        raise ValueError('Output must be inside reports/ablation')
    targets = [output, output.parent / 'README.md', output.parent / 'training_sample.json']
    if any(path.exists() for path in targets):
        raise FileExistsError('Preserve existing experiment reports; choose a fresh output directory')
    if workers not in (1, 2):
        raise ValueError('workers must be 1 or 2')
    source = Path(splits_path or get_dataset('unified').splits_path).resolve()
    digest = sha256_file(source)
    payload = joblib.load(source)
    if sha256_file(source) != digest:
        raise ValueError('Split artifact changed while loading')
    parts = validate_payload(payload)
    positions = sample_positions(parts['train']['Label'], sample_size, seed)
    train = parts['train'].iloc[positions]
    encoder = LabelEncoder().fit(train['Label'])
    classes = list(encoder.classes_)
    targets_y = {name: encoder.transform(frame['Label']) for name, frame in {**parts, 'train': train}.items()}
    train_manifest = manifest(train)
    report = {'schema_version': 1, 'experiment': 'paired_port_ablation',
              'scope': 'exploratory within previously observed unified partitions; not campaign independence',
              'split_sha256': digest, 'seed': seed, 'workers': workers, 'classes': classes,
              'dependencies': {name: version(name) for name in ('numpy', 'pandas', 'scikit-learn', 'xgboost', 'joblib')},
              'python': platform.python_version(), 'code_sha256': sha256_file(__file__),
              'source_partitions': {name: manifest(frame) for name, frame in parts.items()},
              'training_sample': train_manifest, 'requested_train_sample_size': sample_size,
              'evaluation_sampling': 'full original validation and test; no test-based selection',
              'endpoint_overlap': payload['audit'].get('endpoint_overlap'),
              'conditions': {}, 'model_artifacts_saved': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(targets[2], {**train_manifest, 'split_sha256': digest, 'selected_source_positions': positions.tolist(),
                          'selected_global_row_ids': train['_row_id'].astype(str).tolist(),
                          'source_rows': [[str(day), int(row)] for day, row in zip(train['_source_day'], train['_source_row_id'])],
                          'sampling': 'one per class then proportional capacity; seeded without replacement'})
    started = time.monotonic()
    for condition, names in CONDITIONS.items():
        scaler = StandardScaler().fit(train[names].to_numpy(dtype=float))
        matrices = {name: scaler.transform(frame[names].to_numpy(dtype=float))
                    for name, frame in {**parts, 'train': train}.items()}
        result = {'feature_names': names, 'training_row_ids_sha256': train_manifest['row_ids_sha256'],
                  'scaler_fit_rows': int(scaler.n_samples_seen_), 'scaler_mean': scaler.mean_.tolist(),
                  'scaler_scale': scaler.scale_.tolist(), 'models': {}}
        for model_name, model in make_models(seed, workers).items():
            print(f'Training {condition}/{model_name}: {len(train)} rows, {len(names)} features', flush=True)
            fit_start = time.monotonic()
            fit_kwargs = {'sample_weight': compute_sample_weight('balanced', targets_y['train'])} if model_name == 'xgboost' else {}
            model.fit(matrices['train'], targets_y['train'], **fit_kwargs)
            scores = {name: score_predictions(targets_y[name], model.predict(matrices[name]), classes)
                      for name in ('validation', 'test')}
            # XGB exposes unset NaN defaults; store repr for those values, as train.py does.
            scores['parameters'] = {key: repr(value) if isinstance(value, float) and not np.isfinite(value) else value
                                    for key, value in model.get_params().items()}
            scores['fit_and_evaluation_seconds'] = time.monotonic() - fit_start
            baseline = scores if condition == 'full' else report['conditions']['full']['models'][model_name]
            scores['delta_from_full'] = {part: {metric: scores[part][metric] - baseline[part][metric]
                for metric in ('accuracy', 'macro_f1', 'benign_false_positive_rate')} for part in ('validation', 'test')}
            result['models'][model_name] = scores
        report['conditions'][condition] = result
        del matrices
    report['elapsed_seconds'] = time.monotonic() - started
    report['status'] = 'completed'
    write_json(output, report)
    lines = ['# Port sensitivity experiment', '',
        'Paired RF/XGBoost runs use identical sampled training rows and full frozen validation/test sets.',
        'Transforms and class weights use training rows only. No serving artifacts are replaced.', '',
        '| Condition | Model | Features | Test macro F1 | Test benign FPR |', '| --- | --- | ---: | ---: | ---: |']
    for condition, result in report['conditions'].items():
        for model, scores in result['models'].items():
            lines.append(f"| {condition} | {model} | {len(result['feature_names'])} | {scores['test']['macro_f1']:.6%} | {scores['test']['benign_false_positive_rate']:.6%} |")
    lines += ['', 'These previously inspected partitions share endpoints/campaigns. This exploratory comparison',
              'does not establish independent generalization, original-capture parity, or response readiness.',
              f'Full metrics, per-class results, provenance, transforms and deltas: [{output.name}]({output.name}).',
              'Exact sampled training row IDs are in training_sample.json. No fitted experimental models are saved.', '']
    with targets[1].open('x') as stream:
        stream.write('\n'.join(lines))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--splits', type=Path)
    parser.add_argument('--sample-size', type=int, default=50000, help='training-only row cap; evaluation partitions remain full')
    parser.add_argument('--output', type=Path, default=Path('reports/ablation/port_ablation.json'))
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--workers', type=int, choices=(1, 2), default=2)
    args = parser.parse_args(argv)
    try:
        result = run_ablation(args.splits, args.output, args.sample_size, args.seed, args.workers)
        print(f"Completed 6 paired fits in {result['elapsed_seconds']:.2f}s; no serving model replaced")
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
