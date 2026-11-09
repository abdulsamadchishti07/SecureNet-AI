"""Shared policy examples, synthetic flows and isolated pipeline fixtures.

These examples exercise software contracts, not campaign generalization or
CICFlowMeter parity. All files and inference caches are isolated per test.
"""

from dataclasses import dataclass
from types import SimpleNamespace

import joblib
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from ml_engine import datasets, evaluate, predictor, preprocess, train


@dataclass(frozen=True)
class DatasetCase:
    name: str
    # Independent expected policies: (normalized class, source label variants).
    labels: tuple[tuple[str, tuple[str, ...]], ...]
    excluded: tuple[str, ...] = ()

    @property
    def classes(self):
        return tuple(label for label, _ in self.labels)


DATASET_CASES = (
    DatasetCase("friday", (
        ("BENIGN", ("BENIGN",)),
        ("BOTNET", ("Botnet", "Botnet - Attempted")),
        ("DDOS", ("DDoS",)),
        ("PORTSCAN", ("Portscan",)),
    )),
    DatasetCase("thursday", (
        ("BENIGN", ("BENIGN",)),
        ("PORTSCAN", ("Infiltration - Portscan",)),
        ("WEB_BRUTE_FORCE", ("Web Attack - Brute Force", "Web Attack - Brute Force - Attempted")),
        ("WEB_XSS", ("Web Attack - XSS", "Web Attack - XSS - Attempted")),
    ), ("Infiltration", "Infiltration - Attempted", "Web Attack - SQL Injection",
        "Web Attack - SQL Injection - Attempted")),
    DatasetCase("wednesday", (
        ("BENIGN", ("BENIGN",)),
        ("DOS_GOLDENEYE", ("DoS GoldenEye", "DoS GoldenEye - Attempted")),
        ("DOS_HULK", ("DoS Hulk", "DoS Hulk - Attempted")),
        ("DOS_SLOWHTTPTEST", ("DoS Slowhttptest", "DoS Slowhttptest - Attempted")),
        ("DOS_SLOWLORIS", ("DoS Slowloris", "DoS Slowloris - Attempted")),
    ), ("Heartbleed",)),
    DatasetCase("tuesday", (
        ("BENIGN", ("BENIGN",)),
        ("FTP_BRUTE_FORCE", ("FTP-Patator", "FTP-Patator - Attempted")),
        ("SSH_BRUTE_FORCE", ("SSH-Patator", "SSH-Patator - Attempted")),
    )),
    DatasetCase("unified", (
        ("BENIGN", ("BENIGN", "Botnet - Attempted", "FTP-Patator - Attempted",
                    "SSH-Patator - Attempted", "DoS GoldenEye - Attempted",
                    "DoS Hulk - Attempted", "DoS Slowhttptest - Attempted",
                    "DoS Slowloris - Attempted", "Web Attack - Brute Force - Attempted",
                    "Web Attack - XSS - Attempted")),
        ("BOTNET", ("Botnet",)),
        ("BRUTE_FORCE", ("FTP-Patator", "SSH-Patator")),
        ("DDOS", ("DDoS",)),
        ("DOS", ("DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS Slowloris")),
        ("PORTSCAN", ("Portscan", "Infiltration - Portscan")),
        ("WEB_ATTACK", ("Web Attack - Brute Force", "Web Attack - XSS")),
    ), ("Infiltration", "Infiltration - Attempted", "Web Attack - SQL Injection",
        "Web Attack - SQL Injection - Attempted", "Heartbleed")),
)


@pytest.fixture
def dataset_cases():
    return DATASET_CASES


@pytest.fixture(params=DATASET_CASES, ids=lambda case: case.name)
def dataset_case(request):
    return request.param


@pytest.fixture(autouse=True)
def isolated_project(tmp_path, monkeypatch):
    """Redirect registry paths and legacy Friday defaults away from real runs."""
    monkeypatch.setattr(datasets, "PROJECT_ROOT", tmp_path)
    config = datasets.get_dataset("friday")
    paths = {
        "RAW_CSV": config.raw_csv,
        "PROCESSED_CSV": config.processed_dir / "cleaned_friday.csv",
        "SPLITS_PATH": config.splits_path,
        "MODELS_DIR": config.models_dir,
        "SCALER_PATH": config.models_dir / "scaler.pkl",
        "LABEL_ENCODER_PATH": config.models_dir / "label_encoder.pkl",
        "RF_MODEL_PATH": config.models_dir / "random_forest.pkl",
        "XGB_MODEL_PATH": config.models_dir / "xgboost.pkl",
        "BUNDLE_PATH": config.models_dir / "inference_bundle.pkl",
        "REPORTS_DIR": config.reports_dir,
    }
    for module in (preprocess, train, evaluate, predictor):
        for name, path in paths.items():
            if hasattr(module, name):
                monkeypatch.setattr(module, name, str(path))
    monkeypatch.setattr(predictor, "_bundle", None)
    monkeypatch.setattr(predictor, "_weekday_bundles", {})
    return tmp_path


@pytest.fixture
def flow_factory():
    """Build unique model inputs in repeated, bidirectional connection groups."""
    def make(case, groups=30):
        rows = []
        for class_index, (_, source_labels) in enumerate(case.labels):
            for group in range(groups):
                for direction in range(2):
                    row = {
                        column: float(1 + class_index * 1000 + group * 2 + direction)
                        for column in preprocess.SELECTED_COLUMNS
                    }
                    row.update({
                        "Src IP dec": 100 + class_index,
                        "Dst IP dec": 200 + class_index,
                        "Src Port": 10000 + group, "Dst Port": 443, "Protocol": 6,
                        "Label": source_labels[(group * 2 + direction) % len(source_labels)],
                    })
                    if direction:
                        for left, right in (("Src IP dec", "Dst IP dec"), ("Src Port", "Dst Port")):
                            row[left], row[right] = row[right], row[left]
                    rows.append(row)
        return pd.DataFrame(rows)
    return make


@pytest.fixture
def raw_flows(dataset_case, flow_factory):
    return flow_factory(dataset_case)


@pytest.fixture
def cleaned_flows(dataset_case, raw_flows):
    cleaned, _ = preprocess.clean_data(raw_flows, dataset=dataset_case.name)
    return cleaned


@pytest.fixture
def splits(dataset_case, cleaned_flows):
    return preprocess.split_data(cleaned_flows, classes=dataset_case.classes)


@pytest.fixture
def small_estimators(monkeypatch):
    """Use real RF and XGBoost fits with bounded test-time size and concurrency."""
    def small_rf(**kwargs):
        kwargs.update(n_estimators=5, max_depth=3, n_jobs=1)
        return RandomForestClassifier(**kwargs)

    def small_xgb(**kwargs):
        kwargs.update(n_estimators=5, max_depth=3, n_jobs=1)
        return XGBClassifier(**kwargs)

    monkeypatch.setattr(train, "RandomForestClassifier", small_rf)
    monkeypatch.setattr(train, "XGBClassifier", small_xgb)


@pytest.fixture
def prepare_dataset(flow_factory):
    def prepare(case):
        config = datasets.get_dataset(case.name)
        raw = flow_factory(case)
        config.raw_csv.parent.mkdir(parents=True, exist_ok=True)
        raw.to_csv(config.raw_csv, index=False)
        payload = preprocess.preprocess_data(dataset=case.name)
        return SimpleNamespace(config=config, raw=raw, payload=payload)
    return prepare


@pytest.fixture
def prepared_run(dataset_case, prepare_dataset):
    return prepare_dataset(dataset_case)


@pytest.fixture
def train_dataset(prepare_dataset, small_estimators):
    def fit(case):
        run = prepare_dataset(case)
        run.metadata = train.train_model(dataset=case.name)
        run.bundle_path = run.config.models_dir / "inference_bundle.pkl"
        run.bundle = joblib.load(run.bundle_path)
        return run
    return fit


@pytest.fixture
def trained_run(dataset_case, train_dataset):
    return train_dataset(dataset_case)


@pytest.fixture
def valid_features():
    return {column: 1 for column in preprocess.SELECTED_COLUMNS}


@pytest.fixture
def manual_clock():
    class Clock:
        value = 0.0

        def __call__(self):
            return self.value

        def advance(self, seconds):
            self.value += seconds
    return Clock()


@pytest.fixture
def response_event_factory(valid_features):
    from sniffer.events import DetectionEvent

    def make(label="PORTSCAN", confidence=0.99, src_ip="10.10.0.9", **metadata):
        features = {**valid_features, "Src Port": 40000, "Dst Port": 80, "Protocol": 6}
        probabilities = dict.fromkeys(datasets.get_dataset("unified").classes, 0.0)
        probabilities[label] = confidence
        probabilities["BENIGN" if label != "BENIGN" else "PORTSCAN"] += 1 - confidence
        return DetectionEvent(src_ip=src_ip, dst_ip="10.10.0.2", features=features,
            label=label, confidence=confidence, probabilities=probabilities,
            model_scope="unified", model_sha256="a" * 64, source="pcap", **metadata)
    return make


# Backend fixtures construct private app instances; no configured engine is imported.
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from backend.config import Settings
from backend.database import sessions_for
from backend.firewall import FirewallController
from backend.main import create_app
from backend.manage import bootstrap_admin

PASSWORD = "ReviewPassword123!"


@pytest.fixture
def backend_runtime(tmp_path):
    config = Settings(DATABASE_URL="sqlite:///" + str(tmp_path / "backend.sqlite"),
                      SECRET_KEY="u" * 40, SENSOR_API_TOKEN="s" * 40)
    engine = create_engine(config.DATABASE_URL, connect_args={"check_same_thread": False})
    application = create_app(config, engine=engine)
    with TestClient(application, raise_server_exceptions=False) as client:
        yield SimpleNamespace(config=config, engine=engine, app=application, client=client,
                              sessions=sessions_for(engine))
    engine.dispose()


@pytest.fixture
def sensor_headers(backend_runtime):
    config = backend_runtime.config
    return {"X-Sensor-Token": config.SENSOR_API_TOKEN, "X-Sensor-ID": config.SENSOR_ID}


@pytest.fixture
def admin_headers(backend_runtime):
    runtime = backend_runtime
    bootstrap_admin(runtime.engine, "review_admin", "admin@example.com", PASSWORD)
    response = runtime.client.post("/api/auth/login", data={"username": "review_admin", "password": PASSWORD})
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json()["access_token"]}


@pytest.fixture
def operator_headers(backend_runtime, admin_headers):
    client = backend_runtime.client
    created = client.post("/api/auth/register", headers=admin_headers,
        json={"username": "review_operator", "email": "operator@example.com", "password": PASSWORD})
    assert created.status_code == 201 and not created.json()["is_admin"]
    token = client.post("/api/auth/login", data={"username": "review_operator", "password": PASSWORD})
    return {"Authorization": "Bearer " + token.json()["access_token"]}


@pytest.fixture
def payload_factory(response_event_factory):
    def make(with_block=False):
        event = response_event_factory().to_dict()
        firewall = FirewallController().block_ip(event["src_ip"], event["label"]) if with_block else None
        return {"event": event, "decision": {"action": "candidate" if with_block else "alert",
            "reason": "repeated_high_score_flows" if with_block else "single_flow", "evidence_count": 3 if with_block else 1},
            "firewall": firewall}
    return make
