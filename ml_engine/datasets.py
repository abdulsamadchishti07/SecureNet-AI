"""Explicit label policies and isolated artifact locations for each dataset."""

from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class DatasetConfig:
    name: str
    run_directory: str
    classes: tuple[str, ...]
    label_mapping: dict[str, str]
    excluded_labels: tuple[str, ...] = ()

    @property
    def raw_csv(self):
        return PROJECT_ROOT / "dataset" / "raw" / f"{self.name}.csv"

    @property
    def processed_dir(self):
        return PROJECT_ROOT / "dataset" / "processed"

    @property
    def splits_path(self):
        return self.processed_dir / f"{self.name}_splits.pkl"

    @property
    def models_dir(self):
        return PROJECT_ROOT / "ml_engine" / "models" / self.run_directory

    @property
    def reports_dir(self):
        return PROJECT_ROOT / "reports" / self.name


DATASETS = {
    "friday": DatasetConfig(
        name="friday", run_directory="friday_v2",
        classes=("BENIGN", "BOTNET", "DDOS", "PORTSCAN"),
        label_mapping={
            "Botnet": "BOTNET", "Botnet - Attempted": "BOTNET",
            "Portscan": "PORTSCAN", "DDoS": "DDOS",
        },
    ),
    "thursday": DatasetConfig(
        name="thursday", run_directory="thursday_v1",
        classes=("BENIGN", "PORTSCAN", "WEB_BRUTE_FORCE", "WEB_XSS"),
        label_mapping={
            "Infiltration - Portscan": "PORTSCAN",
            "Web Attack - Brute Force": "WEB_BRUTE_FORCE",
            "Web Attack - Brute Force - Attempted": "WEB_BRUTE_FORCE",
            "Web Attack - XSS": "WEB_XSS",
            "Web Attack - XSS - Attempted": "WEB_XSS",
        },
        excluded_labels=(
            "Infiltration", "Infiltration - Attempted",
            "Web Attack - SQL Injection", "Web Attack - SQL Injection - Attempted",
        ),
    ),
    "wednesday": DatasetConfig(
        name="wednesday", run_directory="wednesday_v1",
        classes=("BENIGN", "DOS_GOLDENEYE", "DOS_HULK", "DOS_SLOWHTTPTEST", "DOS_SLOWLORIS"),
        label_mapping={
            "DoS GoldenEye": "DOS_GOLDENEYE",
            "DoS GoldenEye - Attempted": "DOS_GOLDENEYE",
            "DoS Hulk": "DOS_HULK",
            "DoS Hulk - Attempted": "DOS_HULK",
            "DoS Slowhttptest": "DOS_SLOWHTTPTEST",
            "DoS Slowhttptest - Attempted": "DOS_SLOWHTTPTEST",
            "DoS Slowloris": "DOS_SLOWLORIS",
            "DoS Slowloris - Attempted": "DOS_SLOWLORIS",
        },
        excluded_labels=("Heartbleed",),
    ),
    "tuesday": DatasetConfig(
        name="tuesday", run_directory="tuesday_v1",
        classes=("BENIGN", "FTP_BRUTE_FORCE", "SSH_BRUTE_FORCE"),
        label_mapping={
            "FTP-Patator": "FTP_BRUTE_FORCE",
            "FTP-Patator - Attempted": "FTP_BRUTE_FORCE",
            "SSH-Patator": "SSH_BRUTE_FORCE",
            "SSH-Patator - Attempted": "SSH_BRUTE_FORCE",
        },
    ),
}


def get_dataset(name):
    try:
        return DATASETS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown dataset {name!r}; choose from {tuple(DATASETS)}") from exc


def dataset_argument(description):
    """Keep CLI selection identical across preprocessing/training/evaluation."""
    import argparse

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--dataset", choices=tuple(DATASETS), default="friday")
    return parser.parse_args().dataset
