"""Validated, immutable detection events for the local response pipeline."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address
import math
from numbers import Real
from types import MappingProxyType
from uuid import UUID, uuid4

from ml_engine.datasets import get_dataset
from ml_engine.preprocess import SELECTED_COLUMNS


class EventValidationError(ValueError):
    """A flow/prediction cannot be represented as a response event."""


def finite_number(value, name, minimum=0, maximum=float("inf")):
    if isinstance(value, bool) or not isinstance(value, Real):
        raise EventValidationError(f"{name} must be numeric")
    try:
        value = float(value)
    except OverflowError as exc:
        raise EventValidationError(f"{name} is outside its finite range") from exc
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise EventValidationError(f"{name} is outside its finite range")
    return value


@dataclass(frozen=True)
class DetectionEvent:
    src_ip: str
    dst_ip: str
    features: dict
    label: str
    confidence: float
    probabilities: dict
    model_scope: str
    model_sha256: str
    source: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        try:
            config = get_dataset(self.model_scope)
            UUID(self.event_id)
            for name in ("src_ip", "dst_ip"):
                value = getattr(self, name)
                if not isinstance(value, str):
                    raise ValueError("IP metadata must be IPv4 strings")
                object.__setattr__(self, name, str(IPv4Address(value)))
            if self.source not in ("live", "pcap"):
                raise ValueError("source must be live or pcap")
            if (not isinstance(self.model_sha256, str) or len(self.model_sha256) != 64
                    or any(c not in "0123456789abcdef" for c in self.model_sha256)):
                raise ValueError("model_sha256 must identify the loaded artifact")
            if not isinstance(self.observed_at, datetime) or self.observed_at.utcoffset() is None:
                raise ValueError("observed_at must have a timezone")
            if self.label not in config.classes or set(self.probabilities) != set(config.classes):
                raise ValueError("Prediction labels must match the configured model")
            features = {name: finite_number(self.features[name], name) for name in SELECTED_COLUMNS}
            for name, maximum in (("Src Port", 65535), ("Dst Port", 65535), ("Protocol", 255)):
                if not features[name].is_integer() or features[name] > maximum:
                    raise ValueError(f"Invalid discrete feature: {name}")
            probabilities = {name: finite_number(value, name, maximum=1)
                             for name, value in self.probabilities.items()}
            confidence = finite_number(self.confidence, "confidence", maximum=1)
            if (not math.isclose(sum(probabilities.values()), 1, abs_tol=1e-6)
                    or not math.isclose(confidence, probabilities[self.label], abs_tol=1e-6)
                    or confidence + 1e-6 < max(probabilities.values())):
                raise ValueError("Prediction probabilities/confidence disagree")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise EventValidationError(str(exc)) from exc
        object.__setattr__(self, "features", MappingProxyType(features))
        object.__setattr__(self, "probabilities", MappingProxyType(probabilities))
        object.__setattr__(self, "confidence", confidence)

    @classmethod
    def from_flow(cls, flow, prediction, **metadata):
        try:
            return cls(src_ip=flow["Src IP"], dst_ip=flow["Dst IP"], features=flow,
                       label=prediction["label"], confidence=prediction["confidence"],
                       probabilities=prediction["probabilities"], **metadata)
        except (KeyError, TypeError) as exc:
            raise EventValidationError(f"Missing or invalid event metadata: {exc}") from exc

    def to_dict(self):
        return {
            "schema_version": 1, "event_id": self.event_id,
            # Observation time is processing time, not an invented packet timestamp.
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
            "source": self.source, "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": int(self.features["Src Port"]),
            "dst_port": int(self.features["Dst Port"]), "protocol": int(self.features["Protocol"]),
            "label": self.label, "confidence": self.confidence,
            "probabilities": dict(self.probabilities), "features": dict(self.features),
            "model_scope": self.model_scope, "model_run": get_dataset(self.model_scope).run_directory,
            "model_sha256": self.model_sha256,
        }
