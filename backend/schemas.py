"""Strict wire contracts shared by ingestion, lifecycle acknowledgements and tests."""

from datetime import timezone
from ipaddress import IPv4Address
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (AwareDatetime, BaseModel, ConfigDict, EmailStr, Field,
                      StrictFloat, StrictInt, field_validator, model_validator)

from backend.auth import validate_password
from backend.firewall import FirewallController
from ml_engine.datasets import get_dataset
from sniffer.events import DetectionEvent


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class UserRegister(WireModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    email: EmailStr = Field(max_length=128)
    password: str
    is_admin: bool = False

    @field_validator("password")
    @classmethod
    def password_policy(cls, value):
        return validate_password(value, new=True)


class UserOut(WireModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: str
    is_admin: bool


class EventIn(WireModel):
    schema_version: Literal[1] = 1
    event_id: UUID
    observed_at: AwareDatetime
    source: Literal["live", "pcap"]
    src_ip: IPv4Address
    dst_ip: IPv4Address
    src_port: Annotated[StrictInt, Field(ge=0, le=65535)]
    dst_port: Annotated[StrictInt, Field(ge=0, le=65535)]
    protocol: Annotated[StrictInt, Field(ge=0, le=255)]
    label: str
    confidence: Annotated[StrictFloat, Field(ge=0, le=1)]
    features: dict[str, StrictFloat]
    probabilities: dict[str, StrictFloat]
    model_scope: str
    model_run: str
    model_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def consistent_event(self):
        config = get_dataset(self.model_scope)
        if self.model_run != config.run_directory:
            raise ValueError("Model run does not match the requested scope")
        event = DetectionEvent(src_ip=str(self.src_ip), dst_ip=str(self.dst_ip), features=self.features,
            label=self.label, confidence=self.confidence, probabilities=self.probabilities,
            model_scope=self.model_scope, model_sha256=self.model_sha256, source=self.source,
            event_id=str(self.event_id), observed_at=self.observed_at)
        for name, value in (("Src Port", self.src_port), ("Dst Port", self.dst_port), ("Protocol", self.protocol)):
            if event.features[name] != value:
                raise ValueError("Endpoint metadata disagrees with model features")
        self.observed_at = self.observed_at.astimezone(timezone.utc)
        return self


class DecisionIn(WireModel):
    action: Literal["ignore", "alert", "candidate"]
    reason: str = Field(min_length=1, max_length=128)
    evidence_count: Annotated[StrictInt, Field(ge=0, le=10000)] = 0


class BlockIn(WireModel):
    block_id: UUID
    ip: IPv4Address
    threat: str
    mode: Literal["dry_run"]
    blocked_at: AwareDatetime
    unblock_at: AwareDatetime

    @model_validator(mode="after")
    def valid_duration(self):
        if self.unblock_at <= self.blocked_at:
            raise ValueError("Block expiry must follow its creation")
        self.blocked_at = self.blocked_at.astimezone(timezone.utc)
        self.unblock_at = self.unblock_at.astimezone(timezone.utc)
        return self


class ProposalIn(WireModel):
    mode: Literal["dry_run"]
    ip: IPv4Address
    threat: str
    status: Literal["would_block", "already_simulated", "protected", "capacity_reached"]
    block: BlockIn | None = None
    command: list[str] | None = None

    @model_validator(mode="after")
    def consistent_proposal(self):
        if self.status in ("would_block", "already_simulated"):
            if self.block is None or self.block.ip != self.ip:
                raise ValueError("A block proposal needs matching block metadata")
        if self.status == "would_block" and self.command != FirewallController._command(str(self.ip), "-A"):
            raise ValueError("Invalid simulated firewall proposal")
        return self


class AlertIngest(WireModel):
    event: EventIn
    decision: DecisionIn
    firewall: ProposalIn | None = None

    @model_validator(mode="after")
    def supported_response(self):
        if self.decision.action == "candidate" and (
                self.event.label in ("BENIGN", "WEB_ATTACK") or self.event.model_scope != "unified"):
            raise ValueError("This coverage is alert-only")
        if self.firewall:
            if self.decision.action != "candidate" or self.firewall.ip != self.event.src_ip:
                raise ValueError("Firewall proposals must match a candidate event")
            if self.firewall.threat != self.event.label:
                raise ValueError("Firewall threat differs from the event")
            if self.firewall.block and self.firewall.block.threat != self.event.label:
                raise ValueError("Block metadata differs from the event")
        return self


class FirewallActionIn(WireModel):
    action_id: UUID
    block_id: UUID
    mode: Literal["dry_run"]
    ip: IPv4Address
    status: Literal["would_unblock", "not_simulated", "stale_block"]
    reason: Literal["manual", "expired"]
    command: list[str] | None = None

    @model_validator(mode="after")
    def valid_command(self):
        expected = FirewallController._command(str(self.ip), "-D")
        if self.status == "would_unblock" and self.command != expected:
            raise ValueError("Invalid simulated unblock proposal")
        if self.reason == "expired" and self.status != "would_unblock":
            raise ValueError("Expiry must identify the simulated block removed")
        return self


class CommandAck(WireModel):
    action: FirewallActionIn
