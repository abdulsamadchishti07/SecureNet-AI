"""Transactional event persistence and acknowledged simulated response state."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from uuid import uuid4

from sqlalchemy import case, func
from sqlalchemy.exc import IntegrityError

from backend.models import Alert, BlockedIP, FirewallEvent, ResponseCommand
from backend.schemas import AlertIngest, FirewallActionIn, ReconcileIn


class ConflictError(ValueError):
    pass


class MissingRecordError(ValueError):
    pass


def fingerprint(payload, sensor_id):
    serialized = json.dumps({"sensor_id": sensor_id, "payload": payload}, sort_keys=True,
                            separators=(",", ":"), allow_nan=False)
    return sha256(serialized.encode()).hexdigest()


@dataclass
class DetectionResult:
    alert: Alert
    created: bool


class AlertService:
    @staticmethod
    def record_detection(db, payload, sensor_id):
        envelope = payload if isinstance(payload, AlertIngest) else AlertIngest.model_validate(payload)
        body = envelope.model_dump(mode="json")
        # Preserve schema-v1 fingerprints for deliveries made before optional capture timing.
        for name in ("capture_time", "capture_start", "capture_available_at"):
            if body["event"][name] is None:
                del body["event"][name]
        digest = fingerprint(body, sensor_id)
        event = envelope.event
        existing = db.query(Alert).filter_by(event_id=str(event.event_id)).first()
        if existing:
            if existing.payload_sha256 != digest or existing.sensor_id != sensor_id:
                raise ConflictError("Event ID already exists with a different payload or owner")
            return DetectionResult(existing, False)
        alert = Alert(event_id=str(event.event_id), observed_at=event.observed_at,
            source=event.source, src_ip=str(event.src_ip), dst_ip=str(event.dst_ip),
            src_port=event.src_port, dst_port=event.dst_port, protocol=event.protocol,
            label=event.label, confidence=event.confidence, probabilities=event.probabilities,
            features=event.features, model_scope=event.model_scope, model_run=event.model_run,
            model_sha256=event.model_sha256, sensor_id=sensor_id, payload_sha256=digest,
            payload=body, decision_action=envelope.decision.action, decision_reason=envelope.decision.reason)
        db.add(alert)
        proposal = envelope.firewall
        if proposal and proposal.status in ("would_block", "blocked"):
            block = proposal.block
            db.add(BlockedIP(block_id=str(block.block_id), sensor_id=sensor_id,
                ip=str(proposal.ip), threat=proposal.threat, mode=proposal.mode, command=proposal.command,
                status="ACTIVE", blocked_at=block.blocked_at, unblock_at=block.unblock_at))
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            existing = db.query(Alert).filter_by(event_id=str(event.event_id)).first()
            if existing and existing.payload_sha256 == digest and existing.sensor_id == sensor_id:
                return DetectionResult(existing, False)
            raise ConflictError("Event or block identity conflicts with an existing record") from exc
        return DetectionResult(alert, True)

    @staticmethod
    def expire_due(db):
        count = db.query(BlockedIP).filter(BlockedIP.status == "ACTIVE",
            BlockedIP.unblock_at <= datetime.now(timezone.utc)).update(
                {BlockedIP.status: "EXPIRY_PENDING"}, synchronize_session=False)
        if count:
            db.commit()
            db.expire_all()

    @staticmethod
    def list_alerts(db, skip=0, limit=50, label=None, min_confidence=None):
        query = db.query(Alert)
        if label:
            query = query.filter(Alert.label == label.upper())
        if min_confidence is not None:
            query = query.filter(Alert.confidence >= min_confidence)
        return query.order_by(Alert.observed_at.desc(), Alert.id.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def get_summary_stats(db):
        AlertService.expire_due(db)
        counts = dict(db.query(Alert.label, func.count(Alert.id)).group_by(Alert.label).all())
        simulated = db.query(func.count(BlockedIP.id)).filter(
            BlockedIP.status == "ACTIVE", BlockedIP.mode == "dry_run").scalar() or 0
        enforced = db.query(func.count(BlockedIP.id)).filter(
            BlockedIP.status == "ACTIVE", BlockedIP.mode == "enforced").scalar() or 0
        response_mode = "enforced" if enforced and not simulated else ("mixed" if enforced and simulated else "dry_run")
        return {"total_events": sum(counts.values()), "total_attacks": sum(
            count for label, count in counts.items() if label != "BENIGN"),
            "active_blocked_ips": enforced, "active_simulated_blocks": simulated,
            "pending_unblocks": db.query(func.count(ResponseCommand.command_id)).filter_by(status="PENDING").scalar() or 0,
            "threat_distribution": counts, "response_mode": response_mode}

    @staticmethod
    def get_analytics(db, minutes=60):
        """Bounded-size SQL aggregates over persisted flows, never invented packets."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)
        seconds = minutes * 60 // 20
        # Compare native UTC timestamps so subsecond boundaries agree on both DBs.
        index = case(*[(Alert.observed_at < start + timedelta(seconds=(i + 1) * seconds), i)
                       for i in range(19)], else_=19)
        window = (Alert.observed_at >= start, Alert.observed_at < end)
        grouped = db.query(index, func.count(Alert.id),
            func.sum(case((Alert.label != "BENIGN", 1), else_=0))).filter(*window).group_by(index).all()
        counts = {int(slot): (int(total), int(attacks)) for slot, total, attacks in grouped}
        buckets = [{"start": start + timedelta(seconds=i * seconds),
                    "end": start + timedelta(seconds=(i + 1) * seconds),
                    "total": counts.get(i, (0, 0))[0], "attacks": counts.get(i, (0, 0))[1]}
                   for i in range(20)]
        protocols = db.query(Alert.protocol, func.count(Alert.id)).filter(*window).group_by(Alert.protocol).all()
        sources = db.query(Alert.src_ip, func.count(Alert.id).label("count")).filter(
            *window, Alert.label != "BENIGN").group_by(Alert.src_ip).order_by(
                func.count(Alert.id).desc(), Alert.src_ip).limit(5).all()
        return {"window_minutes": minutes, "window_start": start, "window_end": end,
                "time_basis": "observed_at", "buckets": buckets,
                "total_flows": sum(row["total"] for row in buckets),
                "attack_flows": sum(row["attacks"] for row in buckets),
                "protocols": [{"protocol": int(protocol), "count": int(count)} for protocol, count in protocols],
                "top_sources": [{"ip": ip, "count": int(count)} for ip, count in sources]}

    @staticmethod
    def list_blocked_ips(db, status="ACTIVE", skip=0, limit=50):
        AlertService.expire_due(db)
        query = db.query(BlockedIP)
        if status:
            query = query.filter(BlockedIP.status == status)
        return query.order_by(BlockedIP.blocked_at.desc(), BlockedIP.id.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def request_unblock(db, ip, requested_by, block_id=None):
        AlertService.expire_due(db)
        query = db.query(BlockedIP).filter(BlockedIP.ip == str(ip), BlockedIP.status.in_(
            ["ACTIVE", "EXPIRY_PENDING", "UNBLOCK_REQUESTED"]))
        if block_id is not None:
            query = query.filter(BlockedIP.block_id == str(block_id))
        record = query.order_by(BlockedIP.id.desc()).first()
        if record is None:
            raise MissingRecordError("No pending or active simulated block for this IP")
        if not record.block_id or not record.sensor_id:
            raise ConflictError("Legacy block has no sensor ownership; reconcile it before requesting changes")
        existing = db.query(ResponseCommand).filter_by(block_id=record.block_id).first()
        if existing:
            return existing
        command = ResponseCommand(command_id=str(uuid4()), block_id=record.block_id,
                                  sensor_id=record.sensor_id, ip=record.ip, status="PENDING", requested_by=requested_by)
        record.status = "UNBLOCK_REQUESTED"
        db.add(command)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            command = db.query(ResponseCommand).filter_by(block_id=record.block_id).first()
            if command is None:
                raise
        return command

    @staticmethod
    def pending_commands(db, sensor_id, limit=100):
        return db.query(ResponseCommand).filter_by(sensor_id=sensor_id, status="PENDING").order_by(
            ResponseCommand.created_at, ResponseCommand.command_id).limit(limit).all()

    @staticmethod
    def record_firewall_event(db, action, sensor_id, *, commit=True):
        action = action if isinstance(action, FirewallActionIn) else FirewallActionIn.model_validate(action)
        body = action.model_dump(mode="json")
        digest = fingerprint(body, sensor_id)
        existing = db.get(FirewallEvent, str(action.action_id))
        if existing:
            if existing.payload_sha256 != digest or existing.sensor_id != sensor_id:
                raise ConflictError("Action ID has a different payload or owner")
            return existing
        block = db.query(BlockedIP).filter_by(block_id=str(action.block_id), sensor_id=sensor_id,
                                             ip=str(action.ip)).first()
        if block is None:
            raise MissingRecordError("Unknown block or sensor ownership")
        record = FirewallEvent(action_id=str(action.action_id), sensor_id=sensor_id,
                               block_id=block.block_id, payload_sha256=digest, payload=body)
        db.add(record)
        if block.status not in ("EXPIRED", "UNBLOCKED", "ROLLED_BACK"):
            if action.reason == "rollback":
                block.status = "ROLLED_BACK"
            elif action.reason == "expired":
                block.status = "EXPIRED"
            else:
                block.status = "UNBLOCKED"
            block.unblocked_at = datetime.now(timezone.utc)
        if commit:
            try:
                db.commit()
            except IntegrityError as exc:
                db.rollback()
                existing = db.get(FirewallEvent, str(action.action_id))
                if existing and existing.payload_sha256 == digest and existing.sensor_id == sensor_id:
                    return existing
                raise ConflictError("Conflicting action identity") from exc
        return record

    @staticmethod
    def reconcile_sensor_blocks(db, payload, sensor_id):
        envelope = payload if isinstance(payload, ReconcileIn) else ReconcileIn.model_validate(payload)
        keep_ids = {str(item) for item in envelope.active_block_ids}
        now = datetime.now(timezone.utc)
        rows = db.query(BlockedIP).filter(
            BlockedIP.sensor_id == sensor_id,
            BlockedIP.mode == "enforced",
            BlockedIP.status.in_(["ACTIVE", "EXPIRY_PENDING", "UNBLOCK_REQUESTED"]),
        ).all()
        rolled_back_ids = []
        for row in rows:
            if row.block_id not in keep_ids:
                row.status = "ROLLED_BACK"
                row.unblocked_at = now
                if row.block_id:
                    rolled_back_ids.append(row.block_id)
        if rolled_back_ids:
            db.query(ResponseCommand).filter(
                ResponseCommand.sensor_id == sensor_id,
                ResponseCommand.block_id.in_(rolled_back_ids),
                ResponseCommand.status == "PENDING",
            ).update(
                {
                    ResponseCommand.status: "CANCELLED",
                    ResponseCommand.acknowledged_at: now,
                    ResponseCommand.result: {"reason": envelope.reason},
                },
                synchronize_session=False,
            )
        if rows:
            db.commit()
        return {"status": "reconciled", "rolled_back": len(rolled_back_ids), "reason": envelope.reason}

    @staticmethod
    def acknowledge_command(db, command_id, action, sensor_id):
        command = db.query(ResponseCommand).filter_by(command_id=str(command_id), sensor_id=sensor_id).first()
        if command is None:
            raise MissingRecordError("Unknown command or sensor ownership")
        body = action.model_dump(mode="json")
        if str(action.block_id) != command.block_id or str(action.ip) != command.ip or action.reason != "manual":
            raise ConflictError("Acknowledgement does not match the requested block")
        if command.status == "ACKNOWLEDGED":
            if command.result != body:
                raise ConflictError("Command already has a different acknowledgement")
            return command
        AlertService.record_firewall_event(db, action, sensor_id, commit=False)
        command.status, command.result = "ACKNOWLEDGED", body
        command.acknowledged_at = datetime.now(timezone.utc)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            command = db.get(ResponseCommand, str(command_id))
            if command and command.sensor_id == sensor_id and command.result == body:
                return command
            raise ConflictError("Conflicting command acknowledgement") from exc
        return command
