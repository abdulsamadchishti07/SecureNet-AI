"""Alert persistence, firewall state queries, and statistics aggregation."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models import Alert, BlockedIP


class AlertService:
    @staticmethod
    def record_detection(
        db: Session,
        event: Dict[str, Any],
        decision: Optional[Dict[str, Any]] = None,
        firewall: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Persist a detection event and any associated firewall block action."""
        decision = decision or {}
        observed = event.get("observed_at")
        if isinstance(observed, str):
            observed_dt = datetime.fromisoformat(observed)
        elif isinstance(observed, datetime):
            observed_dt = observed
        else:
            observed_dt = datetime.now(timezone.utc)

        alert = Alert(
            event_id=event["event_id"],
            observed_at=observed_dt,
            source=event.get("source", "live"),
            src_ip=event["src_ip"],
            dst_ip=event["dst_ip"],
            src_port=int(event["src_port"]),
            dst_port=int(event["dst_port"]),
            protocol=int(event["protocol"]),
            label=event["label"],
            confidence=float(event["confidence"]),
            probabilities=event.get("probabilities"),
            features=event.get("features"),
            model_scope=event.get("model_scope", "unified"),
            decision_action=decision.get("action", "alert"),
            decision_reason=decision.get("reason"),
        )
        db.add(alert)

        # Record firewall action if a block proposal or active block was generated
        if firewall and firewall.get("status") in ("would_block", "blocked"):
            block_meta = firewall.get("block", {})
            blocked_at = block_meta.get("blocked_at")
            unblock_at = block_meta.get("unblock_at")

            blocked_ip = BlockedIP(
                ip=firewall["ip"],
                threat=firewall.get("threat", alert.label),
                mode=firewall.get("mode", "dry_run"),
                command=firewall.get("command"),
                status="ACTIVE",
                blocked_at=datetime.fromisoformat(blocked_at) if isinstance(blocked_at, str) else datetime.now(timezone.utc),
                unblock_at=datetime.fromisoformat(unblock_at) if isinstance(unblock_at, str) else datetime.now(timezone.utc),
            )
            db.add(blocked_ip)

        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def list_alerts(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        label: Optional[str] = None,
        min_confidence: Optional[float] = None,
    ) -> List[Alert]:
        """Query paginated alerts with optional threat and confidence filtering."""
        query = db.query(Alert)
        if label:
            query = query.filter(Alert.label == label.upper())
        if min_confidence is not None:
            query = query.filter(Alert.confidence >= min_confidence)
        return query.order_by(Alert.observed_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def get_summary_stats(db: Session) -> Dict[str, Any]:
        """Aggregate high-level security metrics for the admin dashboard."""
        total_alerts = db.query(func.count(Alert.id)).scalar() or 0
        total_attacks = db.query(func.count(Alert.id)).filter(Alert.label != "BENIGN").scalar() or 0
        active_blocks = db.query(func.count(BlockedIP.id)).filter(BlockedIP.status == "ACTIVE").scalar() or 0

        # Threat distribution breakdown
        counts_by_threat = (
            db.query(Alert.label, func.count(Alert.id))
            .group_by(Alert.label)
            .all()
        )
        distribution = {label: count for label, count in counts_by_threat}

        return {
            "total_events": total_alerts,
            "total_attacks": total_attacks,
            "active_blocked_ips": active_blocks,
            "threat_distribution": distribution,
        }

    @staticmethod
    def list_blocked_ips(db: Session, status: Optional[str] = "ACTIVE") -> List[BlockedIP]:
        """List blocked IP records."""
        query = db.query(BlockedIP)
        if status:
            query = query.filter(BlockedIP.status == status.upper())
        return query.order_by(BlockedIP.blocked_at.desc()).all()

    @staticmethod
    def unblock_ip(db: Session, ip: str) -> Optional[BlockedIP]:
        """Mark an active block record as UNBLOCKED."""
        record = (
            db.query(BlockedIP)
            .filter(BlockedIP.ip == ip, BlockedIP.status == "ACTIVE")
            .first()
        )
        if record:
            record.status = "UNBLOCKED"
            record.unblocked_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(record)
        return record
