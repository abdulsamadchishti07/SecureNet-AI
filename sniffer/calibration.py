"""Offline policy sensitivity analysis; this does not certify prevention thresholds."""

import argparse
from datetime import datetime
import itertools
import json
from pathlib import Path

from ml_engine.preprocess import sha256_file
from sniffer.events import DetectionEvent
from sniffer.rules import ResponsePolicy


def load_events(path):
    events = []
    with Path(path).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("record_type") == "firewall":
                continue
            row = row.get("event", row)
            metadata = {name: row[name] for name in ("source", "event_id", "model_scope", "model_sha256")}
            for name in ("observed_at", "capture_time", "capture_start", "capture_available_at"):
                if row.get(name) is not None:
                    metadata[name] = datetime.fromisoformat(row[name])
            events.append(DetectionEvent(src_ip=row["src_ip"], dst_ip=row["dst_ip"], features=row["features"],
                label=row["label"], confidence=row["confidence"], probabilities=row["probabilities"], **metadata))
    return events


def calibrate(events, confidences=(0.90,), min_flows=(2, 3, 4), windows=(10, 60), truth=None):
    """Replay in delivery order. Independent truth is an optional complete ID->label map.

    Latency starts at first labelled attack-flow packet, not unobserved attack onset.
    Candidates repeat while eligible; first candidate per source is reported separately.
    No firewall state is involved in this experimental counterfactual.
    """
    if not events:
        raise ValueError("Calibration needs events")
    if len({e.event_id for e in events}) != len(events):
        raise ValueError("Calibration cohort must contain unique event IDs")
    if any(e.capture_start is None or e.capture_time is None or e.capture_available_at is None for e in events):
        raise ValueError("Calibration requires complete capture timing")
    if truth is not None and set(truth) != {e.event_id for e in events}:
        raise ValueError("Truth must label exactly every event ID")
    labels = set(events[0].probabilities)
    if truth is not None and any(value not in labels for value in truth.values()):
        raise ValueError("Truth labels must use the model taxonomy")
    onset = {}
    for event in events:
        label = truth[event.event_id] if truth is not None else event.label
        if label != "BENIGN":
            onset[event.src_ip] = min(onset.get(event.src_ip, event.capture_start), event.capture_start)
    runs = []
    for confidence, count, window in itertools.product(confidences, min_flows, windows):
        policy = ResponsePolicy(confidence, count, window, clock_mode="event_time")
        candidates, first, reached, late = [], {}, {}, 0
        action_counts = {"alert": 0, "ignore": 0, "candidate": 0}
        for event in events:
            decision = policy.evaluate(event)
            action_counts[decision.action] += 1
            late += decision.reason == "late_capture_event"
            if decision.action == "candidate":
                candidates.append(event)
                first.setdefault(event.src_ip, event)
                if event.src_ip in onset and event.capture_available_at >= onset[event.src_ip]:
                    reached.setdefault(event.src_ip, event)
        delays = []
        for source, event in reached.items():
            delay = (event.capture_available_at - onset[source]).total_seconds()
            delays.append({"source": source, "delay_seconds": delay, "trigger_event_id": event.event_id})
        runs.append({"confidence": confidence, "min_flows": count, "window_seconds": window,
                     "candidate_events": len(candidates), "first_candidate_sources": len(first),
                     "decision_counts": action_counts,
                     "late_events_rejected": late, "first_candidate_delays": delays,
                     "sources_without_candidate": sorted(set(onset) - set(reached)),
                     "pre_onset_candidate_events": sum(e.src_ip in onset and e.capture_available_at < onset[e.src_ip] for e in candidates),
                     "benign_triggered_candidates": sum(truth[e.event_id] == "BENIGN" for e in candidates) if truth is not None else None})
    return {"scope": "exploratory policy eligibility, no firewall execution or calibrated deployment claim",
            "truth_basis": "user-supplied event labels; provenance must be verified independently" if truth is not None else "model predictions; not independent truth",
            "event_count": len(events), "time_basis": "capture_available_at in original delivery order",
            "latency_basis": "first attack-labelled flow start to first candidate; incomplete EOF flows may finalize early",
            "firewall_lifetime": "not simulated here; runtime firewall remains processing-monotonic",
            "limitations": ["No source-level false-block rate without labelled source/time exposure intervals",
                            "No independent calibration/evaluation separation established by this tool",
                            "Earliest captured labelled flow is not necessarily actual attack onset"],
            "runs": runs}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--truth", type=Path, help="JSON event ID to taxonomy label; independent provenance required")
    parser.add_argument("--confidence", type=float, nargs="+", default=[0.90, 0.99])
    parser.add_argument("--min-flows", type=int, nargs="+", default=[2, 3, 4])
    parser.add_argument("--window", type=float, nargs="+", default=[10, 60])
    parser.add_argument("--output", type=Path, default=Path("reports/response/calibration.json"))
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise FileExistsError(f"Preserve existing report: {args.output}")
        truth = json.loads(args.truth.read_text()) if args.truth else None
        result = calibrate(load_events(args.events), args.confidence, args.min_flows, args.window, truth)
        result["events_sha256"] = sha256_file(args.events)
        result["truth_sha256"] = sha256_file(args.truth) if args.truth else None
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write("\n")
        print(f"Wrote {len(result['runs'])} sensitivity conditions to {args.output}")
    except (ValueError, TypeError, KeyError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
