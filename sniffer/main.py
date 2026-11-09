"""Sniff packets, print each completed flow's features as a JSON line.

    sudo .venv/bin/python -m sniffer.main -i eth0 [--predict]
    .venv/bin/python -m sniffer.main -r capture.pcap [--predict]
"""

import argparse
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import time

from sniffer.capture import start_capture
from sniffer.extractor import FlowTable, parse
from ml_engine.datasets import DATASETS, DEFAULT_INFERENCE_DATASET


def run(packets, on_flow, termination_grace=5.0):
    """Feed packets (None = idle tick) through a FlowTable, calling on_flow per completed flow."""
    table, last_sweep = FlowTable(termination_grace), 0
    try:
        for pkt in packets:
            if pkt is None:  # live capture idle: use the wall clock
                now, done = round(time.time() * 1_000_000), []
            else:
                p = parse(pkt)
                if p is None:
                    continue
                now, done = p.ts, table.add(p)
            if now - last_sweep >= 1_000_000:
                done += table.expire(now)
                last_sweep = now
            for features in done:
                on_flow(features)
    except KeyboardInterrupt:
        pass
    for features in table.flush():
        on_flow(features)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-i", "--iface", help="live capture interface (needs root/CAP_NET_RAW)")
    source.add_argument("-r", "--pcap", help="read a pcap/pcapng file instead")
    parser.add_argument("-f", "--filter", help="BPF capture filter, e.g. 'not port 22'")
    parser.add_argument("--predict", action="store_true",
                        help="classify each flow with the unified model (detection only, no blocking)")
    parser.add_argument("--dataset", choices=tuple(DATASETS), default=DEFAULT_INFERENCE_DATASET,
                        help="explicit model override for baseline comparisons")
    parser.add_argument("--termination-grace", type=float, default=5.0,
                        help="seconds a torn-down TCP flow stays idle before it is emitted (default 5)")
    response = parser.add_argument_group("local response simulation")
    response.add_argument("--respond", action="store_true",
                          help="queue detections and log dry-run firewall decisions; requires --predict")
    response.add_argument("--alert-log", type=Path, default=Path("runtime/alerts.jsonl"))
    response.add_argument("--queue-size", type=int, default=1024)
    response.add_argument("--response-confidence", type=float, default=0.90)
    response.add_argument("--response-min-flows", type=int, default=3)
    response.add_argument("--response-window", type=float, default=60)
    response.add_argument("--block-seconds", type=float, default=900)
    response.add_argument("--api-url", type=str, default=None,
                          help="optional backend API URL to ingest alerts (e.g. http://localhost:8000)")
    response.add_argument("--protect", action="append", default=[], metavar="IPv4/CIDR",
                          help="protect an admin/gateway/DNS address or CIDR; repeat as needed")
    args = parser.parse_args(argv)
    if args.respond and not args.predict:
        parser.error("--respond requires --predict")

    dispatcher = None
    if args.respond:
        from backend.firewall import FirewallController
        from backend.worker import ResponseDispatcher
        from sniffer.events import DetectionEvent, EventValidationError
        from sniffer.rules import ResponsePolicy
        try:
            policy = ResponsePolicy(args.response_confidence, args.response_min_flows, args.response_window)
            firewall = FirewallController(protected=args.protect, duration_seconds=args.block_seconds)
            dispatcher = ResponseDispatcher(args.alert_log, capacity=args.queue_size,
                                            policy=policy, firewall=firewall, api_url=args.api_url)
        except ValueError as exc:
            parser.error(str(exc))

    if args.predict:
        from ml_engine.predictor import FeatureValidationError, _load_model, predict
        bundle = _load_model(args.dataset)
        if dispatcher is not None:
            model_sha256 = bundle["_artifact_sha256"]

    def on_flow(features):
        if args.predict:
            try:
                prediction = predict(features, dataset=args.dataset)
            except FeatureValidationError as exc:
                print(f"Dropped invalid flow: {exc}", file=sys.stderr)
                return
            if dispatcher is not None:
                try:
                    event = DetectionEvent.from_flow(features, prediction, model_scope=args.dataset,
                        model_sha256=model_sha256, source="pcap" if args.pcap else "live")
                except EventValidationError as exc:
                    print(f"Dropped invalid response event: {exc}", file=sys.stderr)
                else:
                    if not dispatcher.publish(event):
                        print("Response queue full: dropped incoming event", file=sys.stderr)
            features = {**features, **prediction}
        print(json.dumps(features), flush=True)

    response_context = dispatcher if dispatcher is not None else nullcontext()
    with response_context:
        run(start_capture(args.iface, args.pcap, args.filter), on_flow, args.termination_grace)
    if dispatcher is not None:
        print("Response summary: " + json.dumps(dispatcher.stats()), file=sys.stderr)


if __name__ == "__main__":
    main()
