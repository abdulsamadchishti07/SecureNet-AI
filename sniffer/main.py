"""Sniff packets, print each completed flow's features as a JSON line.

    sudo .venv/bin/python -m sniffer.main -i eth0 [--predict]
    .venv/bin/python -m sniffer.main -r capture.pcap [--predict]
"""

import argparse
import json
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
    args = parser.parse_args(argv)

    if args.predict:
        from ml_engine.predictor import FeatureValidationError, _load_model, predict
        _load_model(args.dataset)

    def on_flow(features):
        if args.predict:
            try:
                features = {**features, **predict(features, dataset=args.dataset)}
            except FeatureValidationError as exc:
                print(f"Dropped invalid flow: {exc}", file=sys.stderr)
                return
        print(json.dumps(features), flush=True)

    run(start_capture(args.iface, args.pcap, args.filter), on_flow, args.termination_grace)


if __name__ == "__main__":
    main()
