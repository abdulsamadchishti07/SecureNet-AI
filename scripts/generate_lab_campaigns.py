"""Generate endpoint-disjoint multi-host lab campaigns and run Sprint 6.3/6.4 evaluation.

Creates three synthetic PCAP campaigns (train, calibration, evaluation) on separate
IPv4 subnets with zero shared (src_ip, dst_ip) endpoint pairs, runs paired 20/19/18
port ablations using ml_engine.ablation/train helpers, and runs ground-truth
event-time policy calibration via sniffer.calibration.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import random
import subprocess
import sys

import numpy as np
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader, wrpcap
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from ml_engine.ablation import CONDITIONS
from ml_engine.preprocess import SELECTED_COLUMNS
from ml_engine.train import score_predictions
from sniffer.calibration import calibrate, load_events
from sniffer.main import run as run_sniffer

BASE_EPOCH = 1_760_000_000
MAC_SRC = "02:00:00:00:00:10"
MAC_DST = "02:00:00:00:00:20"

CAMPAIGN_SUBNETS = {
    "train": "10.201",
    "calibration": "10.202",
    "evaluation": "10.203",
}


def _pkt(ts_sec, src_ip, dst_ip, l4, payload=b""):
    frame = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=src_ip, dst=dst_ip) / l4 / payload
    frame.time = ts_sec
    return frame


def _tcp_flow(t0, src_ip, dst_ip, sport, dport, fwd_payload, bwd_payload, gap_us=400, rst_close=False):
    us = 1e-6
    pkts = [
        _pkt(t0, src_ip, dst_ip, TCP(sport=sport, dport=dport, flags="S")),
        _pkt(t0 + gap_us * us, dst_ip, src_ip, TCP(sport=dport, dport=sport, flags="SA")),
        _pkt(t0 + 2 * gap_us * us, src_ip, dst_ip, TCP(sport=sport, dport=dport, flags="A")),
    ]
    cur = t0 + 3 * gap_us * us
    if fwd_payload:
        pkts.append(_pkt(cur, src_ip, dst_ip, TCP(sport=sport, dport=dport, flags="PA"), fwd_payload))
        cur += gap_us * us
    if bwd_payload:
        pkts.append(_pkt(cur, dst_ip, src_ip, TCP(sport=dport, dport=sport, flags="PA"), bwd_payload))
        cur += gap_us * us
    if rst_close:
        pkts.append(_pkt(cur, src_ip, dst_ip, TCP(sport=sport, dport=dport, flags="RA")))
    else:
        pkts.extend([
            _pkt(cur, src_ip, dst_ip, TCP(sport=sport, dport=dport, flags="FA")),
            _pkt(cur + gap_us * us, dst_ip, src_ip, TCP(sport=dport, dport=sport, flags="FA")),
            _pkt(cur + 2 * gap_us * us, src_ip, dst_ip, TCP(sport=sport, dport=dport, flags="A")),
        ])
    return pkts


def build_campaign_packets(name, seed, flows_per_class=25):
    """Build packets for one campaign; returns (packets, role_by_src_ip)."""
    rng = random.Random(seed)
    prefix = CAMPAIGN_SUBNETS[name]
    offset = {"train": 0, "calibration": 2000, "evaluation": 4000}[name]
    t = float(BASE_EPOCH + offset)
    packets = []
    role_by_src = {}

    server_web = f"{prefix}.0.10"
    server_dns = f"{prefix}.0.53"
    server_auth = f"{prefix}.0.22"

    benign_clients = [f"{prefix}.1.{10 + i}" for i in range(4)]
    scan_hosts = [f"{prefix}.2.{10 + i}" for i in range(2)]
    dos_hosts = [f"{prefix}.3.{10 + i}" for i in range(2)]
    bf_hosts = [f"{prefix}.4.{10 + i}" for i in range(2)]

    for ip in benign_clients:
        role_by_src[ip] = "BENIGN"
    for ip in scan_hosts:
        role_by_src[ip] = "PORTSCAN"
    for ip in dos_hosts:
        role_by_src[ip] = "DOS"
    for ip in bf_hosts:
        role_by_src[ip] = "BRUTE_FORCE"

    for i in range(flows_per_class):
        client = benign_clients[i % len(benign_clients)]
        sport = 40000 + i
        if i % 3 == 0:
            # Normal DNS UDP query/response
            packets.append(_pkt(t, client, server_dns, UDP(sport=sport, dport=53), b"q" * rng.randint(28, 48)))
            packets.append(_pkt(t + 0.002, server_dns, client, UDP(sport=53, dport=sport), b"r" * rng.randint(64, 140)))
        else:
            # Normal HTTP GET / 200 OK
            packets.extend(_tcp_flow(
                t, client, server_web, sport, rng.choice((80, 443)),
                b"GET /index.html HTTP/1.1\r\nHost: lab\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 256\r\n\r\n" + b"a" * rng.randint(120, 320),
                gap_us=rng.randint(800, 2500),
            ))
        t += 0.15

    # PORTSCAN: rapid SYN -> RST/ACK across sequential ports
    for i in range(flows_per_class):
        attk = scan_hosts[i % len(scan_hosts)]
        sport = 50000 + i
        dport = 8000 + i
        packets.append(_pkt(t, attk, server_web, TCP(sport=sport, dport=dport, flags="S")))
        packets.append(_pkt(t + 0.00005, server_web, attk, TCP(sport=dport, dport=sport, flags="RA")))
        t += 0.02

    # DOS: high-rate small-IAT flood bursts
    for i in range(flows_per_class):
        attk = dos_hosts[i % len(dos_hosts)]
        sport = 55000 + i
        packets.extend(_tcp_flow(
            t, attk, server_web, sport, 80,
            b"GET /?flood=" + b"x" * rng.randint(250, 500),
            b"HTTP/1.1 503 Busy\r\n",
            gap_us=rng.randint(30, 90),
            rst_close=True,
        ))
        t += 0.01

    # BRUTE_FORCE: repeated FTP/SSH login attempts with auth payload
    for i in range(flows_per_class):
        attk = bf_hosts[i % len(bf_hosts)]
        sport = 60000 + i
        dport = 22 if i % 2 == 0 else 21
        packets.extend(_tcp_flow(
            t, attk, server_auth, sport, dport,
            b"USER admin\r\nPASS guess" + f"{i:03d}".encode(),
            b"530 Login incorrect\r\n",
            gap_us=rng.randint(200, 600),
        ))
        t += 0.08

    packets.sort(key=lambda p: float(p.time))
    return packets, role_by_src


def extract_campaign_dataframe(pcap_path, role_by_src):
    flows = []
    with PcapReader(str(pcap_path)) as reader:
        run_sniffer(reader, flows.append, termination_grace=0.05)
    rows = []
    pairs = set()
    for flow in flows:
        src_ip, dst_ip = flow["Src IP"], flow["Dst IP"]
        label = role_by_src.get(src_ip)
        if label is None:
            raise ValueError(f"Unmapped source IP in extracted flow: {src_ip}")
        pairs.add(tuple(sorted((src_ip, dst_ip))))
        rows.append({**{col: flow[col] for col in SELECTED_COLUMNS}, "Label": label, "Src IP": src_ip, "Dst IP": dst_ip})
    return pd.DataFrame(rows), pairs


def run_campaign_ablation(frames):
    classes = sorted(set(frames["train"]["Label"]))
    encoder = LabelEncoder().fit(classes)
    y_parts = {name: encoder.transform(df["Label"]) for name, df in frames.items()}
    results = {}

    for condition, columns in CONDITIONS.items():
        scaler = StandardScaler().fit(frames["train"][columns].to_numpy(dtype=float))
        matrices = {name: scaler.transform(df[columns].to_numpy(dtype=float)) for name, df in frames.items()}
        models = {
            "random_forest": RandomForestClassifier(
                n_estimators=100, max_depth=12, class_weight="balanced_subsample", random_state=42, n_jobs=2
            ),
            "xgboost": XGBClassifier(
                n_estimators=100, max_depth=8, learning_rate=0.1, subsample=0.8,
                colsample_bytree=0.8, random_state=42, n_jobs=2, eval_metric="mlogloss",
            ),
        }
        cond_res = {}
        for model_name, model in models.items():
            kwargs = {"sample_weight": compute_sample_weight("balanced", y_parts["train"])} if model_name == "xgboost" else {}
            model.fit(matrices["train"], y_parts["train"], **kwargs)
            cond_res[model_name] = {
                part: score_predictions(y_parts[part], model.predict(matrices[part]), classes)
                for part in ("calibration", "evaluation")
            }
        results[condition] = cond_res
    return {"classes": classes, "counts": {k: dict(Counter(df["Label"])) for k, df in frames.items()}, "conditions": results}


def replay_and_calibrate(pcap_path, role_by_src, alert_log, truth_path, output_path, confidences, min_flows, windows):
    if alert_log.exists():
        alert_log.unlink()
    cmd = [
        sys.executable, "-m", "sniffer.main",
        "-r", str(pcap_path),
        "--termination-grace", "0.05",
        "--predict", "--respond",
        "--clock-mode", "event_time",
        "--alert-log", str(alert_log),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    events = load_events(alert_log)
    truth = {ev.event_id: role_by_src[ev.src_ip] for ev in events}
    truth_path.write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    report = calibrate(events, confidences=confidences, min_flows=min_flows, windows=windows, truth=truth)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=Path("runtime/lab_campaigns"))
    parser.add_argument("--flows-per-class", type=int, default=25)
    parser.add_argument("--ablation-dir", type=Path, default=Path("reports/ablation/campaign_disjoint"))
    parser.add_argument("--calibration-out", type=Path, default=Path("reports/response/lab_calibration.json"))
    parser.add_argument("--heldout-out", type=Path, default=Path("reports/response/lab_heldout_eval.json"))
    args = parser.parse_args(argv)

    args.work_dir.mkdir(parents=True, exist_ok=True)
    frames, pair_sets, roles = {}, {}, {}
    for idx, name in enumerate(("train", "calibration", "evaluation")):
        pkts, role_map = build_campaign_packets(name, seed=100 + idx, flows_per_class=args.flows_per_class)
        pcap_path = args.work_dir / f"{name}.pcap"
        wrpcap(str(pcap_path), pkts)
        df, pairs = extract_campaign_dataframe(pcap_path, role_map)
        frames[name], pair_sets[name], roles[name] = df, pairs, role_map

    # Enforce strict zero endpoint-pair overlap across all three partitions.
    for left, right in (("train", "calibration"), ("train", "evaluation"), ("calibration", "evaluation")):
        overlap = pair_sets[left] & pair_sets[right]
        if overlap:
            raise RuntimeError(f"Endpoint pair overlap between {left} and {right}: {overlap}")

    ablation_report = run_campaign_ablation(frames)
    ablation_report["endpoint_pair_counts"] = {k: len(v) for k, v in pair_sets.items()}
    ablation_report["endpoint_pair_overlap"] = 0
    args.ablation_dir.mkdir(parents=True, exist_ok=True)
    (args.ablation_dir / "port_ablation.json").write_text(json.dumps(ablation_report, indent=2) + "\n", encoding="utf-8")

    # Chunk 6.4: Calibrate thresholds on Campaign B (calibration), freeze best, evaluate once on Campaign C.
    cal_report = replay_and_calibrate(
        args.work_dir / "calibration.pcap", roles["calibration"],
        args.work_dir / "calibration_events.jsonl", args.work_dir / "calibration_truth.json",
        args.calibration_out, confidences=(0.50, 0.70, 0.90), min_flows=(2, 3, 4), windows=(10, 60),
    )
    # Select policy minimizing benign false candidates, then minimizing missed attack sources.
    best = min(
        cal_report["runs"],
        key=lambda r: (r["benign_triggered_candidates"], len(r["sources_without_candidate"]), -r["confidence"], r["min_flows"]),
    )
    heldout_report = replay_and_calibrate(
        args.work_dir / "evaluation.pcap", roles["evaluation"],
        args.work_dir / "evaluation_events.jsonl", args.work_dir / "evaluation_truth.json",
        args.heldout_out,
        confidences=(best["confidence"],), min_flows=(best["min_flows"],), windows=(best["window_seconds"],),
    )

    lines = [
        "# Campaign-Disjoint Lab Ablation",
        "",
        f"Zero shared endpoint pairs verified across train ({len(pair_sets['train'])}), "
        f"calibration ({len(pair_sets['calibration'])}), and evaluation ({len(pair_sets['evaluation'])}).",
        "",
        "| Condition | Model | Features | Eval Macro F1 | Eval Benign FPR |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for cond, models in ablation_report["conditions"].items():
        for model_name, metrics in models.items():
            ev = metrics["evaluation"]
            lines.append(
                f"| {cond} | {model_name} | {len(CONDITIONS[cond])} | "
                f"{ev['macro_f1']:.4%} | {ev['benign_false_positive_rate']:.4%} |"
            )
    (args.ablation_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "endpoint_pair_overlap": 0,
        "selected_policy": {k: best[k] for k in ("confidence", "min_flows", "window_seconds")},
        "heldout_benign_triggered_candidates": heldout_report["runs"][0]["benign_triggered_candidates"],
        "heldout_sources_without_candidate": heldout_report["runs"][0]["sources_without_candidate"],
    }))


if __name__ == "__main__":
    main()
