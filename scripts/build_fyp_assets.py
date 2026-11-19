"""Build standalone SVG/PDF defense figures from saved evidence, without fitting models."""

import argparse
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "docs/assets/fyp")
    args = parser.parse_args(argv)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    metric_path = ROOT / "reports/unified/evaluation.json"
    live_path = ROOT / "reports/sprint7/multi_attack_lab.json"
    metrics, live = json.loads(metric_path.read_text()), json.loads(live_path.read_text())
    if live["status"] == "error" or len(live["scenarios"]) != 3:
        parser.error("A completed three-vector lab report is required")
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "svg.fonttype": "none"})
    outputs = []

    def save(figure, name):
        for extension in ("svg", "pdf", "png"):
            path = args.output_dir / f"{name}.{extension}"
            figure.savefig(path, bbox_inches="tight", facecolor="white")
            outputs.append(path)
        plt.close(figure)

    classes = list(metrics["test_class_counts"])
    fig, ax = plt.subplots(figsize=(12, 5))
    for offset, key, label, color in ((-0.25, "precision", "Precision", "#059669"),
                                      (0, "recall", "Recall", "#2563eb"),
                                      (0.25, "f1-score", "F1", "#7c3aed")):
        ax.bar([i + offset for i in range(len(classes))],
               [metrics["classification_report"][name][key] * 100 for name in classes],
               width=0.24, color=color, label=label)
    ax.set_xticks(range(len(classes)), [f"{name}\nn={metrics['test_class_counts'][name]:,}" for name in classes], fontsize=9)
    ax.set_ylim(0, 105)
    ax.set_ylabel("Percent (full 0–100 scale)")
    ax.set_title("Saved CIC-IDS2017 within-capture evaluation • seven classes", loc="left", weight="bold")
    ax.legend(loc="lower right", ncols=3)
    ax.spines[["top", "right"]].set_visible(False)
    fig.text(0.125, -0.04, "Shared endpoint pairs across partitions; WEB_ATTACK n=19 from one pair. These scores do not establish live recall.", fontsize=9)
    save(fig, "class_metrics")

    fig, ax = plt.subplots(figsize=(11, 4))
    limit = max(s["observation_seconds"] for s in live["scenarios"])
    for i, scenario in enumerate(live["scenarios"]):
        latency = scenario["mitigation_latency_seconds"]
        if latency is not None:
            ax.barh(i, latency, color="#059669", height=0.42)
            src = f" ({scenario['detection_source']})" if scenario.get("detection_source") else ""
            ax.text(latency + 0.1, i, f"{latency:.2f}s • {scenario['enforced_label']}{src}", va="center")
        else:
            ax.plot(scenario["observation_seconds"], i, "x", color="#b91c1c", markersize=10, markeredgewidth=2)
            ax.text(0.2, i, f"No confirmed block in {scenario['observation_seconds']:g}s; predictions: {scenario['predicted_labels']}", va="center", color="#991b1b")
    ax.set_yticks(range(3), [s["vector"] for s in live["scenarios"]])
    ax.invert_yaxis()
    ax.set_xlim(0, limit + 1)
    ax.set_xlabel("Seconds from traffic onset; × marks the observation deadline, not a latency")
    ax.set_title("Live isolated socket lab • measured mitigation and detection gaps", loc="left", weight="bold")
    ax.spines[["top", "right"]].set_visible(False)
    fig.text(0.125, -0.05, "One bounded run; TCP timeout confirmation gives an upper bound. Policy 0.5 / 2 flows / 10s; grace 0.1s. No SLA.", fontsize=9)
    save(fig, "live_mitigation")

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 6)
    ax.axis("off")
    boxes = {
        "capture": (0.1, 3.8, "IPv4 capture\n20 flow features"),
        "model": (3.1, 3.8, "SHA-256 check\nUnified RF inference"),
        "policy": (6.1, 3.8, "Repeated-flow policy\nProtected CIDRs"),
        "helper": (9.1, 3.8, "Unix-socket helper\nnftables + lease"),
        "api": (6.1, 1.1, "Durable API outbox\nPostgreSQL + React"),
        "notify": (9.1, 1.1, "Best-effort queue\nSMTP / webhook"),
    }
    for name, (x, y, label) in boxes.items():
        ax.add_patch(FancyBboxPatch((x, y), 2.65, 1.1, boxstyle="round,pad=0.03",
                     edgecolor="#047857" if name == "helper" else "#94a3b8", facecolor="#ecfdf5" if name == "helper" else "#f1f5f9"))
        ax.text(x + 1.325, y + 0.55, label, ha="center", va="center", fontsize=11)
    for start, end in (((2.8, 4.35), (3.05, 4.35)), ((5.8, 4.35), (6.05, 4.35)),
                       ((8.8, 4.35), (9.05, 4.35)), ((7.4, 3.75), (7.4, 2.3)),
                       ((10.4, 3.75), (10.4, 2.3))):
        ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=15, color="#334155"))
    ax.text(7.5, 3.0, "audit / events", fontsize=9)
    ax.text(10.5, 3.0, "confirmed block", fontsize=9)
    ax.set_title("SecureNet AI • runtime boundaries", loc="left", weight="bold")
    ax.text(0.1, 0.4, "Default: dry_run. Enforcement needs explicit --enforce. Only the helper changes rules.\nNotifications default off; separate thread, 600s/IP cooldown, at most 30 logical alert attempts/hour.", fontsize=11)
    save(fig, "architecture")

    manifest = {"sources": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in (metric_path, live_path, Path(__file__).resolve())},
                "assets": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in outputs},
                "scope": "Figures from saved reports; no model training or metric recomputation"}
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"assets": len(outputs), "output_dir": str(args.output_dir)}))


if __name__ == "__main__":
    main()
