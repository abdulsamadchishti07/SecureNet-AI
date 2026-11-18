"""Endpoint-disjoint multi-host campaign generation and ablation smoke tests."""

from scapy.utils import wrpcap

from scripts.generate_lab_campaigns import (
    build_campaign_packets,
    extract_campaign_dataframe,
    run_campaign_ablation,
)


def test_lab_campaigns_are_endpoint_disjoint_and_ablatable(tmp_path):
    frames, pair_sets = {}, {}
    for idx, name in enumerate(("train", "calibration", "evaluation")):
        pkts, roles = build_campaign_packets(name, seed=200 + idx, flows_per_class=6)
        pcap_path = tmp_path / f"{name}.pcap"
        wrpcap(str(pcap_path), pkts)
        df, pairs = extract_campaign_dataframe(pcap_path, roles)
        assert not df.empty
        assert set(df["Label"]) == {"BENIGN", "PORTSCAN", "DOS", "BRUTE_FORCE"}
        frames[name], pair_sets[name] = df, pairs

    assert pair_sets["train"].isdisjoint(pair_sets["calibration"])
    assert pair_sets["train"].isdisjoint(pair_sets["evaluation"])
    assert pair_sets["calibration"].isdisjoint(pair_sets["evaluation"])

    report = run_campaign_ablation(frames)
    assert set(report["conditions"]) == {"full", "no_source_port", "no_ports"}
    for cond in report["conditions"].values():
        assert set(cond) == {"random_forest", "xgboost"}
        for model_res in cond.values():
            assert model_res["evaluation"]["macro_f1"] >= 0.0
