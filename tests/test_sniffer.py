"""Synthetic packet regressions; these do not establish capture-to-CSV parity."""

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from ml_engine.preprocess import SELECTED_COLUMNS
from sniffer.extractor import FlowTable, parse
from sniffer.main import run

A, B = "10.0.0.1", "10.0.0.2"
T0 = 1_700_000_000


@pytest.fixture
def packet_factory():
    def packet(us, src, dst, l4, payload=b"", pad=0):
        """Frame at T0 + us microseconds with optional Ethernet padding."""
        raw = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                    / IP(src=src, dst=dst) / l4 / payload)
        frame = Ether(raw + b"\0" * pad)
        frame.time = T0 + us / 1_000_000
        return frame
    return packet


@pytest.fixture
def tcp_packet(packet_factory):
    def tcp(us, forward, flags, payload=b"", pad=0):
        src, dst, sport, dport = (A, B, 40000, 80) if forward else (B, A, 80, 40000)
        return packet_factory(us, src, dst, TCP(sport=sport, dport=dport, flags=flags), payload, pad)
    return tcp


def collect_flows(packets):
    completed = []
    run(iter(packets), completed.append)
    return completed


def test_port_scan_probe_feature_shape(tcp_packet):
    (flow,) = collect_flows([tcp_packet(0, True, "S", pad=6), tcp_packet(44, False, "RA", pad=6)])
    assert set(flow) == set(SELECTED_COLUMNS) | {"Src IP", "Dst IP"}
    expected = {
        "Src Port": 40000, "Dst Port": 80, "Protocol": 6, "Flow Duration": 44,
        "Total Fwd Packet": 1, "Total Bwd packets": 1, "Packet Length Max": 0,
        "SYN Flag Count": 1, "RST Flag Count": 1, "ACK Flag Count": 1, "FIN Flag Count": 0,
    }
    assert {key: flow[key] for key in expected} == expected
    assert flow["Flow Packets/s"] == pytest.approx(2 / 44e-6)


def test_teardown_then_syn_reuse_splits_and_keeps_client_direction(tcp_packet):
    first, second = collect_flows([
        tcp_packet(0, False, "SA"),  # Capture starts mid-handshake.
        tcp_packet(10, True, "A"),
        tcp_packet(20, True, "PA", b"x" * 100),
        tcp_packet(30, False, "A", b"y" * 300),
        tcp_packet(40, True, "FA"), tcp_packet(50, False, "FA"),
        tcp_packet(60, True, "A"),
        tcp_packet(1000, True, "S"), tcp_packet(1010, False, "SA"),
    ])
    assert (first["Src IP"], first["Src Port"], first["Dst Port"], first["Total Fwd Packet"],
            first["Total Bwd packets"], first["Flow Duration"]) == (A, 40000, 80, 4, 3, 60)
    assert (first["Packet Length Min"], first["Packet Length Max"], first["FIN Flag Count"],
            first["SYN Flag Count"], first["PSH Flag Count"], first["ACK Flag Count"]) == (0, 300, 2, 1, 1, 7)
    assert first["Average Packet Size"] == pytest.approx(400 / 7)
    assert first["Flow IAT Mean"] == pytest.approx(10)
    assert (second["Src Port"], second["Total Fwd Packet"], second["Total Bwd packets"],
            second["Flow Duration"]) == (40000, 1, 1, 10)


def test_udp_timeout_keeps_direction_and_single_packets_are_dropped(packet_factory):
    def udp(us, forward, src=A, dst=B):
        sport, dport = (5353, 53) if forward else (53, 5353)
        return packet_factory(us, src if forward else dst, dst if forward else src,
                              UDP(sport=sport, dport=dport), b"q" * 20)

    first, second = collect_flows([
        udp(0, True), udp(1_000_000, False), udp(121_000_000, False),
        udp(122_000_000, True), udp(5, True, "10.0.0.9", "10.0.0.8"),
    ])
    assert (first["Src Port"], first["Total Fwd Packet"], first["Total Bwd packets"],
            first["Packet Length Max"]) == (5353, 1, 1, 20)
    assert (second["Src Port"], second["Total Fwd Packet"], second["Total Bwd packets"]) == (5353, 1, 1)


def test_torn_down_flow_waits_for_grace(tcp_packet):
    table = FlowTable(termination_grace=5)
    for frame in (tcp_packet(0, True, "S"), tcp_packet(44, False, "RA")):
        table.add(parse(frame))
    last = parse(tcp_packet(44, False, "RA")).ts
    assert table.expire(last + 4_000_000) == []
    assert len(table.expire(last + 6_000_000)) == 1
    assert table.flush() == []  # Already emitted once.
