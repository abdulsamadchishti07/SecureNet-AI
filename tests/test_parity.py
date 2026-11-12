"""Independent arithmetic on synthetic packets; original-capture parity is unproven."""
import csv
import json

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from ml_engine.preprocess import SELECTED_COLUMNS
from scripts.evaluate_pcap_parity import align_flows, compare_flows, evaluate, flow_key, main, normalize_row
from sniffer.main import run


def reference(start=1_700_000_000_000_000, sport=40000):
    # Two payload-free SYN/RST packets 100 us apart, calculated without Flow.features.
    return {'Src IP': '10.0.0.1', 'Dst IP': '10.0.0.2', 'Src Port': sport, 'Dst Port': 80,
            'Protocol': 6, 'Flow Duration': 100, 'Total Fwd Packet': 1, 'Total Bwd packets': 1,
            'Flow Bytes/s': 0, 'Flow Packets/s': 20000, 'Flow IAT Mean': 100,
            'Fwd Packets/s': 10000, 'Bwd Packets/s': 10000,
            'Packet Length Min': 0, 'Packet Length Max': 0, 'Packet Length Mean': 0,
            'FIN Flag Count': 0, 'SYN Flag Count': 1, 'RST Flag Count': 1,
            'PSH Flag Count': 0, 'ACK Flag Count': 1, 'Average Packet Size': 0,
            'flow_start_usec': start, 'flow_end_usec': start + 100}


def test_multiflow_pcap_against_independent_reference_and_cli(tmp_path):
    packets, expected = [], []
    for index in range(2):
        row = reference(start=1_700_000_000_000_000 + index * 10_000_000, sport=40000 + index)
        expected.append(row)
        for offset, src, dst, sport, dport, flags in [
            (0, row['Src IP'], row['Dst IP'], row['Src Port'], 80, 'S'),
            (100, row['Dst IP'], row['Src IP'], 80, row['Src Port'], 'RA')]:
            packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
            packet.time = (row['flow_start_usec'] + offset) / 1e6
            packets.append(packet)
    capture, csv_path, report = tmp_path / 'input.pcap', tmp_path / 'reference.csv', tmp_path / 'report.json'
    wrpcap(str(capture), packets)
    with csv_path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(expected[0]))
        writer.writeheader()
        writer.writerows(reversed(expected))
    main(['--pcap', str(capture), '--reference', str(csv_path), '--report', str(report)])
    result = json.loads(report.read_text())
    assert result['status'] == 'agreement'
    assert result['alignment']['matched'] == [[0, 1], [1, 0]]
    assert all(value['mismatches'] == 0 for value in result['per_feature'].values())
    with pytest.raises(SystemExit):
        main(['--pcap', str(capture), '--report', str(report)])
    smoke = tmp_path / 'smoke.json'
    main(['--pcap', str(capture), '--report', str(smoke)])
    assert json.loads(smoke.read_text())['status'] == 'extraction_only'


def test_alignment_repeated_tuple_ambiguity_protocol_and_paired_ports():
    first, second = reference(), reference(start=1_700_000_010_000_000)
    assert align_flows([first, second], [second, first])['matched'] == [(0, 1), (1, 0)]
    ambiguous = align_flows([first, first], [first])
    assert ambiguous['matched'] == []
    assert ambiguous['ambiguous_extracted'] == [0, 1]
    assert ambiguous['ambiguous_reference'] == [0]
    assert align_flows([first], [{**first, 'Protocol': 17}])['unmatched_reference'] == [0]
    collision = {**first, 'Src Port': 80, 'Dst Port': 40000}
    assert flow_key(collision) != flow_key(first)


def test_direction_mismatch_is_flagged_and_not_silently_repaired():
    row = reference()
    reverse = {**row, 'Src IP': row['Dst IP'], 'Dst IP': row['Src IP'],
               'Src Port': row['Dst Port'], 'Dst Port': row['Src Port']}
    report = evaluate([row], [reverse])
    assert report['status'] == 'discrepancies'
    assert report['comparisons'][0]['orientation_mismatch']


def test_tolerances_zero_counts_and_window_bounds():
    row = reference()
    assert not compare_flows(row, row)
    assert 'SYN Flag Count' in compare_flows({**row, 'SYN Flag Count': 2}, row)
    assert 'Flow Bytes/s' in compare_flows({**row, 'Flow Bytes/s': 1}, row)
    assert not compare_flows({**row, 'Flow Packets/s': 20001}, row)
    for offset, expected in [(1000, [(0, 0)]), (1001, [])]:
        shifted = {**row, 'flow_start_usec': row['flow_start_usec'] + offset,
                   'flow_end_usec': row['flow_end_usec'] + offset}
        assert align_flows([row], [shifted])['matched'] == expected
    assert evaluate([], [])['status'] == 'discrepancies'


@pytest.mark.parametrize('field,value', [('Src Port', 1.5), ('Protocol', 256), ('Flow Bytes/s', float('nan')),
    ('flow_start_usec', -1), ('flow_end_usec', 2), ('Total Fwd Packet', float('inf'))])
def test_invalid_reference_fails(field, value):
    with pytest.raises(ValueError):
        normalize_row({**reference(), field: value})


def test_explicit_timestamp_format_and_timezone():
    row = reference()
    row.pop('flow_start_usec')
    row.pop('flow_end_usec')
    row['Timestamp'] = '2023-11-14T22:13:20+0000'
    normalized = normalize_row(row, 'Timestamp', '%Y-%m-%dT%H:%M:%S%z')
    assert normalized['flow_start_usec'] == reference()['flow_start_usec']
    row['Timestamp'] = '2023-11-14T22:13:20'
    with pytest.raises(ValueError, match='timezone'):
        normalize_row(row, 'Timestamp', '%Y-%m-%dT%H:%M:%S')
    assert normalize_row(row, 'Timestamp', '%Y-%m-%dT%H:%M:%S', 'UTC') == normalized


def test_zero_duration_and_single_packet_capture_exclusions():
    packets = []
    for flags in ['S', 'RA']:
        packet = Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=1234, dport=80, flags=flags)
        packet.time = 1_700_000_000
        packets.append(packet)
    flows = []
    run(packets, flows.append)
    assert flows == []
    run(packets[:1], flows.append)
    assert flows == []


def test_decimal_ipv4_reference_and_incomplete_local_timestamp():
    row = reference()
    row['Src IP dec'], row['Dst IP dec'] = 167772161, 167772162
    del row['Src IP'], row['Dst IP']
    assert normalize_row(row) == normalize_row(reference())
    del row['flow_start_usec'], row['flow_end_usec']
    row['Timestamp'] = '59:50.3'
    with pytest.raises(ValueError, match='Full capture date'):
        normalize_row(row, 'Timestamp', '%M:%S.%f', 'UTC')


def test_extraction_diagnostics_record_excluded_flows_and_packets():
    from scapy.layers.inet6 import IPv6
    packets = []
    for offset, sport in [(0, 1234), (1, 1235)]:
        packet = Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=sport, dport=80, flags='S')
        packet.time = 1_700_000_000 + offset
        packets.append(packet)
    excluded = Ether() / IPv6() / UDP(sport=1, dport=2)
    excluded.time = 1_700_000_010
    packets.append(excluded)
    diagnostic, flows = {}, []
    run(packets, flows.append, diagnostics=diagnostic)
    assert not flows
    assert diagnostic['packets_read'] == 3
    assert diagnostic['non_ipv4_or_fragmented_packets_excluded'] == 1
    assert diagnostic['single_packet_flows_excluded'] == 2
