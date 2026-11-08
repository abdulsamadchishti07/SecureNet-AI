"""Write three synthetic TCP probes to a PCAP; no packets are sent."""

import argparse
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, nargs="?", default=Path("runtime/response_demo.pcap"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; choose another path")
    packets = []
    for index in range(3):
        client, server, port = "10.10.0.9", "10.10.0.2", 40000 + index
        probe = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                 / IP(src=client, dst=server) / TCP(sport=port, dport=80, flags="S"))
        reply = (Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                 / IP(src=server, dst=client) / TCP(sport=80, dport=port, flags="RA"))
        probe.time = 1700000000 + index
        reply.time = probe.time + 44e-6
        packets.extend((probe, reply))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.output), packets)
    print(f"Wrote six synthetic packets to {args.output}; no network traffic sent")


if __name__ == "__main__":
    main()
