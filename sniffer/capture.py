"""Packet sources: a pcap/pcapng file, or live Scapy capture on an interface."""

import queue

from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader


def start_capture(iface=None, pcap=None, bpf=None):
    """Yield packets; live capture also yields None after each idle second so flows can expire."""
    if pcap:
        with PcapReader(pcap) as reader:
            yield from reader
        return
    packets = queue.Queue()
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=packets.put, store=False)
    sniffer.start()
    try:
        while True:
            try:
                yield packets.get(timeout=1)
            except queue.Empty:
                if not sniffer.thread.is_alive():
                    sniffer.join()  # re-raises the capture error (e.g. permission denied)
                    raise RuntimeError("Packet capture stopped")
                yield None
    finally:
        if sniffer.running:
            sniffer.stop()
