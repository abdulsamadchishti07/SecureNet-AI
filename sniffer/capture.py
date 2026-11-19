"""Packet sources: a pcap/pcapng file, or live Scapy capture on an interface."""

import queue

from scapy.config import conf
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader

# ponytail: Scapy defaults conf.bufsize to 64 KB, dropping ~90% of burst packets on Linux PF_PACKET.
LIVE_CAPTURE_BUFSIZE = 4 * 1024 * 1024


def start_capture(iface=None, pcap=None, bpf=None):
    """Yield packets; live capture also yields None after each idle second so flows can expire."""
    if pcap:
        with PcapReader(pcap) as reader:
            yield from reader
        return
    if conf.bufsize < LIVE_CAPTURE_BUFSIZE:
        conf.bufsize = LIVE_CAPTURE_BUFSIZE
    if iface and iface not in conf.ifaces:
        conf.ifaces.reload()
    packets = queue.Queue()
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=packets.put, store=False)
    sniffer.start()
    try:
        while True:
            try:
                yield packets.get(timeout=0.2)
            except queue.Empty:
                if not sniffer.thread.is_alive():
                    sniffer.join()  # re-raises the capture error (e.g. permission denied)
                    raise RuntimeError("Packet capture stopped")
                yield None
    finally:
        if sniffer.running:
            sniffer.stop()
