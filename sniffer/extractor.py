"""Group IPv4 packets into bidirectional flows and compute the 20 Friday model features.

Implements a CICFlowMeter-style interpretation of the local CSV fields. The exact
generating exporter and source-capture parity remain unverified. Current rules:
- timestamps and Flow Duration in microseconds; flows split 120 s after their first packet;
- packet lengths are transport payload bytes (Ethernet padding excluded), ICMP/other = 0;
- direction = first packet's sender, except a leading SYN-ACK; timeout splits keep direction;
- TCP is ready to end after RST, or FIN both ways then ACK; only a new SYN then starts a new flow;
- flag counts are packets carrying the flag, both directions.
"""

from collections import namedtuple

from scapy.layers.inet import ICMP, IP, TCP, UDP

FLOW_TIMEOUT = 120_000_000  # µs; dataset max Flow Duration is 119,999,993
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
FIN1, FIN2, READY = "first_fin", "second_fin", "ready_for_termination"

Packet = namedtuple("Packet", "ts src sport dst dport proto length flags icmp")


def parse(pkt):
    """Scapy packet -> Packet, or None for non-IPv4 or fragmented traffic."""
    ip = pkt.getlayer(IP)
    if ip is None or ip.frag or ip.flags.MF:
        return None
    l4, header = ip.payload, (ip.ihl or 5) * 4
    sport = dport = flags = 0
    length, icmp = 0, None
    if isinstance(l4, ICMP):
        proto, icmp = 1, (l4.type, l4.code)
    elif isinstance(l4, TCP):
        proto, sport, dport, flags = 6, l4.sport, l4.dport, int(l4.flags)
        length = max((ip.len or len(ip)) - header - (l4.dataofs or 5) * 4, 0)
    elif isinstance(l4, UDP):
        proto, sport, dport = 17, l4.sport, l4.dport
        length = max((ip.len or len(ip)) - header - 8, 0)
    else:
        proto = 0  # CICFlowMeter's value for unsupported protocols
    return Packet(round(pkt.time * 1_000_000), ip.src, sport, ip.dst, dport, proto, length, flags, icmp)


class Flow:
    def __init__(self, src, sport, dst, dport, p):
        self.src, self.sport, self.dst, self.dport, self.proto = src, sport, dst, dport, p.proto
        self.start = self.last = p.ts
        self.icmp = p.icmp
        self.fwd = self.bwd = self.fwd_fin = self.bwd_fin = self.bytes = 0
        self.min_len = self.max_len = p.length
        self.counts = dict.fromkeys((FIN, SYN, RST, PSH, ACK), 0)
        self.state = None
        self.emitted = False
        self.add(p)

    def add(self, p):
        forward = (p.src, p.sport) == (self.src, self.sport)
        self.fwd += forward
        self.bwd += not forward
        self.bytes += p.length
        self.min_len, self.max_len = min(self.min_len, p.length), max(self.max_len, p.length)
        for flag in self.counts:
            self.counts[flag] += bool(p.flags & flag)
        if p.flags & FIN:
            self.fwd_fin += forward
            self.bwd_fin += not forward
        self.last = max(self.last, p.ts)

    def features(self):
        """Model input plus IP metadata, or None for flows the dataset never contains."""
        packets, duration = self.fwd + self.bwd, self.last - self.start
        # ponytail: 1-packet / zero-duration flows dropped like the dataset (rates are infinite),
        # so unanswered probes are invisible to the model; a rule layer must cover them if needed.
        if packets < 2 or duration <= 0:
            return None
        seconds = duration / 1_000_000
        return {
            "Src IP": self.src, "Dst IP": self.dst,
            "Src Port": self.sport, "Dst Port": self.dport, "Protocol": self.proto,
            "Flow Duration": duration,
            "Total Fwd Packet": self.fwd, "Total Bwd packets": self.bwd,
            "Flow Bytes/s": self.bytes / seconds, "Flow Packets/s": packets / seconds,
            "Flow IAT Mean": duration / (packets - 1),
            "Fwd Packets/s": self.fwd / seconds, "Bwd Packets/s": self.bwd / seconds,
            "Packet Length Min": self.min_len, "Packet Length Max": self.max_len,
            "Packet Length Mean": self.bytes / packets,
            "FIN Flag Count": self.counts[FIN], "SYN Flag Count": self.counts[SYN],
            "RST Flag Count": self.counts[RST], "PSH Flag Count": self.counts[PSH],
            "ACK Flag Count": self.counts[ACK],
            "Average Packet Size": self.bytes / packets,
        }


def _new_flow(p):
    if p.flags & SYN and p.flags & ACK:  # SYN-ACK seen first: the responder is the destination
        return Flow(p.dst, p.dport, p.src, p.sport, p)
    return Flow(p.src, p.sport, p.dst, p.dport, p)


class FlowTable:
    def __init__(self, termination_grace=5.0):
        # ponytail: CICFlowMeter only closes a torn-down TCP flow on the next SYN or the 120 s
        # timeout. Emitting after this idle grace gives timely alerts; late packets are not reported.
        self.grace = int(termination_grace * 1_000_000)
        self.flows = {}

    def _emit(self, flow):
        if flow.emitted:
            return []
        flow.emitted = True
        features = flow.features()
        return [features] if features else []

    def add(self, p):
        """Account one Packet; return feature dicts of flows it completed."""
        key = (p.proto, *sorted(((p.src, p.sport), (p.dst, p.dport))))
        flow = self.flows.get(key)
        if flow is None:
            self.flows[key] = _new_flow(p)
            return []
        syn_after_teardown = flow.state == READY and p.flags & SYN
        if p.ts - flow.start > FLOW_TIMEOUT or syn_after_teardown:
            done = self._emit(flow)
            new_dialogue = (syn_after_teardown or p.proto not in (6, 17)
                            or (p.proto == 17 and p.ts - flow.last > FLOW_TIMEOUT))
            self.flows[key] = (_new_flow(p) if new_dialogue
                               else Flow(flow.src, flow.sport, flow.dst, flow.dport, p))
            return done
        # Reference splits ICMP only when BOTH code and type change.
        if p.proto == 1 and flow.icmp[0] != p.icmp[0] and flow.icmp[1] != p.icmp[1]:
            done = self._emit(flow)
            self.flows[key] = Flow(p.src, p.sport, p.dst, p.dport, p)
            return done
        flow.add(p)
        if p.flags & FIN:
            if flow.state is None:
                flow.state = FIN1
            elif flow.state == FIN1 and flow.fwd_fin and flow.bwd_fin:
                flow.state = FIN2
        elif p.flags & RST:
            flow.state = READY
        elif p.flags & ACK and flow.state == FIN2:
            flow.state = READY
        return []

    def expire(self, now):
        """Emit flows that can no longer change (or finished TCP flows idle past the grace)."""
        done = []
        for key, flow in list(self.flows.items()):
            if now - flow.start > FLOW_TIMEOUT or (flow.state == READY and now - flow.last > self.grace):
                done += self._emit(flow)
            if now - flow.last > FLOW_TIMEOUT:
                # ponytail: a TCP connection silent >120 s loses its direction; reference keeps it.
                del self.flows[key]
        return done

    def flush(self):
        """Emit everything still open (end of capture)."""
        done = [f for flow in self.flows.values() for f in self._emit(flow)]
        self.flows.clear()
        return done
