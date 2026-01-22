# analyzers/flows.py
# Flow builders for PacketBloom
# - build_flows: from Scapy packets (offline PCAP)
# - build_flows_from_records: from backend live-capture records (pybind11)

from collections import defaultdict
from scapy.all import TCP, UDP, IP, ICMP

def build_flows(packets, ip_filter=None, port_filter=None, proto_filter=None):
    """
    Build flows from Scapy packets (offline PCAP analysis).
    """
    flows = defaultdict(lambda: {
        "src_ip": "", "dst_ip": "", "protocol": "",
        "count": 0, "bytes": 0, "start_ts": None, "end_ts": None,
        "tcp_syn": 0, "tcp_ack": 0, "udp_dns_resp_big": 0, "icmp_echo": 0
    })

    for p in packets:
        if not p.haslayer(IP):
            continue
        ip = p[IP]
        proto = "OTHER"
        sport = dport = None

        if p.haslayer(TCP):
            proto = "TCP"
            sport = p[TCP].sport
            dport = p[TCP].dport
        elif p.haslayer(UDP):
            proto = "UDP"
            sport = p[UDP].sport
            dport = p[UDP].dport
        elif p.haslayer(ICMP):
            proto = "ICMP"

        # Filters
        if ip_filter and ip.src != ip_filter and ip.dst != ip_filter:
            continue
        if port_filter and sport != port_filter and dport != port_filter:
            continue
        if proto_filter and proto != proto_filter:
            continue

        key = (ip.src, ip.dst, proto)
        f = flows[key]
        f["src_ip"], f["dst_ip"], f["protocol"] = ip.src, ip.dst, proto
        f["count"] += 1
        f["bytes"] += len(p)
        ts = getattr(p, "time", None)
        if ts:
            if f["start_ts"] is None or ts < f["start_ts"]:
                f["start_ts"] = ts
            if f["end_ts"] is None or ts > f["end_ts"]:
                f["end_ts"] = ts

        # Anomaly counters
        if proto == "TCP":
            flags = p[TCP].flags
            if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                f["tcp_syn"] += 1
            if flags & 0x10:  # ACK
                f["tcp_ack"] += 1

        if proto == "UDP":
            payload_len = len(bytes(p[UDP].payload)) if p.haslayer(UDP) else 0
            if (sport == 53 or dport == 53) and payload_len > 512:
                f["udp_dns_resp_big"] += 1

        if proto == "ICMP":
            try:
                if p[ICMP].type == 8:  # Echo request
                    f["icmp_echo"] += 1
            except Exception:
                pass

    return flows


def build_flows_from_records(records, ip_filter=None, port_filter=None, proto_filter=None):
    """
    Build flows from backend live-capture records (pybind11).
    Each record should provide:
      - src_ip, dst_ip, proto ("TCP"/"UDP"/"ICMP"/"OTHER")
      - sport, dport (int)
      - length (int)
      - ts (float epoch seconds)
    """
    flows = defaultdict(lambda: {
        "src_ip": "", "dst_ip": "", "protocol": "",
        "count": 0, "bytes": 0, "start_ts": None, "end_ts": None,
        "tcp_syn": 0, "tcp_ack": 0, "udp_dns_resp_big": 0, "icmp_echo": 0
    })

    for r in records:
        # Support both dicts and backend.Rec objects
        proto = r.get("proto") if isinstance(r, dict) else getattr(r, "proto", "OTHER")
        src = r.get("src_ip") if isinstance(r, dict) else getattr(r, "src_ip", "")
        dst = r.get("dst_ip") if isinstance(r, dict) else getattr(r, "dst_ip", "")
        sport = r.get("sport") if isinstance(r, dict) else getattr(r, "sport", 0)
        dport = r.get("dport") if isinstance(r, dict) else getattr(r, "dport", 0)
        length = r.get("length") if isinstance(r, dict) else getattr(r, "length", 0)
        ts = r.get("ts") if isinstance(r, dict) else getattr(r, "ts", None)

        # Filters
        if ip_filter and src != ip_filter and dst != ip_filter:
            continue
        if port_filter and sport != port_filter and dport != port_filter:
            continue
        if proto_filter and proto != proto_filter:
            continue

        key = (src, dst, proto)
        f = flows[key]
        f["src_ip"], f["dst_ip"], f["protocol"] = src, dst, proto
        f["count"] += 1
        f["bytes"] += int(length)

        if ts is not None:
            if f["start_ts"] is None or ts < f["start_ts"]:
                f["start_ts"] = ts
            if f["end_ts"] is None or ts > f["end_ts"]:
                f["end_ts"] = ts

        # Heuristics (records don't include TCP flags):
        if proto == "UDP":
            if sport == 53 or dport == 53:
                if length > 512:
                    f["udp_dns_resp_big"] += 1
        elif proto == "ICMP":
            # Treat ICMP as echo for flood heuristic (simple live-capture signal)
            f["icmp_echo"] += 1

    return flows
