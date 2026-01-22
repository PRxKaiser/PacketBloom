# packetbloom/analyzers/rules.py
# Anomaly detection rules

def detect_anomalies(flow):
    notes = []
    duration = None
    if flow["start_ts"] and flow["end_ts"]:
        duration = max(0.001, flow["end_ts"] - flow["start_ts"])

    # SYN flood
    if flow["protocol"] == "TCP":
        syn = flow["tcp_syn"]
        ack = flow["tcp_ack"]
        if syn >= 50 and ack < syn * 0.2 and (duration and duration <= 10):
            notes.append("SYN flood suspected")

    # DNS amplification
    if flow["protocol"] == "UDP":
        if flow["udp_dns_resp_big"] >= 20:
            notes.append("DNS amplification suspected")

    # ICMP flood
    if flow["protocol"] == "ICMP":
        if flow["icmp_echo"] >= 100 and (duration and duration <= 10):
            notes.append("ICMP flood suspected")

    return notes
