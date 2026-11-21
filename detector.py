# detector.py
from collections import defaultdict, deque
from datetime import datetime, timezone
import time

# Educational thresholds; tune only in an authorized lab.
WINDOW_SECONDS = 10
PACKET_THRESHOLD = 30
MONITORED_PORTS = {21, 22, 23, 445, 3389}

recent_by_source = defaultdict(deque)
alerts = []


def protocol_name(packet):
    if packet.haslayer("TCP"):
        return "TCP"
    if packet.haslayer("UDP"):
        return "UDP"
    if packet.haslayer("ICMP"):
        return "ICMP"
    return "OTHER"


def inspect_packet(packet):
    now = time.time()
    src = packet["IP"].src if packet.haslayer("IP") else "unknown"
    dst = packet["IP"].dst if packet.haslayer("IP") else "unknown"
    proto = protocol_name(packet)

    dport = None
    if packet.haslayer("TCP"):
        dport = int(packet["TCP"].dport)
    elif packet.haslayer("UDP"):
        dport = int(packet["UDP"].dport)

    history = recent_by_source[src]
    history.append(now)
    while history and now - history[0] > WINDOW_SECONDS:
        history.popleft()

    reasons = []
    if len(history) >= PACKET_THRESHOLD:
        reasons.append("High packet rate from one source")
    if dport in MONITORED_PORTS:
        reasons.append(f"Traffic to monitored port {dport}")

    for reason in reasons:
        event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "source": src,
            "destination": dst,
            "protocol": proto,
            "destination_port": dport,
            "reason": reason,
        }
        alerts.append(event)
        print("[ALERT]", event)

    return reasons