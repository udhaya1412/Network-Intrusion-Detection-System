# demo_run.py
from scapy.all import IP, TCP, Ether
from detector import inspect_packet, alerts
from app import app

print("Network IDS demo (simulated packets, no real capture)\n")

print("TC-01: Normal packet")
print("  Reasons:", inspect_packet(IP(src="192.0.2.20", dst="192.0.2.1") / TCP(dport=8080)))

print("\nTC-02: Packet to monitored port 22")
print("  Reasons:", inspect_packet(IP(src="192.0.2.10", dst="192.0.2.1") / TCP(dport=22)))

print("\nTC-03: 35 packets from one source in the window")
for _ in range(35):
    last = inspect_packet(IP(src="192.0.2.30", dst="192.0.2.1") / TCP(dport=8080))
print("  Last packet reasons:", last)

print("\nTC-04: Packet without IP layer")
pkt = Ether()
if pkt.haslayer("IP"):
    inspect_packet(pkt)
else:
    print("  Ignored (no IP layer)")

print(f"\nTotal alerts stored: {len(alerts)}")
print("TC-05: Open http://127.0.0.1:5000 in your browser\n")
app.run(host="127.0.0.1", port=5000, debug=False)