import time
from scapy.all import rdpcap

# === CONFIG ===
main_pcap = "/root/captured_packets.pcap"
ruleset_pcap = "/root/ruleset.pcap"

# === Load packets
print("[*] Loading main traffic...")
main_packets = rdpcap(main_pcap)
print(f"[*] Loaded {len(main_packets)} packets from main traffic.")

print("[*] Loading rule set...")
rule_packets = rdpcap(ruleset_pcap)
print(f"[*] Loaded {len(rule_packets)} packets in rule set.")

# === Convert packets to raw strings for matching
main_summaries = [pkt.summary() for pkt in main_packets]
rule_summaries = [pkt.summary() for pkt in rule_packets]

# === Quick Search Detection
print("\n[+] Starting Quick Search detection...")
start_time = time.time()

matched = 0
for rule in rule_summaries:
    if rule in main_summaries:
        matched += 1

end_time = time.time()
duration = end_time - start_time

# === Results
print("\n========== DETECTION SUMMARY ==========")
print(f"Total Rules: {len(rule_summaries)}")
print(f"Matched Rules: {matched}")
print(f"Detection Time: {duration:.4f} seconds")
print("=======================================\n")
