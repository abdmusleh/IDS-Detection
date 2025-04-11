import time
from scapy.all import rdpcap
from multiprocessing import Process, Manager

# === CONFIG ===
main_pcap = "/root/captured_packets.pcap"
ruleset_pcap = "/root/ruleset.pcap"
THREAD_COUNT = 4  # You can change this to 2, 4, 8, etc.

# === Load Packets
print("[*] Loading main traffic...")
main_packets = rdpcap(main_pcap)
main_summaries = [pkt.summary() for pkt in main_packets]
print(f"[*] Loaded {len(main_packets)} main packets.")

print("[*] Loading rule set...")
rule_packets = rdpcap(ruleset_pcap)
rule_summaries = [pkt.summary() for pkt in rule_packets]
print(f"[*] Loaded {len(rule_summaries)} rule packets.\n")

# === Multiprocessing worker function
def match_worker(rules, main_data, result_dict, process_id):
    match_count = 0
    for rule in rules:
        if rule in main_data:
            match_count += 1
    result_dict[process_id] = match_count

# === Parallel Detection Start
start_time = time.time()

# Manager for shared dictionary to store results
with Manager() as manager:
    result_dict = manager.dict()

    chunk_size = len(rule_summaries) // THREAD_COUNT
    processes = []

    for i in range(THREAD_COUNT):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i != THREAD_COUNT - 1 else len(rule_summaries)
        
        # Start the process
        p = Process(target=match_worker, args=(rule_summaries[start:end], main_summaries, result_dict, i))
        processes.append(p)
        p.start()

    # Wait for all processes to finish
    for p in processes:
        p.join()

    total_matched = sum(result_dict.values())
    end_time = time.time()

# === Report
print("========= PARALLEL DETECTION =========")
print(f"Processes Used: {THREAD_COUNT}")
print(f"Rules Checked: {len(rule_summaries)}")
print(f"Matches Found: {total_matched}")
print(f"Time Taken: {end_time - start_time:.4f} seconds")
print("======================================")
