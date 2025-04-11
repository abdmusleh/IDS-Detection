import tkinter as tk
from tkinter import filedialog, messagebox
import time
import random
from scapy.all import rdpcap
from threading import Thread
from multiprocessing import Process, Manager

class DetectionComparisonApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Detection Method Comparison")
        self.root.geometry("700x600")
        
        # Labels and Buttons
        self.method_label = tk.Label(root, text="Select Detection Method", font=("Helvetica", 14))
        self.method_label.pack(pady=10)
        
        # File Selection Button for Main .pcap file
        self.file_label = tk.Label(root, text="Select Main .pcap File", font=("Helvetica", 12))
        self.file_label.pack(pady=5)

        self.select_file_button = tk.Button(root, text="Browse", command=self.select_file, font=("Helvetica", 12))
        self.select_file_button.pack(pady=5)

        self.selected_file = None  # To store the selected file path

        # Dropdown for selecting the number of rule sets
        self.ruleset_label = tk.Label(root, text="Select Number of Rule Sets", font=("Helvetica", 12))
        self.ruleset_label.pack(pady=5)
        
        self.rule_count = tk.StringVar(value="200")  # Default to 200 rules
        self.ruleset_menu = tk.OptionMenu(root, self.rule_count, "100", "200", "500", "1000")
        self.ruleset_menu.pack(pady=5)
        
        # Method selection buttons
        self.quick_search_button = tk.Button(root, text="Quick Search", command=self.quick_search, font=("Helvetica", 12))
        self.quick_search_button.pack(pady=5)

        self.threaded_search_button = tk.Button(root, text="Threaded Search", command=self.threaded_search, font=("Helvetica", 12))
        self.threaded_search_button.pack(pady=5)

        self.parallel_search_button = tk.Button(root, text="Parallel Search", command=self.parallel_search, font=("Helvetica", 12))
        self.parallel_search_button.pack(pady=5)
        
        # Display Results
        self.results_label = tk.Label(root, text="Results will appear here", font=("Helvetica", 12))
        self.results_label.pack(pady=10)
        
        self.time_label = tk.Label(root, text="Execution Time: N/A", font=("Helvetica", 12))
        self.time_label.pack(pady=10)
        
        self.matches_label = tk.Label(root, text="Matches Found: N/A", font=("Helvetica", 12))
        self.matches_label.pack(pady=10)

    def select_file(self):
        # Open file dialog for user to choose the .pcap file
        self.selected_file = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
        if self.selected_file:
            messagebox.showinfo("File Selected", f"Selected File: {self.selected_file}")
        else:
            messagebox.showwarning("No File Selected", "Please select a valid .pcap file.")

    def quick_search(self):
        self.run_detection("Quick Search")

    def threaded_search(self):
        self.run_detection("Threaded Search")

    def parallel_search(self):
        self.run_detection("Parallel Search")

    def run_detection(self, method):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a main .pcap file first!")
            return
        
        # Get the selected rule set count
        num_rules = int(self.rule_count.get())
        
        # Start Timer
        start_time = time.time()
        
        # Run the selected detection method
        if method == "Quick Search":
            matches = self.quick_search_detection(num_rules)
        elif method == "Threaded Search":
            matches = self.threaded_search_detection(num_rules)
        elif method == "Parallel Search":
            matches = self.parallel_search_detection(num_rules)

        # Calculate elapsed time
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        # Update the results labels with method, time, and matches
        self.results_label.config(text=f"Method: {method}")
        self.time_label.config(text=f"Execution Time: {elapsed_time:.4f} seconds")
        self.matches_label.config(text=f"Matches Found: {matches}")
        
        # Display a message box for completion
        messagebox.showinfo("Detection Complete", f"{method} completed!\nMatches: {matches}\nTime: {elapsed_time:.4f} seconds")

    # Quick Search Detection Logic
    def quick_search_detection(self, num_rules):
        # Load the main traffic and rule set
        main_packets = rdpcap(self.selected_file)
        main_summaries = [pkt.summary() for pkt in main_packets]

        # Simulate matching (replace this with actual matching code)
        matches = random.randint(0, num_rules)
        return matches

    # Threaded Search Detection Logic
    def threaded_search_detection(self, num_rules):
        # Load the main traffic and rule set
        main_packets = rdpcap(self.selected_file)
        main_summaries = [pkt.summary() for pkt in main_packets]
        
        # Prepare ruleset
        rule_packets = rdpcap("/root/ruleset.pcap")
        rule_summaries = [pkt.summary() for pkt in rule_packets]
        
        # Create a list to hold thread results
        result_list = [0] * 4  # Assuming 4 threads

        def match_worker(rules, main_data, result_list, thread_id):
            match_count = 0
            for rule in rules:
                if rule in main_data:
                    match_count += 1
            result_list[thread_id] = match_count
        
        threads = []
        chunk_size = len(rule_summaries) // 4
        for i in range(4):
            start = i * chunk_size
            end = (i + 1) * chunk_size if i != 3 else len(rule_summaries)
            thread = Thread(target=match_worker, args=(rule_summaries[start:end], main_summaries, result_list, i))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Total matches
        total_matches = sum(result_list)
        return total_matches

    # Parallel Search Detection Logic (Multiprocessing)
    def parallel_search_detection(self, num_rules):
        # Load the main traffic and rule set
        main_packets = rdpcap(self.selected_file)
        main_summaries = [pkt.summary() for pkt in main_packets]
        
        # Prepare ruleset
        rule_packets = rdpcap("/root/ruleset.pcap")
        rule_summaries = [pkt.summary() for pkt in rule_packets]
        
        # Manager for shared result dict
        with Manager() as manager:
            result_dict = manager.dict()

            def match_worker(rules, main_data, result_dict, process_id):
                match_count = 0
                for rule in rules:
                    if rule in main_data:
                        match_count += 1
                result_dict[process_id] = match_count

            processes = []
            chunk_size = len(rule_summaries) // 4
            for i in range(4):
                start = i * chunk_size
                end = (i + 1) * chunk_size if i != 3 else len(rule_summaries)
                process = Process(target=match_worker, args=(rule_summaries[start:end], main_summaries, result_dict, i))
                processes.append(process)
                process.start()

            for process in processes:
                process.join()

            # Total matches
            total_matches = sum(result_dict.values())
            return total_matches

# Create main window
root = tk.Tk()
app = DetectionComparisonApp(root)

# Run the application
root.mainloop()
