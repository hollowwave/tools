from datetime import datetime
from collections import defaultdict
import math

class SecurityEngine:
    def __init__(self):
        self.state = defaultdict(lambda: {"score": 0.0, "last_ts": None})
        self.events = defaultdict(list)
        # Constants for easier maintenance
        self.THRESH_HIGH = 50.0
        self.THRESH_MEDIUM = 25.0
        self.BURST_WINDOW = 30 # seconds

    def ingest(self, line):
        # 1. Parsing
        parts = line.split()
        ts = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
        ip = parts[-1].split("=")[1]
        event_type = "FAIL" if "LOGIN_FAIL" in line else "SUCCESS"

        # 2. Memory Management: Prune events older than 1 hour to prevent leaks
        self.events[ip] = [e for e in self.events[ip] if (ts - e[0]).total_seconds() <= 3600]
        self.events[ip].append((ts, event_type))
        
        # 3. Processing
        self.update_state(ip, ts, event_type)
        self.evaluate(ip, ts)

    def update_state(self, ip, ts, event_type):
        s = self.state[ip]
        if s["last_ts"]:
            hours = (ts - s["last_ts"]).total_seconds() / 3600
            s["score"] *= math.exp(-0.5 * hours)

        if event_type == "FAIL":
            s["score"] += 10
        else:
            s["score"] = max(0, s["score"] - 1)
        s["last_ts"] = ts

    def evaluate(self, ip, ts):
        s = self.state[ip]
        
        # 1. Compute Burst (The "Hard Rule")
        recent_fails = [t for t, e in self.events[ip] 
                       if (ts - t).total_seconds() <= self.BURST_WINDOW and e == "FAIL"]
        
        # 2. Decision Logic (Hierarchical)
        if len(recent_fails) >= 3:
            # Burst override: Final decision, skip score
            sev = "HIGH"
            reason = "burst_detected"
        
        elif s["score"] >= self.THRESH_HIGH:
            # Score check: High persistent risk
            sev = "HIGH"
            reason = "high_score"
            
        elif s["score"] >= self.THRESH_MEDIUM:
            # Score check: Medium persistent risk
            sev = "MEDIUM"
            reason = "medium_score"
            
        else:
            # Baseline: Normal traffic
            return 

        # 3. Final Output (Unified Report)
        self.alert(ip, ts, sev, s["score"], reason)
    def alert(self, ip, ts, sev, score, reason):
        # If it's a burst, we don't care about the score context
        if reason == "burst_detected":
            print(f"[ALERT] {sev.ljust(6)} | IP={ip} | Reason={reason.ljust(15)}")
        else:
            # For persistent threats, the score is important context
            print(f"[ALERT] {sev.ljust(6)} | IP={ip} | Reason={reason.ljust(15)} | Score={round(score, 2)}") 
# --- Execution ---
engine = SecurityEngine()
# You can now feed this engine an entire file or a stream of logs

# --- Execution: Add this to the bottom of analyzer.py ---

if __name__ == "__main__":
    engine = SecurityEngine()
    
    # Path to your log file
    log_file = "logs/sample.log"
    
    try:
        with open(log_file, "r") as f:
            for line in f:
                if line.strip(): # Skip empty lines
                    engine.ingest(line.strip())
        print("Processing complete.")
    except FileNotFoundError:
        print(f"Error: Could not find {log_file}. Make sure the file exists!")
