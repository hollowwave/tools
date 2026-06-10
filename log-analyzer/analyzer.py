from datetime import datetime, timedelta
from collections import defaultdict

def analyze_logs(file_path):
    # Mapping IP to a list of failure timestamps
    failures = defaultdict(list)
    
    with open(file_path, "r") as f:
        for line in f:
            if not line.strip(): continue # Skip empty lines
            
            parts = line.split()
            ts_str = f"{parts[0]} {parts[1]}"
            timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            ip = parts[-1].split("=")[1]
            
            if "LOGIN_SUCCESS" in line:
                # Reset if they succeed
                failures[ip] = []
            elif "LOGIN_FAIL" in line:
                failures[ip].append(timestamp)

    print(f"{'IP':<15} | {'Failures':<10} | {'Status'}")
    print("-" * 40)

    # Logic: 3 failures within 60 seconds
    for ip, ts_list in failures.items():
        if len(ts_list) < 3: continue
        
        # Check rolling window
        for i in range(len(ts_list) - 2):
            if ts_list[i+2] - ts_list[i] <= timedelta(seconds=60):
                print(f"{ip:<15} | {len(ts_list):<10} | ALERT: HIGH RISK")
                break

analyze_logs("logs/sample.log")
