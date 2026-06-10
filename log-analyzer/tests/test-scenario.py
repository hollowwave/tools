import sys
import os

# This block allows the script to 'see' the analyzer.py in the parent folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import SecurityEngine
from datetime import datetime, timedelta

def run_simulation(name, events):
    print(f"\n--- Running Scenario: {name} ---")
    engine = SecurityEngine()
    start_time = datetime(2026, 6, 10, 8, 0, 0)
    
    for delay, log_line in events:
        start_time += timedelta(seconds=delay)
        full_log = f"{start_time.strftime('%Y-%m-%d %H:%M:%S')} {log_line}"
        engine.ingest(full_log)

# --- Define Scenarios ---

# Scenario 1: Slow Brute Force (Accumulates risk over time)
scenario_slow = [
    (60, "LOGIN_FAIL user=attacker ip=1.1.1.1"),
    (60, "LOGIN_FAIL user=attacker ip=1.1.1.1"),
    (60, "LOGIN_FAIL user=attacker ip=1.1.1.1")
]

# Scenario 2: Burst Attack (Immediate HIGH)
scenario_burst = [
    (1, "LOGIN_FAIL user=attacker ip=2.2.2.2"),
    (1, "LOGIN_FAIL user=attacker ip=2.2.2.2"),
    (1, "LOGIN_FAIL user=attacker ip=2.2.2.2")
]

# Scenario 3: Normal User with mistakes
scenario_normal = [
    (5, "LOGIN_FAIL user=bob ip=3.3.3.3"),
    (5, "LOGIN_SUCCESS user=bob ip=3.3.3.3"),
    (300, "LOGIN_SUCCESS user=bob ip=3.3.3.3")
]

# Scenario 4: Mixed Attacker (Testing if success resets/erases risk)
scenario_mixed = [
    (1, "LOGIN_FAIL user=attacker ip=4.4.4.4"),
    (1, "LOGIN_FAIL user=attacker ip=4.4.4.4"),
    (5, "LOGIN_SUCCESS user=attacker ip=4.4.4.4"),
    (1, "LOGIN_FAIL user=attacker ip=4.4.4.4"),
    (1, "LOGIN_FAIL user=attacker ip=4.4.4.4"),
    (1, "LOGIN_FAIL user=attacker ip=4.4.4.4")
]

# Scenario 6: Long silence (Testing if decay prevents 'suspicion traps')
scenario_silence = [
    (1, "LOGIN_FAIL user=old ip=5.5.5.5"),
    (1, "LOGIN_FAIL user=old ip=5.5.5.5"),
    (3600, "LOGIN_FAIL user=old ip=5.5.5.5") # 1 hour gap
]

if __name__ == "__main__":
    run_simulation("Slow Brute Force", scenario_slow)
    run_simulation("Burst Attack", scenario_burst)
    run_simulation("Normal User", scenario_normal)
    run_simulation("Mixed Attacker", scenario_mixed)
    run_simulation("Long Silence", scenario_silence)
