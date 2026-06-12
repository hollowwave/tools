"""
config.py — Configuration loader
===================================
One job: load config.json and expose its values as a Config object.

If config.json is missing, safe defaults are used so the tool
always runs without requiring the file to exist first.

Users tune behaviour by editing config.json — no code changes needed.
"""

import json
from pathlib import Path

CONFIG_FILE = "config.json"

DEFAULTS = {
    "burst_window":     30,
    "burst_min_fail":   3,
    "threshold_medium": 25.0,
    "threshold_high":   50.0,
    "event_ttl_hours":  1,
    "alert_cooldown":   60,
    "incidents_file":   "data/incidents.json",
    "monitor_poll_interval":       1,
    "monitor_state_save_interval": 30,
    "monitor_heartbeat_interval":  300,
}


class Config:
    def __init__(self, data: dict):
        self.BURST_WINDOW     = data["burst_window"]
        self.BURST_MIN_FAIL   = data["burst_min_fail"]
        self.THRESH_MEDIUM    = data["threshold_medium"]
        self.THRESH_HIGH      = data["threshold_high"]
        self.EVENT_TTL_HOURS  = data["event_ttl_hours"]
        self.ALERT_COOLDOWN   = data["alert_cooldown"]
        self.INCIDENTS_FILE   = data["incidents_file"]
        self.SPRAY_WINDOW     = data.get("spray_window", 60)
        self.SPRAY_MIN_USERS  = data.get("spray_min_users", 3)
        self.DIST_WINDOW      = data.get("distributed_window", 60)
        self.DIST_MIN_IPS     = data.get("distributed_min_ips", 3)
        self.CORR_WINDOW              = data.get("corr_window", 300)
        self.CORR_MEDIUM_THRESHOLD    = data.get("corr_medium_threshold", 3)
        self.FP_SUCCESS_WINDOW        = data.get("fp_success_window", 60)
        self.FP_SUCCESS_SCORE_REDUCTION = data.get("fp_success_score_reduction", 5)
        self.MONITOR_POLL_INTERVAL       = data.get("monitor_poll_interval", 1)
        self.MONITOR_STATE_SAVE_INTERVAL = data.get("monitor_state_save_interval", 30)
        self.MONITOR_HEARTBEAT_INTERVAL  = data.get("monitor_heartbeat_interval", 300)
        self.ALERTS                      = data.get("alerts", {})

    def show(self):
        """Print current config values — useful for debugging."""
        print("  Active configuration:")
        print(f"    burst_window     = {self.BURST_WINDOW}s")
        print(f"    burst_min_fail   = {self.BURST_MIN_FAIL} failures")
        print(f"    threshold_medium = {self.THRESH_MEDIUM}")
        print(f"    threshold_high   = {self.THRESH_HIGH}")
        print(f"    event_ttl_hours  = {self.EVENT_TTL_HOURS}h")
        print(f"    alert_cooldown   = {self.ALERT_COOLDOWN}s")
        print(f"    incidents_file   = {self.INCIDENTS_FILE}")
        print(f"    spray_window     = {self.SPRAY_WINDOW}s")
        print(f"    spray_min_users  = {self.SPRAY_MIN_USERS} unique users")
        print(f"    dist_window      = {self.DIST_WINDOW}s")
        print(f"    dist_min_ips     = {self.DIST_MIN_IPS} unique IPs")
        print(f"    corr_window      = {self.CORR_WINDOW}s")
        print(f"    corr_medium_threshold = {self.CORR_MEDIUM_THRESHOLD} MEDIUMs")
        print(f"    fp_success_window     = {self.FP_SUCCESS_WINDOW}s")
        print(f"    fp_score_reduction    = {self.FP_SUCCESS_SCORE_REDUCTION}")


def load(path: str = CONFIG_FILE) -> Config:
    """
    Load config from JSON file.
    Falls back to DEFAULTS for any missing key, so partial configs are fine.
    """
    data = dict(DEFAULTS)  # start from defaults

    p = Path(path)
    if p.exists():
        try:
            with open(p) as f:
                overrides = json.load(f)
            data.update(overrides)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[config] Warning: could not read {path} — using defaults. ({e})")
    else:
        print(f"[config] {path} not found — using defaults.")

    return Config(data)
