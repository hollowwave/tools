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
        self.MAX_EVENTS_PER_IP           = data.get("max_events_per_ip", 10_000)
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
    Validates all values — wrong types or nonsensical ranges fall back to
    the default for that key with a clear warning.
    """
    data = dict(DEFAULTS)  # start from defaults

    p = Path(path)
    if p.exists():
        try:
            with open(p) as f:
                overrides = json.load(f)
            if not isinstance(overrides, dict):
                print(f"[config] Warning: {path} must be a JSON object — using defaults.")
            else:
                data.update(overrides)
        except json.JSONDecodeError as e:
            print(f"[config] Warning: {path} is not valid JSON — using defaults. ({e})")
        except OSError as e:
            print(f"[config] Warning: could not read {path} — using defaults. ({e})")
    else:
        print(f"[config] {path} not found — using defaults.")

    data = _validate(data)
    return Config(data)


# ── validation ────────────────────────────────────────────────────────────────

# (key, type, min_value, max_value)  — None means no bound
_NUMERIC_RULES: list = [
    ("burst_window",               (int, float), 1,    86400),
    ("burst_min_fail",             int,          1,    10000),
    ("threshold_medium",           (int, float), 1,    None),
    ("threshold_high",             (int, float), 1,    None),
    ("event_ttl_hours",            (int, float), 0.01, 168),
    ("alert_cooldown",             (int, float), 0,    86400),
    ("spray_window",               (int, float), 1,    86400),
    ("spray_min_users",            int,          2,    10000),
    ("distributed_window",         (int, float), 1,    86400),
    ("distributed_min_ips",        int,          2,    10000),
    ("corr_window",                (int, float), 1,    86400),
    ("corr_medium_threshold",      int,          2,    1000),
    ("fp_success_window",          (int, float), 0,    86400),
    ("fp_success_score_reduction", (int, float), 0,    None),
    ("monitor_poll_interval",      (int, float), 0.1,  60),
    ("monitor_state_save_interval",(int, float), 1,    3600),
    ("monitor_heartbeat_interval", (int, float), 10,   None),
    ("max_events_per_ip",          int,          100,  1_000_000),
]


def _validate(data: dict) -> dict:
    """
    Validate numeric config values. For each invalid value:
      - print a clear warning showing the bad value and what was expected
      - substitute the default so the tool always starts cleanly
    Also enforces threshold_high > threshold_medium.
    """
    errors = 0

    for key, expected_type, lo, hi in _NUMERIC_RULES:
        if key not in data:
            continue  # missing keys get defaults elsewhere
        val     = data[key]
        default = DEFAULTS.get(key)

        # Type check
        if not isinstance(val, expected_type):
            _warn(key, val, f"must be {_type_name(expected_type)}", default)
            data[key] = default
            errors += 1
            continue

        # Range checks
        if lo is not None and val < lo:
            _warn(key, val, f"must be >= {lo}", default)
            data[key] = default
            errors += 1
            continue
        if hi is not None and val > hi:
            _warn(key, val, f"must be <= {hi}", default)
            data[key] = default
            errors += 1
            continue

    # Cross-key: high threshold must be > medium threshold
    med = data.get("threshold_medium", DEFAULTS["threshold_medium"])
    hi  = data.get("threshold_high",   DEFAULTS["threshold_high"])
    if hi <= med:
        print(
            f"[config] Warning: threshold_high ({hi}) must be greater than "
            f"threshold_medium ({med}) — restoring defaults for both."
        )
        data["threshold_medium"] = DEFAULTS["threshold_medium"]
        data["threshold_high"]   = DEFAULTS["threshold_high"]
        errors += 1

    # String key: incidents_file
    if not isinstance(data.get("incidents_file", ""), str):
        _warn("incidents_file", data["incidents_file"], "must be a string",
              DEFAULTS["incidents_file"])
        data["incidents_file"] = DEFAULTS["incidents_file"]
        errors += 1

    if errors:
        print(f"[config] {errors} invalid value(s) replaced with defaults.")

    return data


def _warn(key: str, val, expectation: str, default) -> None:
    print(f"[config] Warning: '{key}' = {val!r} — {expectation}. "
          f"Using default: {default!r}")


def _type_name(t) -> str:
    if isinstance(t, tuple):
        return " or ".join(x.__name__ for x in t)
    return t.__name__
