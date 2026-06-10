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
