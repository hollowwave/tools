import json
from pathlib import Path

INCIDENTS_FILE = "data/incidents.json"


def load(path: str = INCIDENTS_FILE) -> list:
    """
    Load all saved incidents from disk.
    Returns an empty list if the file doesn't exist.
    """
    p = Path(path)
    if not p.exists():
        return []
    try:
        with open(p) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[storage] Warning: could not read {path} — {e}")
        return []


def save(new_incidents: list, path: str = INCIDENTS_FILE):
    """
    Append new incidents to the existing file (or create it).
    Does nothing if new_incidents is empty.
    """
    if not new_incidents:
        return

    Path(path).parent.mkdir(parents=True, exist_ok=True)

    existing = load(path)
    combined = existing + new_incidents
    try:
        with open(path, "w") as f:
            json.dump(combined, f, indent=2)
    except OSError as e:
        print(f"[storage] Warning: could not save to {path} — {e}")
