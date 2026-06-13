"""
storage.py — Incident persistence
=====================================
One job: save and load incidents to/from disk reliably.

Robustness guarantees (P7.5):
    - Atomic writes (temp file + rename) — crash mid-write never corrupts data
    - Retry on save failure — one retry before falling back
    - Fallback file — if main file fails after retry, incidents go to
      data/incidents.backup.json so nothing is lost
    - Backup recovery on load — if main file is corrupt/missing, tries the
      backup automatically and warns the user
"""

import json
import os
import tempfile
from pathlib import Path

INCIDENTS_FILE = "data/incidents.json"
_BACKUP_SUFFIX = ".backup.json"
_MAX_RETRIES   = 2


def load(path: str = INCIDENTS_FILE) -> list:
    """
    Load all saved incidents from disk.
    Returns an empty list if the file doesn't exist.
    If the main file is corrupt, automatically tries the backup.
    """
    p = Path(path)

    # Try main file
    if p.exists():
        result = _try_load(p)
        if result is not None:
            return result
        # Main file corrupt — try backup
        print(f"[storage] Main file corrupt — trying backup...")

    # Try backup
    backup = _backup_path(p)
    if backup.exists():
        result = _try_load(backup)
        if result is not None:
            print(f"[storage] Recovered {len(result)} incident(s) from backup.")
            return result
        print(f"[storage] Backup also corrupt — starting fresh.")

    return []


def save(new_incidents: list, path: str = INCIDENTS_FILE) -> bool:
    """
    Append new incidents to the existing file (or create it).
    Uses atomic write. Retries once on failure, then falls back to
    a backup file so incidents are never silently dropped.
    Returns True on success.
    """
    if not new_incidents:
        return True

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    existing = load(path)
    combined = existing + new_incidents

    for attempt in range(1, _MAX_RETRIES + 1):
        if _atomic_write(p, combined):
            return True
        if attempt < _MAX_RETRIES:
            print(f"[storage] Write attempt {attempt} failed — retrying...")

    # All retries failed — write to backup so nothing is lost
    backup = _backup_path(p)
    print(f"[storage] Could not write to {path} — saving to {backup} instead.")
    if _atomic_write(backup, combined):
        print(f"[storage] {len(new_incidents)} incident(s) saved to backup.")
        return False   # partial success — backup worked but main didn't
    else:
        print(f"[storage] ERROR: could not write to main or backup. "
              f"{len(new_incidents)} incident(s) may be lost.")
        return False


# ── helpers ───────────────────────────────────────────────────────────────────

def _try_load(path: Path) -> list | None:
    """Try to load JSON from path. Returns list on success, None on failure."""
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        print(f"[storage] Warning: {path} contains unexpected data type — ignoring.")
        return None
    except (json.JSONDecodeError, OSError) as e:
        print(f"[storage] Warning: could not read {path} — {e}")
        return None


def _atomic_write(path: Path, data: list) -> bool:
    """Write JSON to a temp file then rename — crash-safe."""
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
            return True
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        print(f"[storage] Warning: atomic write to {path} failed — {e}")
        return False


def _backup_path(p: Path) -> Path:
    """Return the backup path for a given incidents file."""
    return p.parent / (p.stem + _BACKUP_SUFFIX)
