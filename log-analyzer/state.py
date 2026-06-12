"""
state.py — Persistent engine state
=====================================
One job: save and restore the SecurityEngine's in-memory detection state
so that risk scores, cooldowns, and correlation history survive restarts.

What is saved:
    scores        — IP → {score, last_ts}  (decay-corrected on load)
    events        — IP → [(ts, event_type, user)]  (pruned to TTL on load)
    last_alert    — IP → {reason: last_alert_ts}   (cooldown state)
    medium_ts     — IP → [ts, ...]                 (correlation history)
    target_events — user → [(ts, ip)]              (distributed attack tracking)

State file: data/engine_state.json (separate from incidents.json)

Decay correction on load:
    A score of 40 saved 2 hours ago should restore as ~15, not 40.
    The decay formula (same as engine._update_score) is applied at load time
    so the engine picks up exactly where physics left it.
"""

import json
import math
import os
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

STATE_FILE = "data/engine_state.json"
_DT_FMT    = "%Y-%m-%d %H:%M:%S"


# ── serialisation helpers ─────────────────────────────────────────────────────

def _dt_to_str(dt: datetime) -> str:
    return dt.strftime(_DT_FMT)

def _str_to_dt(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, _DT_FMT)
    except (ValueError, TypeError):
        return None


# ── save ──────────────────────────────────────────────────────────────────────

def save(engine, path: str = STATE_FILE) -> bool:
    """
    Serialise the engine's live detection state to disk.
    Uses an atomic write (temp file + rename) so a crash mid-write
    never leaves a corrupt state file.
    Returns True on success, False on failure.
    """
    data = {
        "saved_at": _dt_to_str(datetime.now()),
        "scores": {},
        "events": {},
        "last_alert": {},
        "medium_ts": {},
        "target_events": {},
    }

    # scores: ip → {score, last_ts}
    for ip, s in engine._state.items():
        data["scores"][ip] = {
            "score":   s["score"],
            "last_ts": _dt_to_str(s["last_ts"]) if s["last_ts"] else None,
        }

    # events: ip → [(ts_str, event_type, user)]
    for ip, evlist in engine._events.items():
        data["events"][ip] = [
            (_dt_to_str(t), e, u) for t, e, u in evlist
        ]

    # last_alert: ip → {reason: ts_str}
    for ip, reasons in engine._last_alert.items():
        data["last_alert"][ip] = {
            r: _dt_to_str(ts) for r, ts in reasons.items()
        }

    # medium_ts: ip → [ts_str, ...]
    for ip, tslist in engine._medium_ts.items():
        data["medium_ts"][ip] = [_dt_to_str(t) for t in tslist]

    # target_events: user → [(ts_str, ip)]
    for user, evlist in engine._target_events.items():
        data["target_events"][user] = [
            (_dt_to_str(t), ip) for t, ip in evlist
        ]

    return _atomic_write(path, data)


def _atomic_write(path: str, data: dict) -> bool:
    """Write JSON to a temp file then rename — crash-safe."""
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, p)          # atomic on POSIX; near-atomic on Windows
            return True
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        print(f"[state] Warning: could not save state to {path} — {e}")
        return False


# ── load ──────────────────────────────────────────────────────────────────────

def load(engine, cfg, path: str = STATE_FILE) -> bool:
    """
    Restore a previously saved state into a freshly created engine.
    Applies:
      - TTL pruning  : drops events older than EVENT_TTL_HOURS
      - Decay correction : adjusts scores for time elapsed since save
      - Window pruning   : drops stale cooldowns, medium_ts, target_events

    Returns True if state was loaded, False if file missing or unreadable.
    """
    p = Path(path)
    if not p.exists():
        return False

    try:
        with open(p) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[state] Warning: could not read {path} — {e}. Starting fresh.")
        return False

    now = datetime.now()

    # ── scores (with decay correction) ───────────────────────────────────────
    for ip, s in data.get("scores", {}).items():
        raw_score = s.get("score", 0.0)
        last_ts   = _str_to_dt(s.get("last_ts"))

        if last_ts is not None and raw_score > 0:
            hours_elapsed = (now - last_ts).total_seconds() / 3600
            # Same decay formula as engine._update_score
            corrected = raw_score * math.exp(-0.5 * hours_elapsed)
        else:
            corrected = raw_score

        engine._state[ip] = {
            "score":   corrected,
            "last_ts": last_ts,
        }

    # ── events (prune to TTL) ─────────────────────────────────────────────────
    ttl_seconds = cfg.EVENT_TTL_HOURS * 3600
    for ip, evlist in data.get("events", {}).items():
        restored = []
        for entry in evlist:
            ts = _str_to_dt(entry[0])
            if ts and (now - ts).total_seconds() <= ttl_seconds:
                restored.append((ts, entry[1], entry[2]))
        if restored:
            engine._events[ip] = restored

    # ── last_alert (cooldown state) ───────────────────────────────────────────
    cooldown = cfg.ALERT_COOLDOWN
    for ip, reasons in data.get("last_alert", {}).items():
        restored = {}
        for reason, ts_str in reasons.items():
            ts = _str_to_dt(ts_str)
            # Only restore if still within cooldown window
            if ts and (now - ts).total_seconds() <= cooldown:
                restored[reason] = ts
        if restored:
            engine._last_alert[ip] = restored

    # ── medium_ts (correlation history) ──────────────────────────────────────
    corr_window = cfg.CORR_WINDOW
    for ip, tslist in data.get("medium_ts", {}).items():
        restored = []
        for ts_str in tslist:
            ts = _str_to_dt(ts_str)
            if ts and (now - ts).total_seconds() <= corr_window:
                restored.append(ts)
        if restored:
            engine._medium_ts[ip] = restored

    # ── target_events (distributed attack tracking) ───────────────────────────
    dist_window = cfg.DIST_WINDOW
    for user, evlist in data.get("target_events", {}).items():
        restored = []
        for entry in evlist:
            ts = _str_to_dt(entry[0])
            if ts and (now - ts).total_seconds() <= dist_window:
                restored.append((ts, entry[1]))
        if restored:
            engine._target_events[user] = restored

    saved_at = data.get("saved_at", "unknown")
    _summarise_load(engine, saved_at)
    return True


def _summarise_load(engine, saved_at: str):
    """Print a brief summary of what was restored."""
    n_ips    = len(engine._state)
    n_events = sum(len(v) for v in engine._events.values())
    n_cd     = sum(len(v) for v in engine._last_alert.values())
    n_med    = sum(len(v) for v in engine._medium_ts.values())
    n_tgt    = sum(len(v) for v in engine._target_events.values())

    print(f"  [state] Restored from {saved_at}")
    print(f"  [state] {n_ips} IP(s) tracked | "
          f"{n_events} event(s) | "
          f"{n_cd} cooldown(s) | "
          f"{n_med} correlation point(s) | "
          f"{n_tgt} target event(s)")
