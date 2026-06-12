"""
monitor.py — Live log monitoring
===================================
One job: watch a log file continuously and feed new lines to the engine
in real time, the way a real security system would operate.

Usage (via main.py):
    python main.py monitor <logfile>
    python main.py monitor <logfile> --from-start

Behaviour:
    - Opens the file and (by default) seeks to the end — only new lines
      written after the monitor starts are processed.
    - --from-start replays the whole file first, then tails it.
    - Polls for new data every monitor_poll_interval seconds (default: 1).
    - Saves detection state every monitor_state_save_interval seconds (default: 30).
    - Prints a heartbeat every monitor_heartbeat_interval seconds (default: 300)
      so you know the process is still alive.
    - Handles log rotation: if the file shrinks or its inode changes, the
      monitor reopens it from the start of the new file.
    - Waits gracefully if the file does not exist yet — useful when the
      monitored service hasn't started writing yet.
    - On Ctrl-C: saves state and exits cleanly.

Config keys (all optional, with defaults):
    monitor_poll_interval       — seconds between reads (default: 1)
    monitor_state_save_interval — seconds between state saves (default: 30)
    monitor_heartbeat_interval  — seconds between heartbeat messages (default: 300)
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path

import storage
import state as state_mod


# ── public entry point ────────────────────────────────────────────────────────

def run(log_file: str, cfg, from_start: bool = False):
    """
    Start the monitor loop. Blocks until Ctrl-C.

    log_file   — path to the file to watch
    cfg        — Config object from config.py
    from_start — if True, process existing content before tailing
    """
    poll      = getattr(cfg, "MONITOR_POLL_INTERVAL",       1)
    save_every = getattr(cfg, "MONITOR_STATE_SAVE_INTERVAL", 30)
    heartbeat  = getattr(cfg, "MONITOR_HEARTBEAT_INTERVAL",  300)

    from engine import SecurityEngine
    engine = SecurityEngine(cfg)
    engine.load_state(cfg)

    print(f"  [monitor] Watching {log_file}")
    print(f"  [monitor] Poll interval     : {poll}s")
    print(f"  [monitor] State save every  : {save_every}s")
    print(f"  [monitor] Heartbeat every   : {heartbeat}s")
    print(f"  [monitor] Press Ctrl-C to stop.\n")

    counters = {
        "lines":      0,
        "incidents":  0,
        "last_save":  time.monotonic(),
        "last_beat":  time.monotonic(),
        "start_time": time.monotonic(),
    }

    try:
        _watch_loop(log_file, engine, cfg, from_start,
                    poll, save_every, heartbeat, counters)
    except KeyboardInterrupt:
        pass
    finally:
        _shutdown(engine, cfg, counters)


# ── watch loop ────────────────────────────────────────────────────────────────

def _watch_loop(log_file, engine, cfg, from_start,
                poll, save_every, heartbeat, counters):
    """Main tail-follow loop. Handles file appearance and rotation."""

    f        = None
    last_ino = None
    last_size = None

    while True:
        path = Path(log_file)

        # ── wait for file to appear ───────────────────────────────────────────
        if not path.exists():
            if f is not None:
                # File disappeared — close and wait for it to come back
                f.close()
                f = None
                last_ino  = None
                last_size = None
                print(f"  [monitor] {log_file} disappeared — waiting for it to return...")
            time.sleep(poll)
            continue

        # ── detect rotation (inode change or size shrink) ─────────────────────
        try:
            stat    = path.stat()
            cur_ino  = stat.st_ino
            cur_size = stat.st_size
        except OSError:
            time.sleep(poll)
            continue

        rotated = (
            f is not None and (
                cur_ino != last_ino or        # inode changed (mv + new file)
                cur_size < last_size          # file was truncated
            )
        )

        if rotated:
            print(f"  [monitor] Log rotation detected — reopening {log_file}")
            f.close()
            f = None

        # ── open file ─────────────────────────────────────────────────────────
        if f is None:
            try:
                f = open(log_file, "r")
            except OSError as e:
                print(f"  [monitor] Could not open {log_file} — {e}")
                time.sleep(poll)
                continue

            last_ino  = cur_ino
            last_size = cur_size

            if from_start or rotated:
                # Replay from beginning
                if not rotated:
                    print(f"  [monitor] Replaying existing content first...")
            else:
                # Seek to end — only watch new lines
                f.seek(0, 2)

        # ── read new lines ────────────────────────────────────────────────────
        buf = ""
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            buf += chunk

        if buf:
            lines = buf.split("\n")
            # The last element may be an incomplete line — put it back
            # by rewinding the file position if needed.
            # Simple approach: only process lines that end with \n.
            # If buf ended mid-line, we'll pick it up next poll.
            if not buf.endswith("\n"):
                # Rewind to just before the incomplete line
                incomplete = lines[-1]
                f.seek(-len(incomplete.encode()), 1)
                lines = lines[:-1]

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                counters["lines"] += 1
                engine.ingest(line, silent=False)

            # Update size tracker
            last_size = f.tell()

            # Count new incidents
            counters["incidents"] = len(engine.incidents)

        now = time.monotonic()

        # ── periodic state save ───────────────────────────────────────────────
        if now - counters["last_save"] >= save_every:
            storage.save(engine.incidents, cfg.INCIDENTS_FILE)
            engine.save_state()
            counters["last_save"] = now

        # ── heartbeat ─────────────────────────────────────────────────────────
        if now - counters["last_beat"] >= heartbeat:
            elapsed = int(now - counters["start_time"])
            print(
                f"  [monitor] ♥  alive | "
                f"uptime={_fmt_duration(elapsed)} | "
                f"lines={counters['lines']:,} | "
                f"incidents={counters['incidents']:,}"
            )
            counters["last_beat"] = now

        time.sleep(poll)


# ── shutdown ──────────────────────────────────────────────────────────────────

def _shutdown(engine, cfg, counters):
    """Save state and print exit summary."""
    print(f"\n  [monitor] Stopping...")

    storage.save(engine.incidents, cfg.INCIDENTS_FILE)
    engine.save_state()

    elapsed = int(time.monotonic() - counters["start_time"])
    print(f"  [monitor] Session summary:")
    print(f"  [monitor]   Uptime    : {_fmt_duration(elapsed)}")
    print(f"  [monitor]   Lines     : {counters['lines']:,}")
    print(f"  [monitor]   Incidents : {counters['incidents']:,}")
    print(f"  [monitor] State saved. Goodbye.")


# ── helpers ───────────────────────────────────────────────────────────────────

def _fmt_duration(seconds: int) -> str:
    """Format seconds as Xh Ym Zs."""
    h, rem = divmod(seconds, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"
