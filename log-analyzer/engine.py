import math
from collections import defaultdict
from datetime import datetime

from parser import parse_line
import incidents as incidents_mod


class SecurityEngine:
    def __init__(self, cfg):
        self.cfg         = cfg
        self._state      = defaultdict(lambda: {"score": 0.0, "last_ts": None})
        self._events     = defaultdict(list)
        self._last_alert = defaultdict(dict)  # ip → {reason: last_alert_ts}
        self.incidents   = []                 # all incidents detected this session

    # ── public ───────────────────────────────

    def ingest(self, line: str, silent: bool = False) -> bool:
        """
        Process one raw log line.
        silent=True suppresses per-alert printing (used by export/report commands).
        Returns True if the line parsed successfully, False otherwise.
        """
        parsed = parse_line(line)
        if parsed is None:
            return False

        ts, ip, event_type = parsed
        self._prune(ip, ts)
        self._events[ip].append((ts, event_type))
        self._update_score(ip, ts, event_type)
        self._evaluate(ip, ts, silent=silent)
        return True

    # ── memory management ────────────────────

    def _prune(self, ip: str, now: datetime):
        cutoff = self.cfg.EVENT_TTL_HOURS * 3600
        self._events[ip] = [
            (t, e) for t, e in self._events[ip]
            if (now - t).total_seconds() <= cutoff
        ]

    # ── scoring ──────────────────────────────

    def _update_score(self, ip: str, ts: datetime, event_type: str):
        """
        Exponential decay scoring:
          - Score decays naturally over time (half-life ~1.4 hours)
          - Each FAIL adds 10 points
          - Each SUCCESS subtracts 1 (floor 0)
        """
        s = self._state[ip]

        if s["last_ts"] is not None:
            hours = (ts - s["last_ts"]).total_seconds() / 3600
            s["score"] *= math.exp(-0.5 * hours)

        if event_type == "FAIL":
            s["score"] += 10
        else:
            s["score"] = max(0.0, s["score"] - 1)

        s["last_ts"] = ts

    # ── evaluation ───────────────────────────

    def _evaluate(self, ip: str, ts: datetime, silent: bool = False):
        cfg   = self.cfg
        score = self._state[ip]["score"]

        recent_fails = [
            t for t, e in self._events[ip]
            if (ts - t).total_seconds() <= cfg.BURST_WINDOW and e == "FAIL"
        ]

        if len(recent_fails) >= cfg.BURST_MIN_FAIL:
            self._create_incident(ip, ts, "HIGH", score, "burst_detected", silent)
        elif score >= cfg.THRESH_HIGH:
            self._create_incident(ip, ts, "HIGH", score, "high_score", silent)
        elif score >= cfg.THRESH_MEDIUM:
            self._create_incident(ip, ts, "MEDIUM", score, "medium_score", silent)

    # ── incident creation ────────────────────

    def _create_incident(self, ip: str, ts: datetime, sev: str, score: float, reason: str, silent: bool = False):
        last = self._last_alert[ip].get(reason)
        if last and (ts - last).total_seconds() < self.cfg.ALERT_COOLDOWN:
            return

        self._last_alert[ip][reason] = ts

        incident = incidents_mod.create(ip, ts, sev, reason, score)
        self.incidents.append(incident)

        if not silent:
            print(
                f"[ALERT] {sev:<6} | {incident['timestamp']} "
                f"| ip={ip:<15} | reason={reason:<15} | score={score:.2f}"
            )
