import math
from collections import defaultdict
from datetime import datetime

from parser import parse_line
import incidents as incidents_mod


class SecurityEngine:
    def __init__(self, cfg):
        self.cfg         = cfg
        self._state      = defaultdict(lambda: {"score": 0.0, "last_ts": None})
        self._events     = defaultdict(list)  # ip → [(ts, event_type, user)]
        self._last_alert = defaultdict(dict)  # ip → {reason: last_alert_ts}
        self.incidents   = []                 # all incidents this session

        # Cross-IP state for distributed attack detection
        # target_user → [(ts, ip)]
        self._target_events = defaultdict(list)

    # ── public ───────────────────────────────

    def ingest(self, line: str, silent: bool = False) -> bool:
        """
        Process one raw log line.
        silent=True suppresses per-alert printing.
        Returns True if parsed successfully, False otherwise.
        """
        parsed = parse_line(line)
        if parsed is None:
            return False

        ts, ip, user, event_type = parsed
        self._prune(ip, ts)
        self._events[ip].append((ts, event_type, user))
        self._update_score(ip, ts, event_type)

        # Update cross-IP target tracking for distributed detection
        if event_type == "FAIL" and user:
            self._prune_target(user, ts)
            self._target_events[user].append((ts, ip))

        self._evaluate(ip, ts, user, silent=silent)
        return True

    # ── memory management ────────────────────

    def _prune(self, ip: str, now: datetime):
        """Drop per-IP events older than EVENT_TTL_HOURS."""
        cutoff = self.cfg.EVENT_TTL_HOURS * 3600
        self._events[ip] = [
            (t, e, u) for t, e, u in self._events[ip]
            if (now - t).total_seconds() <= cutoff
        ]

    def _prune_target(self, user: str, now: datetime):
        """Drop target-tracking events older than DIST_WINDOW."""
        cutoff = self.cfg.DIST_WINDOW
        self._target_events[user] = [
            (t, ip) for t, ip in self._target_events[user]
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

    def _evaluate(self, ip: str, ts: datetime, user: str, silent: bool = False):
        cfg   = self.cfg
        score = self._state[ip]["score"]

        # 1. Burst — rapid failures from one IP
        recent_fails = [
            t for t, e, u in self._events[ip]
            if (ts - t).total_seconds() <= cfg.BURST_WINDOW and e == "FAIL"
        ]
        if len(recent_fails) >= cfg.BURST_MIN_FAIL:
            self._create_incident(ip, ts, "HIGH", score, "burst_detected", silent)
            return  # burst is definitive, skip lower-priority checks

        # 2. Password spray — one IP targeting many usernames
        if user:
            recent_users = set(
                u for t, e, u in self._events[ip]
                if (ts - t).total_seconds() <= cfg.SPRAY_WINDOW
                and e == "FAIL"
                and u is not None
            )
            if len(recent_users) >= cfg.SPRAY_MIN_USERS:
                self._create_incident(ip, ts, "HIGH", score, "password_spray", silent)
                return

        # 3. Distributed attack — many IPs targeting one username
        if user:
            recent_ips = set(
                attacking_ip for t, attacking_ip in self._target_events[user]
                if (ts - t).total_seconds() <= cfg.DIST_WINDOW
            )
            if len(recent_ips) >= cfg.DIST_MIN_IPS:
                # Alert is tied to the target username, not a single IP
                self._create_incident(
                    f"TARGET:{user}", ts, "HIGH", 0.0, "distributed_attack", silent
                )
                return

        # 4. Decay score
        if score >= cfg.THRESH_HIGH:
            self._create_incident(ip, ts, "HIGH", score, "high_score", silent)
        elif score >= cfg.THRESH_MEDIUM:
            self._create_incident(ip, ts, "MEDIUM", score, "medium_score", silent)

    # ── incident creation ────────────────────

    def _create_incident(self, ip: str, ts: datetime, sev: str, score: float, reason: str, silent: bool = False):
        """Deduplicate then record an incident."""
        last = self._last_alert[ip].get(reason)
        if last and (ts - last).total_seconds() < self.cfg.ALERT_COOLDOWN:
            return

        self._last_alert[ip][reason] = ts

        incident = incidents_mod.create(ip, ts, sev, reason, score)
        self.incidents.append(incident)

        if not silent:
            print(
                f"[ALERT] {sev:<6} | {incident['timestamp']} "
                f"| ip={ip:<20} | reason={reason:<18} | score={score:.2f}"
            )
