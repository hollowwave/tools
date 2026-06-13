"""
engine.py — Detection logic
==============================
One job: given a parsed log event, decide if it's a threat.

Detection rules (evaluated in priority order):
  1. Burst          : >= BURST_MIN_FAIL failures from one IP in BURST_WINDOW → HIGH
  2. Password spray : >= SPRAY_MIN_USERS unique usernames from one IP in SPRAY_WINDOW → HIGH
  3. Distributed    : >= DIST_MIN_IPS unique IPs failing against one username in DIST_WINDOW → HIGH
  4. Correlation    : >= CORR_MEDIUM_THRESHOLD MEDIUM incidents from one IP → escalate to HIGH
  5. Decay score    : score >= THRESH_HIGH → HIGH, >= THRESH_MEDIUM → MEDIUM

False positive reduction:
  - An IP that successfully logs in resets its recent-failure window
  - Score is reduced on SUCCESS (existing behaviour)
  - Correlation only escalates if MEDIUMs are recent (within CORR_WINDOW)

Accepts a Config object from config.py — no hardcoded values here.
Does NOT print, save, or report — main.py handles that.
"""

import math
from collections import defaultdict
from datetime import datetime

from parser import parse_line
import incidents as incidents_mod
import state as state_mod
import alerting


class SecurityEngine:
    def __init__(self, cfg):
        self.cfg         = cfg
        self._state      = defaultdict(lambda: {"score": 0.0, "last_ts": None})
        self._events     = defaultdict(list)   # ip → [(ts, event_type, user)]
        self._last_alert = defaultdict(dict)   # ip → {reason: last_alert_ts}
        self.incidents   = []                  # all incidents this session

        # Cross-IP state for distributed attack detection
        self._target_events = defaultdict(list)  # user → [(ts, ip)]

        # Per-IP MEDIUM incident timestamps for correlation
        self._medium_ts = defaultdict(list)    # ip → [ts, ...]

        # Metrics — tracked across the whole session
        self.metrics = {
            "events_processed": 0,
            "parse_errors":     0,
            "incidents_high":   0,
            "incidents_medium": 0,
            "false_positive_suppressed": 0,
        }

    # ── state persistence ────────────────────

    def load_state(self, cfg, path: str = None) -> bool:
        """
        Restore detection state from disk.
        Call once after __init__, before processing any lines.
        Returns True if state was found and loaded.
        """
        kwargs = {"path": path} if path else {}
        return state_mod.load(self, cfg, **kwargs)

    def save_state(self, path: str = None) -> bool:
        """
        Persist current detection state to disk.
        Call after processing a batch of lines, or periodically in monitor mode.
        Returns True on success.
        """
        kwargs = {"path": path} if path else {}
        return state_mod.save(self, **kwargs)

    # ── public ───────────────────────────────

    def ingest(self, line: str, silent: bool = False) -> bool:
        """
        Process one raw log line.
        silent=True suppresses per-alert printing.
        Returns True if parsed successfully, False otherwise.
        """
        parsed = parse_line(line)
        if parsed is None:
            self.metrics["parse_errors"] += 1
            return False

        self.metrics["events_processed"] += 1
        ts, ip, user, event_type = parsed

        self._prune(ip, ts)
        self._events[ip].append((ts, event_type, user))

        # Hard cap enforced after append so the newest event is always kept
        cap = getattr(self.cfg, "MAX_EVENTS_PER_IP", 10_000)
        if len(self._events[ip]) > cap:
            self._events[ip] = self._events[ip][-cap:]
        self._update_score(ip, ts, event_type)

        # False positive reduction:
        # A successful login clears recent failure context for this IP.
        # This means a user who mistyped their password then logged in
        # won't accumulate suspicion from that failure window.
        if event_type == "SUCCESS":
            self._clear_recent_fails(ip, ts)

        # Update cross-IP target tracking
        if event_type == "FAIL" and user:
            self._prune_target(user, ts)
            self._target_events[user].append((ts, ip))

        self._evaluate(ip, ts, user, silent=silent)
        return True

    # ── memory management ────────────────────

    def _prune(self, ip: str, now: datetime):
        """
        Drop per-IP events older than EVENT_TTL_HOURS.
        A hard per-IP event cap is enforced in ingest() after append.
        """
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

    def _prune_medium_ts(self, ip: str, now: datetime):
        """Drop MEDIUM timestamps outside the correlation window."""
        cutoff = self.cfg.CORR_WINDOW
        self._medium_ts[ip] = [
            t for t in self._medium_ts[ip]
            if (now - t).total_seconds() <= cutoff
        ]

    def _clear_recent_fails(self, ip: str, now: datetime):
        """
        False positive reduction: on SUCCESS, drop failures within
        FP_SUCCESS_WINDOW seconds. A typo followed by a correct login
        should not count against the user.
        """
        cutoff = self.cfg.FP_SUCCESS_WINDOW
        before = len(self._events[ip])
        self._events[ip] = [
            (t, e, u) for t, e, u in self._events[ip]
            if not (e == "FAIL" and (now - t).total_seconds() <= cutoff)
        ]
        suppressed = before - len(self._events[ip])
        if suppressed > 0:
            self.metrics["false_positive_suppressed"] += suppressed

    # ── scoring ──────────────────────────────

    def _update_score(self, ip: str, ts: datetime, event_type: str):
        """
        Exponential decay scoring:
          - Score decays naturally over time (half-life ~1.4 hours)
          - Each FAIL adds 10 points
          - Each SUCCESS subtracts FP_SUCCESS_SCORE_REDUCTION (default 5)
        """
        s = self._state[ip]
        if s["last_ts"] is not None:
            hours = (ts - s["last_ts"]).total_seconds() / 3600
            s["score"] *= math.exp(-0.5 * hours)

        if event_type == "FAIL":
            s["score"] += 10
        else:
            s["score"] = max(0.0, s["score"] - self.cfg.FP_SUCCESS_SCORE_REDUCTION)

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
            self._create_incident(
                ip, ts, "HIGH", score, "burst_detected",
                detail=f"{len(recent_fails)} failures in {cfg.BURST_WINDOW}s",
                silent=silent
            )
            return

        # 2. Password spray — one IP targeting many usernames
        if user:
            recent_users = set(
                u for t, e, u in self._events[ip]
                if (ts - t).total_seconds() <= cfg.SPRAY_WINDOW
                and e == "FAIL" and u is not None
            )
            if len(recent_users) >= cfg.SPRAY_MIN_USERS:
                self._create_incident(
                    ip, ts, "HIGH", score, "password_spray",
                    detail=f"{len(recent_users)} unique usernames in {cfg.SPRAY_WINDOW}s",
                    silent=silent
                )
                return

        # 3. Distributed attack — many IPs targeting one username
        if user:
            recent_ips = set(
                attacking_ip for t, attacking_ip in self._target_events[user]
                if (ts - t).total_seconds() <= cfg.DIST_WINDOW
            )
            if len(recent_ips) >= cfg.DIST_MIN_IPS:
                self._create_incident(
                    f"TARGET:{user}", ts, "HIGH", 0.0, "distributed_attack",
                    detail=f"{len(recent_ips)} IPs targeting '{user}' in {cfg.DIST_WINDOW}s",
                    silent=silent
                )
                return

        # 4. Correlation — repeated MEDIUMs escalate to HIGH
        self._prune_medium_ts(ip, ts)
        if len(self._medium_ts[ip]) >= cfg.CORR_MEDIUM_THRESHOLD:
            self._create_incident(
                ip, ts, "HIGH", score, "correlated_medium",
                detail=f"{len(self._medium_ts[ip])} MEDIUM incidents in {cfg.CORR_WINDOW}s",
                silent=silent
            )
            self._medium_ts[ip].clear()  # reset after escalation
            return

        # 5. Decay score
        if score >= cfg.THRESH_HIGH:
            self._create_incident(
                ip, ts, "HIGH", score, "high_score",
                detail=f"score {score:.1f} >= threshold {cfg.THRESH_HIGH}",
                silent=silent
            )
        elif score >= cfg.THRESH_MEDIUM:
            self._create_incident(
                ip, ts, "MEDIUM", score, "medium_score",
                detail=f"score {score:.1f} >= threshold {cfg.THRESH_MEDIUM}",
                silent=silent
            )

    # ── incident creation ────────────────────

    def _create_incident(self, ip: str, ts: datetime, sev: str, score: float,
                         reason: str, detail: str = "", silent: bool = False):
        """Deduplicate, record metrics, then create an incident."""
        last = self._last_alert[ip].get(reason)
        if last and (ts - last).total_seconds() < self.cfg.ALERT_COOLDOWN:
            return

        self._last_alert[ip][reason] = ts

        # Track MEDIUM timestamps for correlation
        if sev == "MEDIUM":
            self._medium_ts[ip].append(ts)

        # Update metrics
        if sev == "HIGH":
            self.metrics["incidents_high"] += 1
        else:
            self.metrics["incidents_medium"] += 1

        incident = incidents_mod.create(ip, ts, sev, reason, score, detail)
        self.incidents.append(incident)

        if not silent:
            detail_str = f" | {detail}" if detail else ""
            print(
                f"[ALERT] {sev:<6} | {incident['timestamp']} "
                f"| ip={ip:<20} | reason={reason:<18} | score={score:.2f}{detail_str}"
            )

        alerting.dispatch(incident, self.cfg)
