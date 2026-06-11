"""
incidents.py — Incident data structure
========================================
An incident is the core entity this system tracks.
One incident = one detected threat event.

Fields:
    ip        — source IP (or TARGET:<username> for distributed attacks)
    timestamp — when detected (ISO string)
    severity  — "HIGH" or "MEDIUM"
    reason    — what rule fired
    score     — decay score at detection time
    detail    — human-readable explanation of why this fired (Pillar 9)

Reasons:
    burst_detected      — N+ failures in BURST_WINDOW seconds
    password_spray      — N+ unique usernames from one IP in SPRAY_WINDOW
    distributed_attack  — N+ IPs targeting one username in DIST_WINDOW
    correlated_medium   — N+ MEDIUM incidents escalated to HIGH
    high_score          — decay score crossed THRESH_HIGH
    medium_score        — decay score crossed THRESH_MEDIUM
"""

from datetime import datetime


def create(ip: str, ts: datetime, severity: str, reason: str,
           score: float, detail: str = "") -> dict:
    """Build a new incident dict."""
    return {
        "ip":        ip,
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "severity":  severity,
        "reason":    reason,
        "score":     round(score, 2),
        "detail":    detail,
    }


def from_dict(d: dict) -> dict:
    """
    Deserialize from a plain dict (e.g. loaded from JSON).
    Returns None if required fields are missing.
    """
    required = {"ip", "timestamp", "severity", "reason", "score"}
    if not required.issubset(d.keys()):
        return None
    # Backfill detail for older incidents that predate this field
    if "detail" not in d:
        d["detail"] = ""
    return d


def timestamp_as_dt(incident: dict) -> datetime:
    """Parse the incident's timestamp string back to a datetime object."""
    return datetime.strptime(incident["timestamp"], "%Y-%m-%d %H:%M:%S")


def explain(incident: dict) -> str:
    """
    Return a plain-English explanation of why this incident fired.
    Answers the question: 'Why did this alert trigger?'
    """
    r = incident["reason"]
    d = incident.get("detail", "")
    ip = incident["ip"]
    ts = incident["timestamp"]
    sev = incident["severity"]

    explanations = {
        "burst_detected":     f"Rapid login failures detected from {ip} ({d}). "
                              f"This pattern matches a brute-force attack.",
        "password_spray":     f"Single IP {ip} tried many different usernames ({d}). "
                              f"This evades per-account lockout policies.",
        "distributed_attack": f"Multiple attackers coordinated against the same account ({d}). "
                              f"No single IP would trigger a standard alert.",
        "correlated_medium":  f"IP {ip} accumulated repeated MEDIUM alerts ({d}), "
                              f"escalated to HIGH — persistent low-level threat.",
        "high_score":         f"IP {ip} crossed the HIGH risk threshold ({d}). "
                              f"Repeated failures over time indicate sustained attack.",
        "medium_score":       f"IP {ip} crossed the MEDIUM risk threshold ({d}). "
                              f"Worth monitoring — not yet conclusive.",
    }

    explanation = explanations.get(r, f"Rule '{r}' fired for {ip}.")
    return f"[{ts}] {sev} — {explanation}"
