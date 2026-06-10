from datetime import datetime


def create(ip: str, ts: datetime, severity: str, reason: str, score: float) -> dict:
    """
    Build a new incident dict.

    Fields:
        ip        — source IP address
        timestamp — when the event was detected (ISO string)
        severity  — "HIGH" or "MEDIUM"
        reason    — "burst_detected", "high_score", or "medium_score"
        score     — the IP's decay score at detection time
    """
    return {
        "ip":        ip,
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "severity":  severity,
        "reason":    reason,
        "score":     round(score, 2),
    }


def from_dict(d: dict) -> dict:
    """
    Deserialize an incident from a plain dict (e.g. loaded from JSON).
    Validates required fields; returns None if the dict is malformed.
    """
    required = {"ip", "timestamp", "severity", "reason", "score"}
    if not required.issubset(d.keys()):
        return None
    return d


def timestamp_as_dt(incident: dict) -> datetime:
    """Parse the incident's timestamp string back to a datetime object."""
    return datetime.strptime(incident["timestamp"], "%Y-%m-%d %H:%M:%S")
