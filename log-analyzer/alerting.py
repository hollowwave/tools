"""
alerting.py — Multi-channel alert delivery
============================================
One job: take an incident and deliver it to every enabled channel.

Supported channels:
    webhook — generic HTTP POST (JSON payload)
    discord — Discord webhook with colored embed
    slack   — Slack incoming webhook with block message
    email   — SMTP (works with Gmail, Outlook, any relay)
    file    — append to a local alert log file

All channels are disabled by default. Enable and configure them in
config.json under the "alerts" key:

    "alerts": {
        "min_severity": "HIGH",
        "webhook": { "enabled": false, "url": "https://..." },
        "discord": { "enabled": false, "url": "https://discord.com/api/webhooks/..." },
        "slack":   { "enabled": false, "url": "https://hooks.slack.com/services/..." },
        "email": {
            "enabled":   false,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "username":  "you@gmail.com",
            "password":  "your-app-password",
            "from":      "you@gmail.com",
            "to":        ["oncall@yourteam.com"]
        },
        "file": { "enabled": false, "path": "data/alerts.log" }
    }

Reliability:
    - Each channel retries up to MAX_RETRIES times with exponential backoff.
    - If all retries fail, the incident is written to data/failed_alerts.json
      so nothing is permanently lost.
    - Delivery failures never crash the engine — errors are caught and logged.

Severity filter:
    - min_severity = "HIGH"   → only HIGH alerts are delivered
    - min_severity = "MEDIUM" → both MEDIUM and HIGH are delivered (default)
"""

import json
import os
import smtplib
import tempfile
import time
import urllib.request
import urllib.error
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

FAILED_ALERTS_FILE = "data/failed_alerts.json"
MAX_RETRIES        = 3
RETRY_BASE_DELAY   = 2   # seconds; doubles each retry

SEVERITY_ORDER = {"MEDIUM": 0, "HIGH": 1}

# ANSI-style severity colors for Discord / Slack (as decimal / hex)
_DISCORD_COLORS = {"HIGH": 0xFF0000, "MEDIUM": 0xFFAA00}   # red / amber
_SLACK_COLORS   = {"HIGH": "#FF0000", "MEDIUM": "#FFAA00"}


# ── public entry point ────────────────────────────────────────────────────────

def dispatch(incident: dict, cfg) -> None:
    """
    Deliver an incident to all enabled channels.
    Called by the engine immediately after an incident is created.
    Never raises — all errors are caught internally.
    """
    alerts_cfg = getattr(cfg, "ALERTS", {})
    if not alerts_cfg:
        return  # alerting not configured — silent no-op

    # Severity filter
    min_sev   = alerts_cfg.get("min_severity", "MEDIUM").upper()
    inc_sev   = incident.get("severity", "MEDIUM").upper()
    min_order = SEVERITY_ORDER.get(min_sev, 0)
    inc_order = SEVERITY_ORDER.get(inc_sev, 0)
    if inc_order < min_order:
        return

    channels = {
        "webhook": _send_webhook,
        "discord": _send_discord,
        "slack":   _send_slack,
        "email":   _send_email,
        "file":    _send_file,
    }

    failed = []
    for name, fn in channels.items():
        ch_cfg = alerts_cfg.get(name, {})
        if not ch_cfg.get("enabled", False):
            continue
        success = _deliver_with_retry(name, fn, incident, ch_cfg)
        if not success:
            failed.append({"channel": name, "incident": incident,
                           "failed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

    if failed:
        _save_failed(failed)


# ── retry wrapper ─────────────────────────────────────────────────────────────

def _deliver_with_retry(name: str, fn, incident: dict, ch_cfg: dict) -> bool:
    """
    Call fn(incident, ch_cfg) up to MAX_RETRIES times.
    Uses exponential backoff between attempts.
    Returns True if any attempt succeeded.
    """
    delay = RETRY_BASE_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            fn(incident, ch_cfg)
            return True
        except Exception as e:
            if attempt < MAX_RETRIES:
                print(f"  [alert:{name}] Attempt {attempt} failed ({e}) — "
                      f"retrying in {delay}s...")
                time.sleep(delay)
                delay *= 2
            else:
                print(f"  [alert:{name}] All {MAX_RETRIES} attempts failed — "
                      f"incident queued to {FAILED_ALERTS_FILE}")
    return False


# ── channel: webhook ─────────────────────────────────────────────────────────

def _send_webhook(incident: dict, ch_cfg: dict) -> None:
    """Generic HTTP POST — JSON payload."""
    url     = ch_cfg["url"]
    payload = json.dumps(incident).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "log-analyzer/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"HTTP {resp.status}")


# ── channel: discord ─────────────────────────────────────────────────────────

def _send_discord(incident: dict, ch_cfg: dict) -> None:
    """Discord webhook with a colored embed."""
    sev   = incident.get("severity", "MEDIUM")
    color = _DISCORD_COLORS.get(sev, 0x888888)
    ip    = incident.get("ip", "unknown")
    ts    = incident.get("timestamp", "")
    reason = incident.get("reason", "")
    detail = incident.get("detail", "")
    score  = incident.get("score", 0)

    embed = {
        "title":       f"🚨 {sev} Alert — {reason}",
        "color":       color,
        "description": detail or f"Threat detected from {ip}",
        "fields": [
            {"name": "IP",        "value": ip,           "inline": True},
            {"name": "Score",     "value": str(score),   "inline": True},
            {"name": "Timestamp", "value": ts,           "inline": False},
        ],
        "footer": {"text": "log-analyzer"},
    }
    payload = json.dumps({"embeds": [embed]}).encode()
    req = urllib.request.Request(
        ch_cfg["url"],
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"HTTP {resp.status}")


# ── channel: slack ────────────────────────────────────────────────────────────

def _send_slack(incident: dict, ch_cfg: dict) -> None:
    """Slack incoming webhook with a color-coded attachment."""
    sev    = incident.get("severity", "MEDIUM")
    color  = _SLACK_COLORS.get(sev, "#888888")
    ip     = incident.get("ip", "unknown")
    ts     = incident.get("timestamp", "")
    reason = incident.get("reason", "")
    detail = incident.get("detail", "")
    score  = incident.get("score", 0)

    attachment = {
        "color":    color,
        "title":    f"{sev} Alert — {reason}",
        "text":     detail or f"Threat detected from {ip}",
        "fields": [
            {"title": "IP",        "value": ip,         "short": True},
            {"title": "Score",     "value": str(score), "short": True},
            {"title": "Timestamp", "value": ts,         "short": False},
        ],
        "footer": "log-analyzer",
    }
    payload = json.dumps({"attachments": [attachment]}).encode()
    req = urllib.request.Request(
        ch_cfg["url"],
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"HTTP {resp.status}")


# ── channel: email ────────────────────────────────────────────────────────────

def _send_email(incident: dict, ch_cfg: dict) -> None:
    """Send alert via SMTP. Supports TLS (port 587) and SSL (port 465)."""
    sev    = incident.get("severity", "MEDIUM")
    ip     = incident.get("ip", "unknown")
    reason = incident.get("reason", "")
    detail = incident.get("detail", "")
    ts     = incident.get("timestamp", "")
    score  = incident.get("score", 0)

    subject = f"[{sev}] {reason} from {ip}"
    body    = (
        f"Log Analyzer Alert\n"
        f"{'─' * 40}\n"
        f"Severity  : {sev}\n"
        f"Reason    : {reason}\n"
        f"IP        : {ip}\n"
        f"Score     : {score}\n"
        f"Timestamp : {ts}\n"
        f"Detail    : {detail or 'n/a'}\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = ch_cfg["from"]
    msg["To"]      = ", ".join(ch_cfg["to"])

    host = ch_cfg.get("smtp_host", "localhost")
    port = int(ch_cfg.get("smtp_port", 587))
    user = ch_cfg.get("username", "")
    pwd  = ch_cfg.get("password", "")

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=10) as s:
            if user:
                s.login(user, pwd)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.ehlo()
            s.starttls()
            if user:
                s.login(user, pwd)
            s.send_message(msg)


# ── channel: file ─────────────────────────────────────────────────────────────

def _send_file(incident: dict, ch_cfg: dict) -> None:
    """Append a formatted alert line to a local file."""
    path = Path(ch_cfg.get("path", FAILED_ALERTS_FILE))
    path.parent.mkdir(parents=True, exist_ok=True)

    sev    = incident.get("severity", "MEDIUM")
    ip     = incident.get("ip", "unknown")
    ts     = incident.get("timestamp", "")
    reason = incident.get("reason", "")
    detail = incident.get("detail", "")
    score  = incident.get("score", 0)

    line = (
        f"{ts} | {sev:<6} | ip={ip:<20} | "
        f"reason={reason:<18} | score={score}"
        + (f" | {detail}" if detail else "")
        + "\n"
    )
    with open(path, "a") as f:
        f.write(line)


# ── failed alert persistence ──────────────────────────────────────────────────

def _save_failed(failed: list) -> None:
    """
    Append failed deliveries to data/failed_alerts.json.
    Uses atomic write so the file is never corrupt.
    """
    path = Path(FAILED_ALERTS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = []
    if path.exists():
        try:
            with open(path) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = []

    combined = existing + failed

    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(combined, f, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        print(f"  [alert] Warning: could not save failed alerts — {e}")


def replay_failed(cfg) -> None:
    """
    Retry all previously failed alert deliveries.
    Called via: python main.py alerts --replay
    Clears the failed file on success.
    """
    path = Path(FAILED_ALERTS_FILE)
    if not path.exists():
        print("  No failed alerts to replay.")
        return

    try:
        with open(path) as f:
            failed = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Could not read {FAILED_ALERTS_FILE} — {e}")
        return

    if not failed:
        print("  No failed alerts to replay.")
        return

    print(f"  Replaying {len(failed)} failed alert(s)...")
    still_failed = []
    for entry in failed:
        incident = entry.get("incident", {})
        channel  = entry.get("channel", "unknown")

        channels = {
            "webhook": _send_webhook,
            "discord": _send_discord,
            "slack":   _send_slack,
            "email":   _send_email,
            "file":    _send_file,
        }
        alerts_cfg = getattr(cfg, "ALERTS", {})
        ch_cfg     = alerts_cfg.get(channel, {})
        fn         = channels.get(channel)

        if fn and ch_cfg:
            success = _deliver_with_retry(channel, fn, incident, ch_cfg)
            if not success:
                still_failed.append(entry)
            else:
                print(f"  ✓ Replayed {channel} alert for {incident.get('ip', '?')}")
        else:
            print(f"  ✗ Channel '{channel}' not configured — keeping in queue")
            still_failed.append(entry)

    # Rewrite the failed file with only the ones that still failed
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(still_failed, f, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        print(f"  Warning: could not update {FAILED_ALERTS_FILE} — {e}")

    remaining = len(still_failed)
    if remaining == 0:
        print("  All failed alerts replayed successfully.")
    else:
        print(f"  {remaining} alert(s) still failed — kept in {FAILED_ALERTS_FILE}")
