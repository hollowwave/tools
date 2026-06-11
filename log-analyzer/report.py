"""
report.py — Reporting layer
==============================
One job: take incidents and metrics and produce output.

Supports three output formats:
  - console (default) : human-readable summary printed to stdout
  - json              : incidents as raw JSON, printed or saved to file
  - file              : human-readable summary written to a .txt file
"""

import json
from collections import defaultdict
from pathlib import Path

import incidents as incidents_mod


# ── console summary ──────────────────────────────────────────────────────────

def print_summary(incidents: list, metrics: dict = None):
    """Print a human-readable summary to stdout."""
    if not incidents:
        print("\n  No incidents detected.")
        if metrics:
            _print_metrics(metrics)
        return

    highs = [i for i in incidents if i["severity"] == "HIGH"]
    meds  = [i for i in incidents if i["severity"] == "MEDIUM"]

    by_ip = defaultdict(int)
    for i in incidents:
        by_ip[i["ip"]] += 1
    top = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:5]

    print("\n" + "─" * 60)
    print("  SUMMARY")
    print("─" * 60)
    print(f"  Total incidents : {len(incidents)}")
    print(f"  HIGH            : {len(highs)}")
    print(f"  MEDIUM          : {len(meds)}")
    print("\n  Top offending IPs:")
    for ip, count in top:
        print(f"    {ip:<22} {count} incident(s)")
    print("─" * 60)

    if metrics:
        _print_metrics(metrics)


def _print_metrics(metrics: dict):
    """Print engine metrics."""
    processed = metrics.get("events_processed", 0)
    errors    = metrics.get("parse_errors", 0)
    highs     = metrics.get("incidents_high", 0)
    meds      = metrics.get("incidents_medium", 0)
    fp_supp   = metrics.get("false_positive_suppressed", 0)
    total_inc = highs + meds

    print("\n  METRICS")
    print("─" * 60)
    print(f"  Events processed          : {processed}")
    print(f"  Parse errors              : {errors}")
    print(f"  Incidents (HIGH/MEDIUM)   : {highs} / {meds}")
    print(f"  FP suppressed (on SUCCESS): {fp_supp}")
    if processed > 0:
        rate = (total_inc / processed) * 100
        print(f"  Alert rate                : {rate:.2f}% ({total_inc} alerts / {processed} events)")
    print("─" * 60)


def print_history(incidents: list, ip: str):
    """Print all incidents for a specific IP."""
    matches = [i for i in incidents if i["ip"] == ip]
    if not matches:
        print(f"\n  No incidents found for {ip}.")
        return

    print(f"\n  Incident history for {ip}  ({len(matches)} total)")
    print("─" * 60)
    for i in matches:
        print(f"  {i['timestamp']}  {i['severity']:<6}  {i['reason']:<18}  score={i['score']}")
        if i.get("detail"):
            print(f"    → {i['detail']}")
    print("─" * 60)


def print_explain(incidents: list):
    """Print plain-English explanation for every incident."""
    if not incidents:
        print("\n  No incidents to explain.")
        return

    print("\n" + "─" * 60)
    print("  EXPLANATIONS")
    print("─" * 60)
    for i in incidents:
        d = incidents_mod.from_dict(i)
        if d:
            print(f"  {incidents_mod.explain(d)}")
    print("─" * 60)


# ── export ───────────────────────────────────────────────────────────────────

def export(incidents: list, fmt: str = "console", output: str = None,
           metrics: dict = None):
    """
    Export incidents in the requested format.
    fmt     : "console" | "json" | "file"
    output  : file path (required for fmt="file"; optional for fmt="json")
    """
    if fmt == "json":
        content = json.dumps(incidents, indent=2)
        if output:
            _write(content, output)
            print(f"  Exported {len(incidents)} incident(s) → {output}")
        else:
            print(content)

    elif fmt == "file":
        if not output:
            print("  Error: --output <path> is required with --format file")
            return
        lines = _summary_lines(incidents, metrics)
        _write("\n".join(lines), output)
        print(f"  Report saved → {output}")

    else:
        print_summary(incidents, metrics)


# ── helpers ──────────────────────────────────────────────────────────────────

def _summary_lines(incidents: list, metrics: dict = None) -> list:
    """Build summary as a list of strings (for file export)."""
    if not incidents:
        return ["No incidents detected."]

    highs = [i for i in incidents if i["severity"] == "HIGH"]
    meds  = [i for i in incidents if i["severity"] == "MEDIUM"]

    by_ip = defaultdict(int)
    for i in incidents:
        by_ip[i["ip"]] += 1
    top = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:5]

    lines = [
        "─" * 60,
        "  INCIDENT REPORT",
        "─" * 60,
        f"  Total : {len(incidents)}  (HIGH={len(highs)}, MEDIUM={len(meds)})",
        "",
        "  Top offending IPs:",
    ]
    for ip, count in top:
        lines.append(f"    {ip:<22} {count} incident(s)")

    lines += ["", "  All incidents:", "─" * 60]
    for i in incidents:
        detail = f" → {i['detail']}" if i.get("detail") else ""
        lines.append(
            f"  {i['timestamp']}  {i['severity']:<6}  {i['ip']:<20}  {i['reason']}{detail}"
        )

    if metrics:
        lines += ["", "─" * 60, "  METRICS", "─" * 60]
        for k, v in metrics.items():
            lines.append(f"  {k:<35} {v}")

    lines.append("─" * 60)
    return lines


def _write(content: str, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
