import json
from collections import defaultdict
from pathlib import Path


# ── console summary ──────────────────────────────────────────────────────────

def print_summary(incidents: list):
    """Print a human-readable summary to stdout."""
    if not incidents:
        print("\n  No incidents detected.")
        return

    highs = [i for i in incidents if i["severity"] == "HIGH"]
    meds  = [i for i in incidents if i["severity"] == "MEDIUM"]

    by_ip = defaultdict(int)
    for i in incidents:
        by_ip[i["ip"]] +v= 1
    top = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:5]

    print("\n" + "─" * 50)
    print("  SUMMARY")
    print("─" * 50)
    print(f"  Total incidents : {len(incidents)}")
    print(f"  HIGH            : {len(highs)}")
    print(f"  MEDIUM          : {len(meds)}")
    print("\n  Top offending IPs:")
    for ip, count in top:
        print(f"    {ip:<18} {count} incident(s)")
    print("─" * 50)


def print_history(incidents: list, ip: str):
    """Print all incidents for a specific IP."""
    matches = [i for i in incidents if i["ip"] == ip]
    if not matches:
        print(f"\n  No incidents found for {ip}.")
        return

    print(f"\n  Incident history for {ip}  ({len(matches)} total)")
    print("─" * 50)
    for i in matches:
        print(f"  {i['timestamp']}  {i['severity']:<6}  {i['reason']:<15}  score={i['score']}")
    print("─" * 50)


# ── export ───────────────────────────────────────────────────────────────────

def export(incidents: list, fmt: str = "console", output: str = None):
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
        lines = _summary_lines(incidents)
        _write("\n".join(lines), output)
        print(f"  Report saved → {output}")

    else:
        # Default: console
        print_summary(incidents)


# ── helpers ──────────────────────────────────────────────────────────────────

def _summary_lines(incidents: list) -> list:
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
        "─" * 50,
        "  INCIDENT REPORT",
        "─" * 50,
        f"  Total : {len(incidents)}  (HIGH={len(highs)}, MEDIUM={len(meds)})",
        "",
        "  Top offending IPs:",
    ]
    for ip, count in top:
        lines.append(f"    {ip:<18} {count} incident(s)")
    lines += ["", "  All incidents:", "─" * 50]
    for i in incidents:
        lines.append(f"  {i['timestamp']}  {i['severity']:<6}  {i['ip']:<15}  {i['reason']}")
    lines.append("─" * 50)
    return lines


def _write(content: str, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
