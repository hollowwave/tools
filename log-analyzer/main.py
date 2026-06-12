"""
main.py — CLI entry point
===========================
Usage:
  python main.py analyze <logfile> [--format console|json|file] [--output <path>]
  python main.py report             [--format console|json|file] [--output <path>]
  python main.py history <ip>
  python main.py simulate           [--output <path>]
  python main.py export             [--format json|file] --output <path>
  python main.py reset              [--confirm]

This file only orchestrates — it does not detect, parse, or store anything
directly. Each job belongs to its own module:

    config.py    → load config.json
    parser.py    → parse raw log lines
    engine.py    → detect threats, produce incidents
    incidents.py → incident data structure
    storage.py   → save/load incidents from disk
    report.py    → output and export
    simulator.py → generate synthetic log files
"""

import sys

import config as config_mod
import storage
import report as report_mod
import simulator
import monitor as monitor_mod
from engine import SecurityEngine


# ── helpers ──────────────────────────────────────────────────────────────────

def _parse_flags(args: list) -> dict:
    """
    Parse simple --key value flags from an argument list.
    Also handles bare --confirm flag (value = True).
    """
    flags = {}
    i = 0
    while i < len(args):
        if args[i].startswith("--"):
            key = args[i][2:]
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                flags[key] = args[i + 1]
                i += 2
            else:
                flags[key] = True
                i += 1
        else:
            i += 1
    return flags


def _run_engine(log_file: str, cfg, silent: bool = False, load_state: bool = False):
    """
    Shared helper: open a log file, feed it to the engine, return the engine.
    Exits with an error message if the file is not found.
    """
    engine = SecurityEngine(cfg)

    if load_state:
        engine.load_state(cfg)
    total  = 0
    errors = 0
    try:
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                if not engine.ingest(line, silent=silent):
                    errors += 1
    except FileNotFoundError:
        print(f"  Error: file not found — {log_file}")
        sys.exit(1)

    return engine, total, errors


# ── commands ─────────────────────────────────────────────────────────────────

def cmd_analyze(args: list, cfg):
    """
    Analyze a log file and print live alerts + optional export.

    python main.py analyze logs/sample.log
    python main.py analyze logs/sample.log --format json --output data/out.json
    """
    if not args:
        print("  Usage: python main.py analyze <logfile> [--format console|json|file] [--output <path>]")
        return

    log_file = args[0]
    flags    = _parse_flags(args[1:])
    fmt      = flags.get("format", "console")
    output   = flags.get("output")

    past = storage.load(cfg.INCIDENTS_FILE)
    if past:
        print(f"  [memory] {len(past)} incident(s) on record from previous runs")

    engine, total, errors = _run_engine(log_file, cfg, silent=(fmt != "console"), load_state=True)

    storage.save(engine.incidents, cfg.INCIDENTS_FILE)
    if engine.incidents:
        print(f"  [memory] {len(engine.incidents)} new incident(s) saved to {cfg.INCIDENTS_FILE}")

    engine.save_state()
    print(f"  [state]  Detection state saved.")

    report_mod.export(engine.incidents, fmt=fmt, output=output, metrics=engine.metrics)
    print(f"\n  {total} lines processed, {errors} parse error(s).")


def cmd_alerts(args: list, cfg):
    """
    Manage alert delivery.

    python main.py alerts            — show configured channels and status
    python main.py alerts --replay   — retry all previously failed deliveries
    python main.py alerts --test     — send a test alert to all enabled channels
    """
    import alerting as alerting_mod

    flags = _parse_flags(args)

    if "replay" in flags:
        alerting_mod.replay_failed(cfg)
        return

    if "test" in flags:
        test_incident = {
            "ip":        "10.0.0.1",
            "timestamp": "2026-01-01 00:00:00",
            "severity":  "HIGH",
            "reason":    "test_alert",
            "score":     99.0,
            "detail":    "This is a test alert from log-analyzer.",
        }
        print("  Sending test alert to all enabled channels...")
        alerting_mod.dispatch(test_incident, cfg)
        print("  Done. Check your channels.")
        return

    # Default: show channel status
    alerts_cfg = getattr(cfg, "ALERTS", {})
    if not alerts_cfg:
        print("  No 'alerts' block found in config.json.")
        print("  Add one to enable alert delivery.")
        return

    print(f"\n  Alert Delivery Channels")
    print("  " + "─" * 44)
    print(f"  Min severity : {alerts_cfg.get('min_severity', 'MEDIUM')}")
    print()

    channels = ["webhook", "discord", "slack", "email", "file"]
    for ch in channels:
        ch_cfg   = alerts_cfg.get(ch, {})
        enabled  = ch_cfg.get("enabled", False)
        status   = "✓ enabled" if enabled else "✗ disabled"

        # Show a safe preview of the destination
        if ch == "email" and enabled:
            dest = ", ".join(ch_cfg.get("to", []))
        elif ch == "file" and enabled:
            dest = ch_cfg.get("path", "")
        elif ch in ("webhook", "discord", "slack") and enabled:
            url  = ch_cfg.get("url", "")
            dest = url[:40] + "..." if len(url) > 40 else url
        else:
            dest = ""

        dest_str = f"  → {dest}" if dest else ""
        print(f"  {ch:<10} {status}{dest_str}")

    from pathlib import Path
    import alerting as alerting_mod
    failed_path = Path(alerting_mod.FAILED_ALERTS_FILE)
    if failed_path.exists():
        try:
            import json
            with open(failed_path) as f:
                failed = json.load(f)
            if failed:
                print(f"\n    {len(failed)} failed alert(s) queued in {alerting_mod.FAILED_ALERTS_FILE}")
                print(f"  Run: python main.py alerts --replay")
        except Exception:
            pass

    print("  " + "─" * 44)


def cmd_monitor(args: list, cfg):
    """
    Watch a log file continuously and analyze new lines in real time.

    python main.py monitor <logfile>
    python main.py monitor <logfile> --from-start
    """
    if not args:
        print("  Usage: python main.py monitor <logfile> [--from-start]")
        return

    log_file   = args[0]
    flags      = _parse_flags(args[1:])
    from_start = "from-start" in flags

    monitor_mod.run(log_file, cfg, from_start=from_start)


def cmd_report(args: list, cfg):
    """
    Print or export a summary of all stored incidents.

    python main.py report
    python main.py report --format json --output data/report.json
    python main.py report --format file --output data/report.txt
    """
    flags     = _parse_flags(args)
    fmt       = flags.get("format", "console")
    output    = flags.get("output")
    incidents = storage.load(cfg.INCIDENTS_FILE)

    if not incidents:
        print("  No incidents on record. Run 'analyze' first.")
        return

    report_mod.export(incidents, fmt=fmt, output=output)


def cmd_history(args: list, cfg):
    """
    Show all stored incidents for a specific IP.

    python main.py history 10.0.0.1
    """
    if not args:
        print("  Usage: python main.py history <ip>")
        return

    ip        = args[0]
    incidents = storage.load(cfg.INCIDENTS_FILE)
    report_mod.print_history(incidents, ip)


def cmd_simulate(args: list, cfg):
    """
    Generate a synthetic log file with all attack patterns.

    python main.py simulate
    python main.py simulate --output logs/custom.log
    """
    flags  = _parse_flags(args)
    output = flags.get("output", simulator.OUTPUT_FILE)

    print(f"  Generating simulation → {output}")
    simulator.generate(output=output)
    print(f"\n  Run 'python main.py analyze {output}' to process it.")


def cmd_scenarios(args: list, cfg):
    """
    Generate the full scenario library into logs/.
    Each file isolates one attack pattern for focused testing.

    python main.py scenarios
    """
    print("  Generating scenario library...")
    simulator.build_scenario_library()
    print("\n  Run 'python main.py analyze logs/<scenario>.log' to test each one.")


def cmd_explain(args: list, cfg):
    """
    Print plain-English explanations for all stored incidents.
    Answers 'Why did this alert fire?' for every incident.

    python main.py explain
    python main.py explain 10.0.0.1
    """
    incidents = storage.load(cfg.INCIDENTS_FILE)
    if not incidents:
        print("  No incidents on record. Run 'analyze' first.")
        return

    # Optional: filter by IP
    if args:
        ip = args[0]
        incidents = [i for i in incidents if i["ip"] == ip]
        if not incidents:
            print(f"  No incidents found for {ip}.")
            return

    report_mod.print_explain(incidents)


def cmd_stress(args: list, cfg):
    """
    Alert fatigue test — generate a large log and measure alert rate.

    python main.py stress
    python main.py stress --events 100000
    """
    flags      = _parse_flags(args)
    num_events = int(flags.get("events", 100000))
    output     = "logs/stress_test.log"

    print(f"  Generating {num_events:,} events → {output}")
    simulator.generate_stress(output=output, count=num_events)

    print(f"  Analyzing...")
    engine, total, errors = _run_engine(output, cfg, silent=True)

    m         = engine.metrics
    total_inc = m["incidents_high"] + m["incidents_medium"]
    rate      = (total_inc / total * 100) if total > 0 else 0

    print(f"\n  STRESS TEST RESULTS")
    print(f"  {'─' * 40}")
    print(f"  Events         : {total:>10,}")
    print(f"  Parse errors   : {errors:>10,}")
    print(f"  HIGH alerts    : {m['incidents_high']:>10,}")
    print(f"  MEDIUM alerts  : {m['incidents_medium']:>10,}")
    print(f"  Total alerts   : {total_inc:>10,}")
    print(f"  Alert rate     : {rate:>9.2f}%")
    print(f"  FP suppressed  : {m['false_positive_suppressed']:>10,}")
    print(f"  {'─' * 40}")

    if rate > 10:
        print(f"    Alert rate {rate:.1f}% is HIGH — analyst fatigue risk.")
    elif rate > 5:
        print(f"    Alert rate {rate:.1f}% is MODERATE — consider tuning thresholds.")
    else:
        print(f"    Alert rate {rate:.1f}% is acceptable.")


def cmd_export(args: list, cfg):
    """
    Export all stored incidents without re-running analysis.

    python main.py export --format json --output data/export.json
    python main.py export --format file --output data/report.txt
    """
    flags  = _parse_flags(args)
    fmt    = flags.get("format", "json")
    output = flags.get("output")

    if not output:
        print("  Usage: python main.py export --format json|file --output <path>")
        return

    incidents = storage.load(cfg.INCIDENTS_FILE)
    if not incidents:
        print("  No incidents on record. Run 'analyze' first.")
        return

    report_mod.export(incidents, fmt=fmt, output=output)


def cmd_reset(args: list, cfg):
    """
    Clear all stored incidents.

    python main.py reset --confirm
    """
    flags = _parse_flags(args)
    if "confirm" not in flags:
        print("  This will delete all stored incidents.")
        print("  Run: python main.py reset --confirm")
        return

    import json
    from pathlib import Path
    path = Path(cfg.INCIDENTS_FILE)
    if path.exists():
        # Write empty list rather than deleting, so the file always exists
        with open(path, "w") as f:
            json.dump([], f)
        print(f"  Incidents cleared → {cfg.INCIDENTS_FILE}")
    else:
        print("  Nothing to reset.")


def cmd_state(args: list, cfg):
    """
    Inspect or clear the persistent detection state.

    python main.py state            — show summary of saved state
    python main.py state --reset --confirm  — wipe the state file
    """
    import json
    from pathlib import Path

    flags = _parse_flags(args)
    path  = Path(state_mod.STATE_FILE)

    if "reset" in flags:
        if "confirm" not in flags:
            print("  This will wipe all saved detection state (scores, cooldowns, history).")
            print("  Run: python main.py state --reset --confirm")
            return
        if path.exists():
            path.unlink()
            print(f"  Detection state cleared → {path}")
        else:
            print("  No state file found — nothing to clear.")
        return

    # Default: show state summary
    if not path.exists():
        print("  No saved state found. Run 'analyze' first.")
        return

    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Could not read state file — {e}")
        return

    saved_at      = data.get("saved_at", "unknown")
    n_ips         = len(data.get("scores", {}))
    n_events      = sum(len(v) for v in data.get("events", {}).values())
    n_cooldowns   = sum(len(v) for v in data.get("last_alert", {}).values())
    n_medium_pts  = sum(len(v) for v in data.get("medium_ts", {}).values())
    n_target_evts = sum(len(v) for v in data.get("target_events", {}).values())

    print(f"\n  Detection State — saved at {saved_at}")
    print("  " + "─" * 48)
    print(f"  IPs tracked          : {n_ips}")
    print(f"  Recent events        : {n_events}")
    print(f"  Active cooldowns     : {n_cooldowns}")
    print(f"  Correlation points   : {n_medium_pts}")
    print(f"  Target-tracking evts : {n_target_evts}")

    # Show top IPs by score
    scores = data.get("scores", {})
    if scores:
        print("\n  Top IP scores (decay-uncorrected, as saved):")
        top = sorted(scores.items(), key=lambda x: x[1].get("score", 0), reverse=True)[:5]
        for ip, s in top:
            print(f"    {ip:<22} score={s['score']:.2f}  last_seen={s.get('last_ts', 'n/a')}")
    print("  " + "─" * 48)


import state as state_mod


def cmd_help():
    print("""
  Log Analyzer — CLI reference
  ─────────────────────────────────────────────────────
  alerts         [--test] [--replay]
               Show alert channel status, send a test alert, or replay failures.

  monitor  <logfile> [--from-start]
               Watch a log file live. Ctrl-C to stop cleanly.

  analyze  <logfile> [--format console|json|file] [--output <path>]
               Analyze a log file. Prints live alerts and a summary.

  report         [--format console|json|file] [--output <path>]
               Summarize all stored incidents.

  history  <ip>
               Show incident history for a specific IP.

  explain        [<ip>]
               Plain-English explanation for every stored incident.

  stress         [--events <n>]
               Alert fatigue test — generate N events and measure alert rate.

  scenarios
               Generate the full scenario library into logs/.

  export         --format json|file --output <path>
               Export stored incidents without re-analyzing.

  state          [--reset --confirm]
               Show saved detection state summary, or wipe it.

  reset          --confirm
               Clear all stored incidents.
  ─────────────────────────────────────────────────────
  Config: edit config.json to tune thresholds and windows.
""")


# ── dispatch ─────────────────────────────────────────────────────────────────

COMMANDS = {
    "alerts":    cmd_alerts,
    "monitor":   cmd_monitor,
    "state":     cmd_state,
    "analyze":   cmd_analyze,
    "report":    cmd_report,
    "history":   cmd_history,
    "explain":   cmd_explain,
    "simulate":  cmd_simulate,
    "scenarios": cmd_scenarios,
    "stress":    cmd_stress,
    "export":    cmd_export,
    "reset":     cmd_reset,
}


def main():
    cfg = config_mod.load()

    if len(sys.argv) < 2 or sys.argv[1] in ("help", "--help", "-h"):
        cmd_help()
        return

    command = sys.argv[1]
    args    = sys.argv[2:]

    if command not in COMMANDS:
        print(f"  Unknown command: '{command}'")
        print("  Run 'python main.py help' to see available commands.")
        sys.exit(1)

    COMMANDS[command](args, cfg)


if __name__ == "__main__":
    main()
