import sys

import config as config_mod
import storage
import report as report_mod
import simulator
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


def _run_engine(log_file: str, cfg, silent: bool = False):
    """
    Shared helper: open a log file, feed it to the engine, return the engine.
    Exits with an error message if the file is not found.
    """
    engine = SecurityEngine(cfg)
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

    engine, total, errors = _run_engine(log_file, cfg, silent=(fmt != "console"))

    storage.save(engine.incidents, cfg.INCIDENTS_FILE)
    if engine.incidents:
        print(f"  [memory] {len(engine.incidents)} new incident(s) saved to {cfg.INCIDENTS_FILE}")

    report_mod.export(engine.incidents, fmt=fmt, output=output)
    print(f"\n  {total} lines processed, {errors} parse error(s).")


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


def cmd_help():
    print("""
  Log Analyzer — CLI reference
  ─────────────────────────────────────────────────────
  analyze  <logfile> [--format console|json|file] [--output <path>]
               Analyze a log file. Prints live alerts and a summary.

  report         [--format console|json|file] [--output <path>]
               Summarize all stored incidents.

  history  <ip>
               Show incident history for a specific IP.

  simulate       [--output <path>]
               Generate a synthetic attack log for testing.

  scenarios
               Generate the full scenario library into logs/.

  export         --format json|file --output <path>
               Export stored incidents without re-analyzing.

  reset          --confirm
               Clear all stored incidents.
  ─────────────────────────────────────────────────────
  Config: edit config.json to tune thresholds and windows.
""")


# ── dispatch ─────────────────────────────────────────────────────────────────

COMMANDS = {
    "analyze":   cmd_analyze,
    "report":    cmd_report,
    "history":   cmd_history,
    "simulate":  cmd_simulate,
    "scenarios": cmd_scenarios,
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
