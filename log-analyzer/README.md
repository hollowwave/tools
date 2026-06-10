# Log Analyzer

A command-line security log analyzer that detects threats using burst detection and exponential decay scoring.

## Usage

```bash
# Generate a synthetic attack log (no manual editing needed)
python main.py simulate

# Analyze a log file — prints live alerts + summary
python main.py analyze logs/sample.log

# Show all stored incidents
python main.py report

# Show incident history for a specific IP
python main.py history 10.0.0.1

# Export incidents to JSON or text file
python main.py export --format json --output data/export.json
python main.py export --format file --output data/report.txt

# Clear all stored incidents
python main.py reset --confirm
```

## Output formats

All commands that produce output accept `--format` and `--output`:

```bash
python main.py analyze logs/sample.log --format json
python main.py report --format file --output data/report.txt
```

| Flag | Behaviour |
|------|-----------|
| `--format console` | Human-readable summary (default) |
| `--format json` | Raw JSON — printed or saved to `--output` |
| `--format file` | Human-readable text saved to `--output` |

## Configuration

Edit `config.json` to tune detection without touching code:

```json
{
  "burst_window": 30,
  "burst_min_fail": 3,
  "threshold_medium": 25.0,
  "threshold_high": 50.0,
  "event_ttl_hours": 1,
  "alert_cooldown": 60,
  "incidents_file": "data/incidents.json"
}
```

## How detection works

Two rules run on every event:

- **Burst detection** — N or more failures from the same IP within `burst_window` seconds → `HIGH` alert immediately
- **Decay scoring** — each failure adds 10 points; score decays over time. Crossing `threshold_high` → `HIGH`, crossing `threshold_medium` → `MEDIUM`

Incidents are deduplicated: same IP + reason won't re-alert within `alert_cooldown` seconds.

## Project structure

```
log-analyzer/
├── main.py        # CLI entry point — dispatches commands
├── engine.py      # detection logic (burst + decay scoring)
├── parser.py      # parses raw log lines into structured data
├── incidents.py   # incident data structure (create, serialize)
├── storage.py     # saves/loads incidents to data/incidents.json
├── report.py      # console summary, JSON export, file export
├── simulator.py   # generates synthetic attack logs for testing
├── config.json    # tunable detection parameters
│
├── logs/
│   ├── sample.log
│   └── simulated.log    # created by 'simulate' command
│
└── data/
    └── incidents.json   # created automatically on first run
```

## Log format

```
YYYY-MM-DD HH:MM:SS LOGIN_FAIL user=<name> ip=<address>
YYYY-MM-DD HH:MM:SS LOGIN_SUCCESS user=<name> ip=<address>
```

## Roadmap

- [x] Phase 3 — Clean engine (burst + decay, consistent output)
- [x] Phase 4 — System (modules + storage + incident objects + reports)
- [x] Phase 5 — Tool (CLI + config + output control)
- [ ] Future — IP allowlist, real-time streaming, configurable log formats
