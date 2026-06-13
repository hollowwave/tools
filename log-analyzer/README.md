# Log Analyzer (late beta)

A command-line security log analyzer that detects threats using burst detection, exponential decay scoring, password spray detection, distributed attack correlation, and false positive reduction.

Phase 7 adds persistent state, live monitoring, multi-channel alert delivery, a detection coverage matrix, and production robustness hardening — so it operates like a real security system rather than a one-shot script.

## Usage

```bash
# Generate the full scenario library (burst, spray, distributed, evasion, normal)
python main.py scenarios

# Generate a single mixed attack log
python main.py simulate

# Analyze a log file — prints live alerts + summary + metrics
python main.py analyze logs/sample.log

# Watch a log file continuously (stays alive, processes new lines as they arrive)
python main.py monitor logs/auth.log
python main.py monitor logs/auth.log --from-start   # replay existing content first

# Show all stored incidents
python main.py report

# Show incident history for a specific IP
python main.py history 10.0.0.1

# Explain why every alert fired (plain English)
python main.py explain
python main.py explain 10.0.0.1

# Show saved detection state (IP scores, cooldowns, correlation history)
python main.py state
python main.py state --reset --confirm   # wipe detection state

# Show detection coverage matrix
python main.py coverage

# Show alert delivery channel status
python main.py alerts
python main.py alerts --test             # send a test alert to all enabled channels
python main.py alerts --replay          # retry previously failed deliveries

# Alert fatigue test — run N events and measure alert rate
python main.py stress
python main.py stress --events 50000

# Export incidents to JSON or text file
python main.py export --format json --output data/export.json
python main.py export --format file --output data/report.txt

# Clear all stored incidents
python main.py reset --confirm
```

## Persistent state

Detection state survives restarts. IP scores, cooldowns, correlation history, and event windows are saved to `data/engine_state.json` after every `analyze` run and periodically during `monitor` mode.

On restart, scores are **decay-corrected** for elapsed time — a score of 80 saved two hours ago restores as ~29, not 80. An attacker cannot reset their risk score by waiting for the analyzer to restart.

```bash
python main.py state              # inspect what's currently saved
python main.py state --reset --confirm   # wipe and start fresh
```

## Live monitoring

```bash
python main.py monitor logs/auth.log
```

The analyzer stays alive, tailing the file and processing new lines as they arrive — identical to `tail -f` behaviour. Handles:

- **File not yet created** — waits silently until it appears
- **Log rotation** — detects inode change or file truncation, reopens cleanly
- **Mid-read errors** — recovers and reopens next cycle rather than crashing

State is saved every 30 seconds. A heartbeat prints every 5 minutes so you know the process is alive. `Ctrl-C` saves state and exits cleanly with a session summary.

## Alert delivery

Configure delivery channels in `config.json` under the `"alerts"` key. All channels are disabled by default.

```json
"alerts": {
  "min_severity": "HIGH",
  "discord": { "enabled": true,  "url": "https://discord.com/api/webhooks/..." },
  "slack":   { "enabled": false, "url": "https://hooks.slack.com/services/..." },
  "webhook": { "enabled": false, "url": "https://your-endpoint.example.com" },
  "email": {
    "enabled": false,
    "smtp_host": "smtp.gmail.com", "smtp_port": 587,
    "username": "you@gmail.com",   "password": "your-app-password",
    "from": "you@gmail.com",       "to": ["oncall@yourteam.com"]
  },
  "file": { "enabled": false, "path": "data/alerts.log" }
}
```

Each channel retries up to 3 times with exponential backoff. If all retries fail, the incident is written to `data/failed_alerts.json` — nothing is silently dropped. Run `python main.py alerts --replay` to retry the queue.

## Detection coverage matrix

```bash
python main.py coverage
```

Prints a full matrix of known attack types, the rule that covers each one, its status (`COVERED` / `PARTIAL` / `MISSING`), and the live threshold values from your current config. Also lists honest gaps so you know exactly what the tool cannot detect.

```
Attack Type                Rule                  Status
──────────────────────────────────────────────────────────────────
Burst Brute Force          burst_detected        ✓ COVERED
Slow Brute Force           high_score (decay)    ✓ COVERED
Password Spray             password_spray        ✓ COVERED
Distributed Attack         distributed_attack    ✓ COVERED
Credential Stuffing        correlated_medium     ~ PARTIAL
Account Enumeration        —                     ✗ MISSING
Botnet / Slow Distributed  —                     ✗ MISSING
...
```

## Configuration

Edit `config.json` to tune detection without touching code. All values are validated on load — invalid types or out-of-range values fall back to defaults with a clear warning rather than crashing.

```json
{
  "burst_window": 30,
  "burst_min_fail": 3,
  "threshold_medium": 25.0,
  "threshold_high": 50.0,
  "event_ttl_hours": 1,
  "alert_cooldown": 60,
  "incidents_file": "data/incidents.json",
  "spray_window": 60,
  "spray_min_users": 3,
  "distributed_window": 60,
  "distributed_min_ips": 3,
  "corr_window": 300,
  "corr_medium_threshold": 3,
  "fp_success_window": 60,
  "fp_success_score_reduction": 5,
  "monitor_poll_interval": 1,
  "monitor_state_save_interval": 30,
  "monitor_heartbeat_interval": 300,
  "max_events_per_ip": 10000
}
```

## How detection works

Five rules run on every event, evaluated in priority order:

1. **Burst detection** — N+ failures from one IP within `burst_window` seconds → `HIGH` immediately
2. **Password spray** — one IP targeting N+ unique usernames within `spray_window` seconds → `HIGH`
3. **Distributed attack** — N+ IPs failing against the same username within `distributed_window` seconds → `HIGH`
4. **Correlation** — N+ `MEDIUM` incidents from one IP within `corr_window` seconds → escalated to `HIGH`
5. **Decay scoring** — each failure adds 10 points; score decays over time. Crossing `threshold_high` → `HIGH`, crossing `threshold_medium` → `MEDIUM`

**False positive reduction** — if an IP successfully logs in, failures within the last `fp_success_window` seconds are cleared from its window. A mistyped password followed by a correct login does not accumulate suspicion.

Incidents are deduplicated: the same IP + reason won't re-alert within `alert_cooldown` seconds.

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

## Scenario library

Generated by `python main.py scenarios`:

| File | Pattern | What it tests |
|------|---------|---------------|
| `burst_attack.log` | 10 rapid failures | Burst detection |
| `slow_attack.log` | 8 failures over 10 min | Decay scoring |
| `evasion_slow.log` | Failures every 35s (> burst window) | Score accumulation under evasion |
| `password_spray.log` | One IP, many usernames | Spray detection |
| `distributed_attack.log` | Many IPs, one target username | Distributed detection |
| `normal_users.log` | Legit logins with occasional typos | False positive baseline |
| `mixed_environment.log` | All patterns combined | Full engine test |

## Project structure

```
log-analyzer/
├── main.py        # CLI entry point — dispatches all commands
├── engine.py      # detection logic (5 rules + scoring + metrics)
├── parser.py      # parses raw log lines into structured data
├── incidents.py   # incident data structure + explain()
├── storage.py     # saves/loads incidents (atomic writes + backup recovery)
├── state.py       # persistent detection state (scores, cooldowns, history)
├── alerting.py    # multi-channel alert delivery (webhook/discord/slack/email/file)
├── monitor.py     # live file-watching loop
├── report.py      # summary, metrics, explanations, export
├── simulator.py   # scenario library + stress test generator
├── config.json    # tunable detection parameters
│
├── logs/
│   ├── sample.log
│   ├── simulated.log
│   └── ...                       # generated by 'scenarios' command
│
└── data/
    ├── incidents.json            # created automatically on first run
    ├── incidents.backup.json     # written if main file fails
    ├── engine_state.json         # persistent detection state
    └── failed_alerts.json        # alert delivery failures (replayable)
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
- [x] Phase 6 — Detection engineering (spray, distributed, correlation, FP reduction, metrics, explainability)
- [x] Phase 7 — Operationalization (persistent state, live monitoring, alert delivery, coverage matrix, robustness)
- [ ] Future — IP allowlist, configurable log formats, baseline behaviour modelling
