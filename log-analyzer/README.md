Security Log Analyzer
A simple Python-based security log analyzer that detects suspicious login activity using burst detection and scoring.

Features
- Detects login failures from log files
- Burst detection for rapid failed attempts
- Score-based risk evaluation
- Severity levels: LOW, MEDIUM, HIGH
- Incident-style alert output

How it works:
- Reads log files line by line
- Tracks IP activity over time
- Uses two signals:
    - burst activity (short-term attacks)
    - risk score (long-term behavior)
- Combines rules to generate alerts

Log format
Example input: 2026-06-10 08:00:01 LOGIN_FAIL user=admin ip=10.0.0.4


