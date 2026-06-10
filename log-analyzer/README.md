<h1>Security Log Analyzer</h1><br>
A simple Python-based security log analyzer that detects suspicious login activity using burst detection and scoring.<br><br>

Features<br>
- Detects login failures from log files
- Burst detection for rapid failed attempts
- Score-based risk evaluation
- Severity levels: LOW, MEDIUM, HIGH
- Incident-style alert output

How it works:<br>
- Reads log files line by line
- Tracks IP activity over time
- Uses two signals:
    - burst activity (short-term attacks)
    - risk score (long-term behavior)
- Combines rules to generate alerts

Log format<br>
Example input: 2026-06-10 08:00:01 LOGIN_FAIL user=admin ip=10.0.0.4


