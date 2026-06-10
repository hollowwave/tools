from datetime import datetime


def parse_line(line: str):
    """
    Parse a single log line.
    Returns (datetime, ip, event_type) or None if the line is malformed.

    event_type is either "FAIL" or "SUCCESS".
    """
    try:
        parts = line.split()
        if len(parts) < 3:
            return None

        ts = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")

        ip = next((p.split("=")[1] for p in parts if p.startswith("ip=")), None)
        if not ip:
            return None

        event_type = "FAIL" if "LOGIN_FAIL" in line else "SUCCESS"
        return ts, ip, event_type

    except (ValueError, IndexError):
        return None
