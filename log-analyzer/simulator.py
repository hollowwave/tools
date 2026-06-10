import random
from datetime import datetime, timedelta
from pathlib import Path

ATTACKER_IPS = [f"10.0.0.{i}" for i in range(1, 11)]
LEGIT_IPS    = [f"192.168.1.{i}" for i in range(1, 6)]
USERS        = ["alice", "bob", "carol", "dave", "eve"]

OUTPUT_FILE  = "logs/simulated.log"


def _line(ts: datetime, event: str, ip: str, user: str = "attacker") -> str:
    return f"{ts.strftime('%Y-%m-%d %H:%M:%S')} {event} user={user} ip={ip}"

def _offset(base: datetime, seconds: float) -> datetime:
    return base + timedelta(seconds=seconds)


# ── attack patterns ──────────────────────────────────────────────────────────

def brute_force(base: datetime, ip: str, start: float = 0) -> list:
    """10 rapid failures in 20 seconds — triggers burst detection."""
    return [
        (_offset(base, start + i * 2), _line(_offset(base, start + i * 2), "LOGIN_FAIL", ip))
        for i in range(10)
    ]

def credential_stuffing(base: datetime, start: float = 0) -> list:
    """2 failures per IP across 10 IPs — each stays under burst, but score builds."""
    events = []
    for i, ip in enumerate(ATTACKER_IPS):
        for j in range(2):
            ts = _offset(base, start + i * 15 + j * 5)
            events.append((ts, _line(ts, "LOGIN_FAIL", ip)))
    return events

def slow_and_low(base: datetime, ip: str, start: float = 0) -> list:
    """8 failures over 10 minutes — avoids burst, tests score decay."""
    return [
        (_offset(base, start + i * 75), _line(_offset(base, start + i * 75), "LOGIN_FAIL", ip))
        for i in range(8)
    ]

def mixed(base: datetime, ip: str, start: float = 0) -> list:
    """Recon → burst → success. Most realistic multi-stage pattern."""
    events = []
    # Stage 1: slow recon
    for i in range(4):
        ts = _offset(base, start + i * 90)
        events.append((ts, _line(ts, "LOGIN_FAIL", ip)))
    # Stage 2: burst
    burst_start = start + 4 * 90 + 10
    for i in range(4):
        ts = _offset(base, burst_start + i * 5)
        events.append((ts, _line(ts, "LOGIN_FAIL", ip)))
    # Stage 3: success (attacker got in)
    ts = _offset(base, burst_start + 30)
    events.append((ts, _line(ts, "LOGIN_SUCCESS", ip)))
    return events

def legit_traffic(base: datetime, start: float = 0, count: int = 20) -> list:
    """Normal user logins — adds realistic noise."""
    events = []
    for i in range(count):
        ip   = random.choice(LEGIT_IPS)
        user = random.choice(USERS)
        ts   = _offset(base, start + i * 30 + random.uniform(0, 15))
        event = "LOGIN_FAIL" if random.random() < 0.1 else "LOGIN_SUCCESS"
        events.append((ts, _line(ts, event, ip, user=user)))
    return events


# ── scenario builder ─────────────────────────────────────────────────────────

def generate(output: str = OUTPUT_FILE):
    """
    Combine all patterns into a time-sorted log file.
    Prints a summary of what was generated.
    """
    base = datetime(2024, 6, 1, 9, 0, 0)
    all_events = []

    bf_ip = "10.0.0.1"
    sl_ip = "10.0.0.7"
    ms_ip = "10.0.0.9"

    all_events += brute_force(base, ip=bf_ip, start=0)
    all_events += credential_stuffing(base, start=60)
    all_events += slow_and_low(base, ip=sl_ip, start=200)
    all_events += mixed(base, ip=ms_ip, start=300)
    all_events += legit_traffic(base, start=0, count=30)

    all_events.sort(key=lambda x: x[0])

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        for _, line in all_events:
            f.write(line + "\n")

    print(f"  Generated {len(all_events)} log lines → {output}")
    print(f"  Patterns: brute_force ({bf_ip}), credential_stuffing (10 IPs),")
    print(f"            slow_and_low ({sl_ip}), mixed multi-stage ({ms_ip}),")
    print(f"            legit traffic (30 events)")
