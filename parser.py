"""
parser.py — Log parsing and normalization
Author: Marhfour Mehdi
"""

import re
from datetime import datetime


# ── Log Formats ────────────────────────────────────────────────────────────────
SYSLOG_PATTERN = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.*)"
)

AUTH_PATTERNS = {
    "FAILED_LOGIN":    re.compile(r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)", re.I),
    "SUCCESS_LOGIN":   re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)", re.I),
    "INVALID_USER":    re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)", re.I),
    "ROOT_ATTEMPT":    re.compile(r"Failed password for root from (\d+\.\d+\.\d+\.\d+)", re.I),
    "SUDO":            re.compile(r"sudo:.*COMMAND=(.*)", re.I),
    "CONNECTION":      re.compile(r"Connection from (\d+\.\d+\.\d+\.\d+)", re.I),
    "DISCONNECT":      re.compile(r"Disconnected from (\d+\.\d+\.\d+\.\d+)", re.I),
}


def parse_line(line):
    """Parse a single syslog line into structured fields."""
    line = line.strip()
    if not line:
        return None

    match = SYSLOG_PATTERN.match(line)
    if match:
        return {
            "timestamp": match.group(1),
            "host":      match.group(2),
            "service":   match.group(3),
            "message":   match.group(4),
            "raw":       line,
        }
    return {
        "timestamp": datetime.now().strftime("%b %d %H:%M:%S"),
        "host":      "unknown",
        "service":   "unknown",
        "message":   line,
        "raw":       line,
    }


def classify_event(parsed):
    """Classify a parsed log line into an event type."""
    if not parsed:
        return None

    msg = parsed["message"]
    for event_type, pattern in AUTH_PATTERNS.items():
        match = pattern.search(msg)
        if match:
            groups = match.groups()
            return {
                **parsed,
                "event_type": event_type,
                "user":       groups[0] if len(groups) > 1 else "N/A",
                "source_ip":  next(
                    (g for g in groups if g and re.match(r"\d+\.\d+\.\d+\.\d+", g)),
                    "N/A"
                ),
            }
    return {**parsed, "event_type": "INFO", "user": "N/A", "source_ip": "N/A"}


def parse_file(filepath):
    """Parse an entire log file and return classified events."""
    events = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed = parse_line(line)
                event  = classify_event(parsed)
                if event:
                    events.append(event)
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
    return events


def parse_sample():
    """Return built-in sample log events for demo mode."""
    sample_logs = [
        "Mar 15 09:01:01 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 09:01:02 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 09:01:03 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 09:01:04 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 09:01:05 server sshd: Failed password for root from 192.168.1.100 port 22",
        "Mar 15 09:01:06 server sshd: Failed password for admin from 10.0.0.50 port 22",
        "Mar 15 09:01:07 server sshd: Failed password for admin from 10.0.0.50 port 22",
        "Mar 15 09:01:08 server sshd: Failed password for admin from 10.0.0.50 port 22",
        "Mar 15 09:02:01 server sshd: Invalid user test from 172.16.0.10 port 4521",
        "Mar 15 09:02:02 server sshd: Invalid user oracle from 172.16.0.10 port 4522",
        "Mar 15 09:02:03 server sshd: Invalid user postgres from 172.16.0.10 port 4523",
        "Mar 15 09:03:01 server sshd: Accepted password for mehdi from 192.168.1.1 port 22",
        "Mar 15 09:04:01 server sudo: mehdi : COMMAND=/usr/bin/apt-get update",
        "Mar 15 09:05:01 server sshd: Connection from 203.0.113.10 port 53412",
        "Mar 15 09:05:02 server sshd: Connection from 203.0.113.10 port 53413",
        "Mar 15 09:05:03 server sshd: Connection from 203.0.113.10 port 53414",
        "Mar 15 09:05:04 server sshd: Connection from 203.0.113.10 port 53415",
        "Mar 15 09:05:05 server sshd: Connection from 203.0.113.10 port 53416",
        "Mar 15 09:05:06 server sshd: Connection from 203.0.113.10 port 53417",
        "Mar 15 09:05:07 server sshd: Connection from 203.0.113.10 port 53418",
        "Mar 15 09:05:08 server sshd: Connection from 203.0.113.10 port 53419",
        "Mar 15 09:05:09 server sshd: Connection from 203.0.113.10 port 53420",
        "Mar 15 09:05:10 server sshd: Connection from 203.0.113.10 port 53421",
    ]
    events = []
    for line in sample_logs:
        parsed = parse_line(line)
        event  = classify_event(parsed)
        if event:
            events.append(event)
    return events