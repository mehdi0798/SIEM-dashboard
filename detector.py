"""
detector.py — Threat detection engine
Author: Marhfour Mehdi
"""

from collections import defaultdict

# ── Thresholds ─────────────────────────────────────────────────────────────────
THRESHOLDS = {
    "FAILED_LOGIN":  5,
    "ROOT_ATTEMPT":  1,
    "INVALID_USER":  3,
    "CONNECTION":    10,
    "SUCCESS_LOGIN": 1,
    "SUDO":          1,
}

SEVERITY = {
    "BRUTE_FORCE":        "HIGH",
    "ROOT_ATTACK":        "HIGH",
    "CREDENTIAL_STUFFING":"HIGH",
    "PORT_SCAN":          "MEDIUM",
    "SUCCESSFUL_LOGIN":   "LOW",
    "SUDO_EXECUTION":     "LOW",
}

DESCRIPTIONS = {
    "BRUTE_FORCE":         "Multiple failed login attempts from same IP — possible brute force",
    "ROOT_ATTACK":         "Direct root login attempt detected — critical risk",
    "CREDENTIAL_STUFFING": "Multiple invalid usernames from same IP — credential stuffing",
    "PORT_SCAN":           "High connection rate from single IP — possible port scan",
    "SUCCESSFUL_LOGIN":    "Successful authentication recorded",
    "SUDO_EXECUTION":      "Privileged command executed via sudo",
}

MITRE = {
    "BRUTE_FORCE":         "T1110 — Brute Force",
    "ROOT_ATTACK":         "T1078 — Valid Accounts (root)",
    "CREDENTIAL_STUFFING": "T1110.004 — Credential Stuffing",
    "PORT_SCAN":           "T1046 — Network Service Scanning",
    "SUCCESSFUL_LOGIN":    "T1078 — Valid Accounts",
    "SUDO_EXECUTION":      "T1548.003 — Sudo and Sudo Caching",
}


def detect(events):
    """
    Run detection rules against classified events.
    Returns list of alert dictionaries.
    """
    counts = defaultdict(lambda: defaultdict(int))

    for e in events:
        ip = e.get("source_ip", "N/A")
        counts[e["event_type"]][ip] += 1

    alerts = []
    seen   = set()

    for e in events:
        ip         = e.get("source_ip", "N/A")
        event_type = e["event_type"]
        count      = counts[event_type][ip]

        alert_type = None

        if event_type == "FAILED_LOGIN" and count >= THRESHOLDS["FAILED_LOGIN"]:
            alert_type = "BRUTE_FORCE"
        elif event_type == "ROOT_ATTEMPT" and count >= THRESHOLDS["ROOT_ATTEMPT"]:
            alert_type = "ROOT_ATTACK"
        elif event_type == "INVALID_USER" and count >= THRESHOLDS["INVALID_USER"]:
            alert_type = "CREDENTIAL_STUFFING"
        elif event_type == "CONNECTION" and count >= THRESHOLDS["CONNECTION"]:
            alert_type = "PORT_SCAN"
        elif event_type == "SUCCESS_LOGIN":
            alert_type = "SUCCESSFUL_LOGIN"
        elif event_type == "SUDO":
            alert_type = "SUDO_EXECUTION"

        if alert_type:
            key = (alert_type, ip)
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "Alert":       alert_type,
                    "Severity":    SEVERITY.get(alert_type, "LOW"),
                    "Source_IP":   ip,
                    "User":        e.get("user", "N/A"),
                    "Count":       count,
                    "Description": DESCRIPTIONS.get(alert_type, ""),
                    "MITRE":       MITRE.get(alert_type, "N/A"),
                    "Timestamp":   e.get("timestamp", "N/A"),
                    "Host":        e.get("host", "N/A"),
                })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: order.get(a["Severity"], 99))
    return alerts