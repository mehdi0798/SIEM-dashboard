# SIEM Dashboard

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

A Python-based Security Information and Event Management (SIEM) dashboard that parses system logs, detects threats in real time, maps findings to MITRE ATT&CK techniques, and exports structured alert reports.

Built during cybersecurity studies at Al Akhawayn University, inspired by real SOC workflows using Splunk and FortiAnalyzer during internships at Palo Alto Networks and Fortinet.

## Features
- Parses standard syslog and auth.log formats
- Detects brute force, root attacks, credential stuffing, port scans
- MITRE ATT&CK technique mapping per alert
- Severity classification — HIGH / MEDIUM / LOW
- Color-coded terminal dashboard
- CSV report export with full alert metadata
- Demo mode with built-in sample logs

## Project Structure
```
siem-dashboard/
├── dashboard.py   # Main entry point — terminal dashboard
├── parser.py      # Log parsing and event classification
├── detector.py    # Threat detection engine with MITRE mapping
└── requirements.txt
```

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Demo mode
python dashboard.py --demo

# Analyze a real log file
python dashboard.py /var/log/auth.log

# Custom output directory
python dashboard.py /var/log/auth.log -o my_reports/
```

## Detection Rules & MITRE ATT&CK Mapping

| Alert | Severity | Trigger | MITRE Technique |
|-------|----------|---------|-----------------|
| BRUTE_FORCE | HIGH | 5+ failed logins from same IP | T1110 — Brute Force |
| ROOT_ATTACK | HIGH | Any root login attempt | T1078 — Valid Accounts |
| CREDENTIAL_STUFFING | HIGH | 3+ invalid usernames from same IP | T1110.004 |
| PORT_SCAN | MEDIUM | 10+ connections from same IP | T1046 — Network Scanning |
| SUCCESSFUL_LOGIN | LOW | Successful authentication | T1078 — Valid Accounts |
| SUDO_EXECUTION | LOW | Sudo command executed | T1548.003 — Sudo Caching |

## Disclaimer
For authorized security monitoring and educational use only.

## Author
**Marhfour Mehdi** — github.com/mehdi0798