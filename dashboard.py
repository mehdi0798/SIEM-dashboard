"""
dashboard.py — SIEM terminal dashboard and report export
Author: Marhfour Mehdi
"""

import os
import argparse
import pandas as pd
from datetime import datetime
from parser import parse_file, parse_sample
from detector import detect

# ── Colors ─────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

SEV_COLOR = {"HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.GREEN}

BANNER = f"""
{C.CYAN}{C.BOLD}
  ███████╗██╗███████╗███╗   ███╗    ██████╗  █████╗ ███████╗██╗  ██╗
  ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██╔══██╗██╔════╝██║  ██║
  ███████╗██║█████╗  ██╔████╔██║    ██║  ██║███████║███████╗███████║
  ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██║  ██║██╔══██║╚════██║██╔══██║
  ███████║██║███████╗██║ ╚═╝ ██║    ██████╔╝██║  ██║███████║██║  ██║
  ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{C.RESET}
{C.WHITE}  SIEM Dashboard v1.0  |  Author: Marhfour Mehdi  |  github.com/mehdi0798{C.RESET}
{C.YELLOW}  For authorized security monitoring and educational use only{C.RESET}
"""


def print_banner():
    print(BANNER)


def print_dashboard(alerts, events):
    """Print the full SIEM dashboard to terminal."""
    print(f"\n{C.BOLD}{'─' * 70}{C.RESET}")
    print(f"{C.BOLD}  SIEM DASHBOARD — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.BOLD}{'─' * 70}{C.RESET}")
    print(f"  Total log lines processed : {len(events)}")
    print(f"  Total alerts generated    : {len(alerts)}")

    for sev in ["HIGH", "MEDIUM", "LOW"]:
        count = len([a for a in alerts if a["Severity"] == sev])
        col   = SEV_COLOR.get(sev, C.WHITE)
        if count:
            print(f"  {col}{sev:<8}{C.RESET} : {count} alert(s)")

    if not alerts:
        print(f"\n{C.GREEN}  [✓] No threats detected.{C.RESET}")
        return

    print(f"\n{C.BOLD}  ALERTS{C.RESET}")
    print(f"{'─' * 70}")

    for a in alerts:
        col = SEV_COLOR.get(a["Severity"], C.WHITE)
        print(
            f"\n  {col}[{a['Severity']}]{C.RESET} {C.BOLD}{a['Alert']}{C.RESET}"
            f"\n  {'Source IP':<14}: {a['Source_IP']}"
            f"\n  {'User':<14}: {a['User']}"
            f"\n  {'Occurrences':<14}: {a['Count']}"
            f"\n  {'Description':<14}: {a['Description']}"
            f"\n  {'MITRE ATT&CK':<14}: {a['MITRE']}"
            f"\n  {'Timestamp':<14}: {a['Timestamp']}"
            f"\n  {'Host':<14}: {a['Host']}"
        )
        print(f"  {C.YELLOW}{'─' * 55}{C.RESET}")


def save_report(alerts, output_dir="reports"):
    """Export alerts to timestamped CSV."""
    if not alerts:
        return None

    os.makedirs(output_dir, exist_ok=True)
    df        = pd.DataFrame(alerts)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath  = os.path.join(output_dir, f"siem_{timestamp}.csv")
    df.to_csv(filepath, index=False)

    print(f"\n{C.GREEN}  [+] Report saved → {filepath}{C.RESET}")
    return filepath


def parse_args():
    parser = argparse.ArgumentParser(
        description="SIEM Dashboard — by Marhfour Mehdi"
    )
    parser.add_argument("logfile", nargs="?", help="Path to log file")
    parser.add_argument("--demo",   action="store_true", help="Run with sample logs")
    parser.add_argument("-o", "--output", default="reports", help="Output directory")
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    if args.demo or not args.logfile:
        print(f"  {C.CYAN}[*] Running in DEMO mode with built-in sample logs{C.RESET}")
        print(f"  {C.CYAN}[*] Usage: python dashboard.py /var/log/auth.log{C.RESET}\n")
        events = parse_sample()
    else:
        print(f"  {C.CYAN}[*] Loading log file: {args.logfile}{C.RESET}")
        events = parse_file(args.logfile)

    print(f"  {C.CYAN}[*] Parsed {len(events)} log events{C.RESET}")
    print(f"  {C.CYAN}[*] Running threat detection engine...{C.RESET}")

    alerts = detect(events)
    print_dashboard(alerts, events)
    save_report(alerts, args.output)

    print(f"\n{C.GREEN}  [✓] Analysis complete!{C.RESET}\n")


if __name__ == "__main__":
    main()