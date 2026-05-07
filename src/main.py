"""
main.py

Entry point for the Windows Event Log Analyzer.
"""

from pathlib import Path

from parser import load_events
from detector import run_all_detections
from reporter import build_report, save_report


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    log_path = project_root / "logs" / "sample_security_events.csv"
    output_path = project_root / "output" / "analysis_report.txt"

    print("[*] Windows Event Log Analyzer")
    print(f"[*] Loading log file: {log_path}")

    events = load_events(log_path)
    print(f"[*] Parsed events: {len(events)}")

    print("[*] Running detection rules...")
    findings = run_all_detections(events)
    print(f"[*] Suspicious findings: {len(findings)}")

    print("[*] Building report...")
    report = build_report(events, findings)

    save_report(report, output_path)

    print("\n" + report)
    print(f"\n[*] Report saved to: {output_path}")


if __name__ == "__main__":
    main()