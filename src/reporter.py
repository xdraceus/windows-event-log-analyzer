"""
reporter.py

Creates readable Windows Event Log analysis reports from parsed events
and detection findings.

This module does not parse logs or perform detection logic.
"""

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def finding_to_dict(finding: Any) -> Dict[str, Any]:
    """Convert DetectionFinding objects or dictionaries into dictionaries."""
    if isinstance(finding, dict):
        return finding

    if hasattr(finding, "to_dict"):
        return finding.to_dict()

    if hasattr(finding, "__dict__"):
        return vars(finding)

    raise TypeError(f"Unsupported finding type: {type(finding)}")


def event_to_dict(event: Any) -> Dict[str, Any]:
    """Convert WindowsEvent objects or dictionaries into dictionaries."""
    if isinstance(event, dict):
        return event

    if hasattr(event, "to_dict"):
        return event.to_dict()

    if hasattr(event, "__dict__"):
        return vars(event)

    raise TypeError(f"Unsupported event type: {type(event)}")


def get_field(data: Dict[str, Any], *names: str) -> Optional[Any]:
    """Safely retrieve the first available field from possible key names."""
    for name in names:
        value = data.get(name)

        if value not in [None, "", "-", "N/A", []]:
            return value

    return None


def get_event_id(event: Dict[str, Any]) -> Optional[int]:
    """Safely retrieve an event ID from an event dictionary."""
    value = get_field(event, "event_id", "EventID")

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def unique_values(values: Iterable[Any]) -> List[Any]:
    """Return unique values while preserving order."""
    seen = set()
    unique = []

    for value in values:
        if value in [None, "", "-", "N/A", []]:
            continue

        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)

        if value not in seen:
            seen.add(value)
            unique.append(value)

    return unique


def extract_source(related_events: List[Dict[str, Any]]) -> str:
    """Extract the best source identifier from related events."""
    sources = unique_values(
        get_field(event, "ip_address", "IpAddress")
        or get_field(event, "workstation_name", "WorkstationName")
        or get_field(event, "computer", "Computer")
        for event in related_events
    )

    return str(sources[0]) if sources else "Unknown Source"


def extract_target_user(related_events: List[Dict[str, Any]]) -> str:
    """Extract the best target user value from related events."""
    users = unique_values(
        get_field(event, "target_user_name", "TargetUserName")
        or get_field(event, "account_name", "AccountName")
        or get_field(event, "subject_user_name", "SubjectUserName")
        for event in related_events
    )

    return str(users[0]) if users else "Unknown User"


def extract_related_event_ids(related_events: List[Dict[str, Any]]) -> str:
    """Extract related event IDs as a comma-separated string."""
    event_ids = unique_values(get_event_id(event) for event in related_events)
    return ", ".join(str(event_id) for event_id in event_ids) if event_ids else "Unknown"


def extract_processes(related_events: List[Dict[str, Any]]) -> Optional[str]:
    """Extract process names from related events when available."""
    processes = unique_values(
        get_field(event, "process_name", "ProcessName") for event in related_events
    )

    return ", ".join(str(process) for process in processes) if processes else None


def extract_command_lines(related_events: List[Dict[str, Any]]) -> Optional[str]:
    """Extract command lines from related events when available."""
    commands = unique_values(
        get_field(event, "command_line", "CommandLine") for event in related_events
    )

    return " | ".join(str(command) for command in commands) if commands else None


def format_finding(finding: Dict[str, Any]) -> str:
    """Format a single detection finding for the report."""
    related_events = [
        event_to_dict(event) for event in finding.get("related_events", [])
    ]

    source = extract_source(related_events)
    target_user = extract_target_user(related_events)
    related_event_ids = extract_related_event_ids(related_events)

    severity = finding.get("severity", "Unknown")
    alert = finding.get("rule_name", "Unknown Alert")
    description = finding.get("description")
    mitre_attack = finding.get("mitre_attack")
    recommendation = finding.get("recommendation")

    process_names = extract_processes(related_events)
    command_lines = extract_command_lines(related_events)

    lines = [
        f"- {source}",
        f"  Severity: {severity}",
        f"  Alert: {alert}",
        f"  Related Event IDs: {related_event_ids}",
        f"  Target User: {target_user}",
    ]

    if description:
        lines.append(f"  Description: {description}")

    if process_names:
        lines.append(f"  Process: {process_names}")

    if command_lines:
        lines.append(f"  Command Line: {command_lines}")

    if mitre_attack:
        lines.append(f"  MITRE ATT&CK: {mitre_attack}")

    if recommendation:
        lines.append(f"  Recommendation: {recommendation}")

    return "\n".join(lines)


def build_report(events: List[Any], findings: List[Any]) -> str:
    """
    Build the complete Windows Event Log analysis report.

    Args:
        events: Parsed Windows events.
        findings: Detection findings from detector.py.

    Returns:
        A formatted string report.
    """
    normalized_findings = [finding_to_dict(finding) for finding in findings]

    lines = [
        "==== Windows Event Log Analysis Report ====",
        "",
        "Summary:",
        f"- Total parsed events: {len(events)}",
        f"- Suspicious findings: {len(normalized_findings)}",
        "",
        "Findings:",
    ]

    if not normalized_findings:
        lines.append("- No suspicious findings detected.")
        return "\n".join(lines)

    for finding in normalized_findings:
        lines.append(format_finding(finding))
        lines.append("")

    return "\n".join(lines).rstrip()


def save_report(report: str, output_path: str | Path) -> Path:
    """
    Save a text report to disk.

    Args:
        report: Report string.
        output_path: Destination file path.

    Returns:
        Path to the saved report.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(report, encoding="utf-8")

    return output_path


def build_and_save_report(
    events: List[Any],
    findings: List[Any],
    output_path: str | Path,
) -> Path:
    """
    Build and save a Windows Event Log report.

    Args:
        events: Parsed Windows events.
        findings: Detection findings.
        output_path: Destination report path.

    Returns:
        Path to the saved report.
    """
    report = build_report(events, findings)
    return save_report(report, output_path)


if __name__ == "__main__":
    from parser import load_events
    from detector import run_all_detections

    project_root = Path(__file__).resolve().parent.parent
    sample_path = project_root / "logs" / "sample_security_events.csv"
    output_path = project_root / "output" / "analysis_report.txt"

    parsed_events = load_events(sample_path)
    detection_findings = run_all_detections(parsed_events)

    final_report = build_report(parsed_events, detection_findings)
    save_report(final_report, output_path)

    print(final_report)
    print(f"\nReport saved to: {output_path}")