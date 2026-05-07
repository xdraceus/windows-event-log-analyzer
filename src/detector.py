"""
detector.py

Detection logic for the Windows Event Log Analyzer.

This module consumes parsed WindowsEvent objects or dictionaries from parser.py
and returns structured findings for reporter.py.
"""

from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


RISKY_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

# These are additional triage events not already covered by dedicated rules.
SUSPICIOUS_EVENT_IDS = {
    1102: "Audit log cleared",
    4648: "Explicit credential logon",
    4698: "Scheduled task created",
    4726: "User account deleted",
    4732: "User added to security-enabled local group",
    4771: "Kerberos pre-authentication failed",
    4776: "NTLM authentication failed",
    7045: "New service installed",
}


@dataclass
class DetectionFinding:
    rule_id: str
    rule_name: str
    severity: str
    description: str
    event_count: int
    related_events: List[Dict[str, Any]]
    mitre_attack: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def event_to_dict(event: Any) -> Dict[str, Any]:
    if isinstance(event, dict):
        return event

    if hasattr(event, "to_dict"):
        return event.to_dict()

    if hasattr(event, "__dict__"):
        return vars(event)

    raise TypeError(f"Unsupported event type: {type(event)}")


def get_event_id(event: Dict[str, Any]) -> Optional[int]:
    value = event.get("event_id") or event.get("EventID")

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_field(event: Dict[str, Any], *names: str) -> Optional[Any]:
    for name in names:
        value = event.get(name)

        if value not in [None, "", "-", "N/A", []]:
            return value

    return None


def normalize_process_name(value: Optional[str]) -> Optional[str]:
    if not value:
        return None

    return str(value).replace("\\", "/").split("/")[-1].lower()


def command_line_contains_risky_process(command_line: Optional[str]) -> Optional[str]:
    if not command_line:
        return None

    command_line_lower = str(command_line).lower()

    for process in RISKY_PROCESSES:
        if process in command_line_lower:
            return process

    return None


def sort_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def sort_key(event: Dict[str, Any]):
        timestamp = get_field(event, "timestamp", "Timestamp")

        if isinstance(timestamp, datetime):
            return timestamp

        if isinstance(timestamp, str):
            for fmt in [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %H:%M",
                "%m/%d/%Y %I:%M %p",
            ]:
                try:
                    return datetime.strptime(timestamp, fmt)
                except ValueError:
                    pass

        return datetime.min

    return sorted(events, key=sort_key)


def detect_brute_force(events: List[Dict[str, Any]], threshold: int = 5) -> List[DetectionFinding]:
    findings = []
    grouped_failures = defaultdict(list)

    for event in events:
        if get_event_id(event) != 4625:
            continue

        source = get_field(event, "ip_address", "IpAddress") or get_field(
            event, "workstation_name", "WorkstationName"
        )

        if source:
            grouped_failures[source].append(event)

    for source, failures in grouped_failures.items():
        if len(failures) >= threshold:
            findings.append(
                DetectionFinding(
                    rule_id="DET-001",
                    rule_name="Potential Brute Force Activity",
                    severity="High",
                    description=f"{len(failures)} failed logons detected from source {source}.",
                    event_count=len(failures),
                    related_events=failures,
                    mitre_attack="T1110 - Brute Force",
                    recommendation="Review the source IP/workstation, validate whether activity is legitimate, and consider blocking the source or enforcing MFA/account lockout controls.",
                )
            )

    return findings


def detect_failed_then_success(events: List[Dict[str, Any]], min_failures: int = 2) -> List[DetectionFinding]:
    findings = []
    grouped_events = defaultdict(list)

    for event in events:
        if get_event_id(event) not in {4624, 4625}:
            continue

        user = get_field(event, "target_user_name", "TargetUserName", "account_name", "AccountName")
        source = get_field(event, "ip_address", "IpAddress") or get_field(
            event, "workstation_name", "WorkstationName"
        )

        if user and source:
            grouped_events[(user, source)].append(event)

    for (user, source), user_source_events in grouped_events.items():
        ordered = sort_events(user_source_events)

        failure_count = 0
        related = []

        for event in ordered:
            event_id = get_event_id(event)

            if event_id == 4625:
                failure_count += 1
                related.append(event)

            elif event_id == 4624:
                if failure_count >= min_failures:
                    related.append(event)

                    findings.append(
                        DetectionFinding(
                            rule_id="DET-002",
                            rule_name="Failed Logons Followed by Successful Logon",
                            severity="High",
                            description=f"User {user} had {failure_count} failed logons from {source}, followed by a successful logon.",
                            event_count=len(related),
                            related_events=related.copy(),
                            mitre_attack="T1110 - Brute Force / T1078 - Valid Accounts",
                            recommendation="Validate whether the successful logon was authorized. Review MFA logs, source reputation, session activity, and endpoint behavior after login.",
                        )
                    )

                failure_count = 0
                related = []

    return findings


def detect_admin_privilege_logon(events: List[Dict[str, Any]]) -> List[DetectionFinding]:
    findings = []

    for event in events:
        if get_event_id(event) == 4672:
            user = get_field(event, "account_name", "AccountName", "target_user_name", "TargetUserName")
            privileges = get_field(event, "privilege_list", "PrivilegeList")

            findings.append(
                DetectionFinding(
                    rule_id="DET-003",
                    rule_name="Admin Privilege Logon",
                    severity="Medium",
                    description=f"Special privileges were assigned to user {user}. Privileges: {privileges}",
                    event_count=1,
                    related_events=[event],
                    mitre_attack="T1078 - Valid Accounts",
                    recommendation="Confirm whether this privileged logon is expected. Review the account, source host, logon type, and privilege list.",
                )
            )

    return findings


def detect_account_lockout(events: List[Dict[str, Any]]) -> List[DetectionFinding]:
    findings = []

    for event in events:
        if get_event_id(event) == 4740:
            user = get_field(event, "target_user_name", "TargetUserName", "account_name", "AccountName")
            source = get_field(event, "ip_address", "IpAddress") or get_field(
                event, "workstation_name", "WorkstationName"
            )

            findings.append(
                DetectionFinding(
                    rule_id="DET-004",
                    rule_name="Account Lockout",
                    severity="Medium",
                    description=f"Account lockout detected for user {user} from source {source}.",
                    event_count=1,
                    related_events=[event],
                    mitre_attack="T1110 - Brute Force",
                    recommendation="Review prior failed logons for the account and source. Determine whether this was user error, password spraying, or brute force activity.",
                )
            )

    return findings


def detect_account_creation(events: List[Dict[str, Any]]) -> List[DetectionFinding]:
    findings = []

    for event in events:
        if get_event_id(event) == 4720:
            new_user = get_field(event, "target_user_name", "TargetUserName")
            creator = get_field(event, "subject_user_name", "SubjectUserName", "account_name", "AccountName")

            findings.append(
                DetectionFinding(
                    rule_id="DET-005",
                    rule_name="Suspicious Account Creation",
                    severity="High",
                    description=f"New user account {new_user} was created by {creator}.",
                    event_count=1,
                    related_events=[event],
                    mitre_attack="T1136 - Create Account",
                    recommendation="Validate the account creation request, creator identity, ticket/change record, and group memberships assigned after creation.",
                )
            )

    return findings


def detect_risky_process_execution(events: List[Dict[str, Any]]) -> List[DetectionFinding]:
    findings = []

    for event in events:
        if get_event_id(event) != 4688:
            continue

        process_name = normalize_process_name(get_field(event, "process_name", "ProcessName"))
        command_line = get_field(event, "command_line", "CommandLine")
        command_line_process = command_line_contains_risky_process(command_line)

        if process_name in RISKY_PROCESSES or command_line_process:
            matched_process = process_name if process_name in RISKY_PROCESSES else command_line_process
            user = get_field(event, "account_name", "AccountName", "subject_user_name", "SubjectUserName")

            findings.append(
                DetectionFinding(
                    rule_id="DET-006",
                    rule_name="Risky Process Execution",
                    severity="Medium",
                    description=f"Risky process activity detected: {matched_process} by {user}.",
                    event_count=1,
                    related_events=[event],
                    mitre_attack="T1059 - Command and Scripting Interpreter",
                    recommendation=f"Review command line usage, parent process, and execution context. Command line: {command_line}",
                )
            )

    return findings


def detect_other_triage_events(events: List[Dict[str, Any]]) -> List[DetectionFinding]:
    findings = []

    for event in events:
        event_id = get_event_id(event)

        if event_id not in SUSPICIOUS_EVENT_IDS:
            continue

        rule_name = SUSPICIOUS_EVENT_IDS[event_id]
        severity = "Medium"

        if event_id in {1102, 4726, 7045}:
            severity = "High"

        findings.append(
            DetectionFinding(
                rule_id=f"DET-EID-{event_id}",
                rule_name=rule_name,
                severity=severity,
                description=f"Potentially suspicious or triage-worthy event detected: {rule_name}.",
                event_count=1,
                related_events=[event],
                mitre_attack=map_event_to_mitre(event_id),
                recommendation="Review the full event context, associated user, source system, and nearby activity before closing as benign.",
            )
        )

    return findings


def map_event_to_mitre(event_id: int) -> Optional[str]:
    mapping = {
        1102: "T1070 - Indicator Removal",
        4648: "T1078 - Valid Accounts",
        4698: "T1053 - Scheduled Task/Job",
        4720: "T1136 - Create Account",
        4726: "T1531 - Account Access Removal",
        4732: "T1098 - Account Manipulation",
        4740: "T1110 - Brute Force",
        4771: "T1110 - Brute Force",
        4776: "T1110 - Brute Force",
        7045: "T1543 - Create or Modify System Process",
    }

    return mapping.get(event_id)


def run_all_detections(events: List[Any]) -> List[DetectionFinding]:
    normalized_events = [event_to_dict(event) for event in events]

    findings = []
    findings.extend(detect_brute_force(normalized_events))
    findings.extend(detect_failed_then_success(normalized_events))
    findings.extend(detect_admin_privilege_logon(normalized_events))
    findings.extend(detect_account_lockout(normalized_events))
    findings.extend(detect_account_creation(normalized_events))
    findings.extend(detect_risky_process_execution(normalized_events))
    findings.extend(detect_other_triage_events(normalized_events))

    return findings


def run_all_detections_as_dicts(events: List[Any]) -> List[Dict[str, Any]]:
    return [finding.to_dict() for finding in run_all_detections(events)]


if __name__ == "__main__":
    from pathlib import Path
    from parser import load_events

    sample_path = Path(__file__).resolve().parent.parent / "logs" / "sample_security_events.csv"

    parsed_events = load_events(sample_path)
    findings = run_all_detections(parsed_events)

    print(f"Generated {len(findings)} detection findings.")

    for finding in findings:
        print(f"[{finding.severity}] {finding.rule_name}: {finding.description}")

