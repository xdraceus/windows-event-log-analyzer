"""
parser.py

Parses Windows Event Log CSV data into a cleaner, normalized structure
for later use by detector.py and reporter.py.

This module does not perform detection, alerting, or reporting.
"""

import csv
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


PLACEHOLDER_VALUES = {"", "-", "N/A", "NA", "null", "None"}


@dataclass
class WindowsEvent:
    record_id: Optional[int]
    timestamp: Optional[datetime]
    computer: Optional[str]
    channel: Optional[str]
    provider: Optional[str]
    event_id: Optional[int]
    severity: Optional[str]
    task_category: Optional[str]

    account_name: Optional[str]
    account_domain: Optional[str]
    target_user_name: Optional[str]
    target_domain_name: Optional[str]
    logon_type: Optional[int]
    ip_address: Optional[str]
    workstation_name: Optional[str]

    process_name: Optional[str]
    parent_process_name: Optional[str]
    command_line: Optional[str]

    object_name: Optional[str]
    service_name: Optional[str]
    share_name: Optional[str]

    status: Optional[str]
    sub_status: Optional[str]
    failure_reason: Optional[str]
    privilege_list: Optional[List[str]]
    group_name: Optional[str]
    subject_user_name: Optional[str]

    source_port: Optional[int]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    protocol: Optional[str]
    rule_name: Optional[str]

    message: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)

        if self.timestamp:
            data["timestamp"] = self.timestamp.isoformat(sep=" ")

        return data


def clean_value(value: Any) -> Optional[str]:
    if value is None:
        return None

    value = str(value).strip()

    if value in PLACEHOLDER_VALUES:
        return None

    return value


def to_int(value: Any) -> Optional[int]:
    value = clean_value(value)

    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def parse_timestamp(value: Any) -> Optional[datetime]:
    value = clean_value(value)

    if value is None:
        return None

    known_formats = [
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y %I:%M %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ]

    for fmt in known_formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None


def parse_privileges(value: Any) -> Optional[List[str]]:
    value = clean_value(value)

    if value is None:
        return None

    privileges = [item.strip() for item in value.split(";") if item.strip()]
    return privileges if privileges else None


def parse_row(row: Dict[str, Any]) -> WindowsEvent:
    return WindowsEvent(
        record_id=to_int(row.get("RecordID")),
        timestamp=parse_timestamp(row.get("Timestamp")),
        computer=clean_value(row.get("Computer")),
        channel=clean_value(row.get("Channel")),
        provider=clean_value(row.get("Provider")),
        event_id=to_int(row.get("EventID")),
        severity=clean_value(row.get("Severity")),
        task_category=clean_value(row.get("TaskCategory")),

        account_name=clean_value(row.get("AccountName")),
        account_domain=clean_value(row.get("AccountDomain")),
        target_user_name=clean_value(row.get("TargetUserName")),
        target_domain_name=clean_value(row.get("TargetDomainName")),
        logon_type=to_int(row.get("LogonType")),
        ip_address=clean_value(row.get("IpAddress")),
        workstation_name=clean_value(row.get("WorkstationName")),

        process_name=clean_value(row.get("ProcessName")),
        parent_process_name=clean_value(row.get("ParentProcessName")),
        command_line=clean_value(row.get("CommandLine")),

        object_name=clean_value(row.get("ObjectName")),
        service_name=clean_value(row.get("ServiceName")),
        share_name=clean_value(row.get("ShareName")),

        status=clean_value(row.get("Status")),
        sub_status=clean_value(row.get("SubStatus")),
        failure_reason=clean_value(row.get("FailureReason")),
        privilege_list=parse_privileges(row.get("PrivilegeList")),
        group_name=clean_value(row.get("GroupName")),
        subject_user_name=clean_value(row.get("SubjectUserName")),

        source_port=to_int(row.get("SourcePort")),
        destination_ip=clean_value(row.get("DestinationIp")),
        destination_port=to_int(row.get("DestinationPort")),
        protocol=clean_value(row.get("Protocol")),
        rule_name=clean_value(row.get("RuleName")),

        message=clean_value(row.get("Message")),
    )


def load_events(csv_path: str | Path) -> List[WindowsEvent]:
    csv_path = Path(csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(f"Log file not found: {csv_path}")

    events: List[WindowsEvent] = []

    with csv_path.open(mode="r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            events.append(parse_row(row))

    return events


def load_events_as_dicts(csv_path: str | Path) -> List[Dict[str, Any]]:
    return [event.to_dict() for event in load_events(csv_path)]


if __name__ == "__main__":
    sample_path = Path(__file__).resolve().parent.parent / "logs" / "sample_security_events.csv"

    parsed_events = load_events(sample_path)

    print(f"Parsed {len(parsed_events)} Windows Event Log records.")

    for event in parsed_events[:5]:
        print(event.to_dict())
