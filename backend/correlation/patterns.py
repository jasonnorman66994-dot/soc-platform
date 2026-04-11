from __future__ import annotations

from typing import Any


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _event_types(events: list[dict[str, Any]]) -> list[str]:
    return [str(event.get("event_type", "")) for event in events]


def _contains_ordered(types: list[str], sequence: list[str]) -> bool:
    sequence_index = 0
    for item in types:
        if item == sequence[sequence_index]:
            sequence_index += 1
            if sequence_index == len(sequence):
                return True
    return False


def _max_severity(left: str, right: str) -> str:
    if SEVERITY_ORDER.get(left, 2) >= SEVERITY_ORDER.get(right, 2):
        return left
    return right


def detect_patterns(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect attack patterns from a timeline window of user events."""
    if not events:
        return []

    alerts: list[dict[str, Any]] = []
    event_types = _event_types(events)

    failed_count = sum(1 for item in event_types if item == "failed_login")
    has_login_success = "login_success" in event_types
    has_password_change = "password_change" in event_types
    has_privilege_change = "privilege_change" in event_types

    if failed_count >= 5 and has_login_success:
        severity = "high"
        if has_password_change or has_privilege_change:
            severity = _max_severity(severity, "critical")

        alerts.append(
            {
                "type": "account_takeover",
                "severity": severity,
                "description": "Multiple failed logins followed by success indicate potential account takeover",
                "mitre": ["T1110", "T1078"],
            }
        )

    locations = {item.get("location") for item in events if item.get("location")}
    if len(locations) > 1 and has_login_success:
        alerts.append(
            {
                "type": "impossible_travel",
                "severity": "high",
                "description": "Rapid location changes within login activity indicate impossible travel",
                "mitre": ["T1078", "T1021"],
            }
        )

    if _contains_ordered(event_types, ["login_success", "password_change", "privilege_change"]):
        alerts.append(
            {
                "type": "post_compromise_privilege_escalation",
                "severity": "critical",
                "description": "Successful login followed by credential and privilege changes",
                "mitre": ["T1098", "T1078", "T1484"],
            }
        )

    return alerts
