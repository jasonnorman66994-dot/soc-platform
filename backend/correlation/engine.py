from __future__ import annotations

from collections import defaultdict
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from correlation.patterns import detect_patterns

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
WINDOW = timedelta(minutes=10)
user_sessions: dict[str, list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)


def _normalize_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return datetime.now(timezone.utc)
        if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    return datetime.now(timezone.utc)


def correlate(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Correlate recent user activity into sequence-based alerts within a fixed time window."""
    user = str(event.get("user") or "anonymous")
    event_time = _normalize_timestamp(event.get("timestamp"))

    user_sessions[user].append((event_time, event))

    user_sessions[user] = [
        (timestamp, item)
        for timestamp, item in user_sessions[user]
        if event_time - timestamp < WINDOW
    ]

    timeline = [item for _, item in sorted(user_sessions[user], key=lambda row: row[0])]
    return detect_patterns(timeline)


def _max_severity(alerts: list[dict]) -> str:
    if not alerts:
        return "medium"
    return max((item.get("severity", "medium") for item in alerts), key=lambda s: SEVERITY_ORDER.get(s, 2))


def build_incident(event: dict, alerts: list[dict]) -> dict | None:
    """Build a deterministic incident representation for event+alerts correlation."""
    if not alerts:
        return None

    event_type = event.get("event_type", "unknown")
    user = event.get("user") or "anonymous"
    ip = event.get("ip") or "unknown"
    location = event.get("location") or "unknown"
    timestamp = _normalize_timestamp(event.get("timestamp"))

    alert_types = sorted({item.get("type", "detection") for item in alerts})
    fingerprint_source = f"{user}|{ip}|{event_type}|{'-'.join(alert_types)}"
    fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()

    title = f"{event_type} correlation for {user}"
    description = f"Detected alerts linked to {event_type} from IP {ip}"

    return {
        "fingerprint": fingerprint,
        "status": "open",
        "severity": _max_severity(alerts),
        "title": title,
        "description": description,
        "first_seen": timestamp,
        "last_seen": timestamp,
        "event_count": 1,
        "alert_count": len(alerts),
        "context": {
            "user": user,
            "ip": ip,
            "event_type": event_type,
            "location": location,
            "alert_types": alert_types,
        },
    }
