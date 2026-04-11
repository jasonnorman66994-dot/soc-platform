from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    return datetime.now(timezone.utc)


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
    description = f"Detected {len(alerts)} alert(s) linked to {event_type} from IP {ip}"

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
