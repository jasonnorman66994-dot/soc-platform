from typing import Any


def detect(event: Any) -> list[str]:
    """Return simple rule-based alerts for an incoming event payload."""
    event_type = getattr(event, "event_type", None) or event.get("event_type")
    ip = getattr(event, "ip", None) or event.get("ip")

    alerts: list[str] = []
    if event_type == "failed_login":
        alerts.append("Potential brute force attempt")

    if isinstance(ip, str) and ip.startswith("185."):
        alerts.append("Suspicious IP range")

    return alerts
