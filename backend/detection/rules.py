from typing import Any


def detect(event: Any) -> list[dict]:
    """Run baseline SOC detections against a normalized event payload."""
    event_type = event.get("event_type") if isinstance(event, dict) else getattr(event, "event_type", None)
    ip = event.get("ip") if isinstance(event, dict) else getattr(event, "ip", None)
    location = event.get("location") if isinstance(event, dict) else getattr(event, "location", None)

    alerts: list[dict] = []

    if event_type == "failed_login":
        alerts.append(
            {
                "type": "brute_force",
                "severity": "medium",
                "description": "Multiple failed logins indicate possible brute force activity",
            }
        )

    if location and location not in {"NG", "US"}:
        alerts.append(
            {
                "type": "impossible_travel",
                "severity": "high",
                "description": f"Login from unusual geography: {location}",
            }
        )

    if isinstance(ip, str) and ip.startswith("185."):
        alerts.append(
            {
                "type": "suspicious_ip",
                "severity": "high",
                "description": "Source IP matches suspicious range",
            }
        )

    return alerts
