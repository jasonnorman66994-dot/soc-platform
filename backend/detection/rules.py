from typing import Any


import os
from functools import lru_cache

_DEFAULT_ALLOWED_LOCATIONS = "US,GB,CA,AU,DE,FR,NL,JP,SG,NG"


@lru_cache(maxsize=1)
def _allowed_locations() -> frozenset[str]:
    """Return the set of expected country codes (ISO 3166-1 alpha-2).

    Override via comma-separated ALLOWED_LOCATIONS env var, e.g.::

        ALLOWED_LOCATIONS=US,CA,GB
    """
    raw = os.getenv("ALLOWED_LOCATIONS", _DEFAULT_ALLOWED_LOCATIONS)
    return frozenset(code.strip().upper() for code in raw.split(",") if code.strip())


def detect(event: Any) -> list[dict]:
    """Run baseline SOC detections against a normalized event payload."""
    event_type = event.get("event_type") if isinstance(event, dict) else getattr(event, "event_type", None)
    ip = event.get("ip") if isinstance(event, dict) else getattr(event, "ip", None)
    location = event.get("location") if isinstance(event, dict) else getattr(event, "location", None)
    if isinstance(location, str):
        location = location.strip().upper()

    alerts: list[dict] = []

    if event_type == "failed_login":
        alerts.append(
            {
                "type": "brute_force",
                "severity": "medium",
                "description": "Multiple failed logins indicate possible brute force activity",
            }
        )

    if location and location not in _allowed_locations():
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
