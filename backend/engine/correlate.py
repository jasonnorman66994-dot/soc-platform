from datetime import datetime, timedelta, timezone


def correlate(events: list[dict], alerts: list[dict]) -> dict | None:
    if not alerts:
        return None

    now = datetime.now(timezone.utc)
    recent = [e for e in events if _is_recent(e, now)]
    users = {e.get("user_id") for e in recent if e.get("user_id")}
    ips = {e.get("ip") for e in recent if e.get("ip")}

    severity = "high"
    if any(a.get("severity") == "critical" for a in alerts):
        severity = "critical"

    return {
        "entity": next(iter(users), "unknown"),
        "severity": severity,
        "status": "open",
        "story": {
            "users": list(users),
            "ips": list(ips),
            "stages": [e.get("event_type") or e.get("type") for e in recent[-6:]],
        },
    }


def _is_recent(event: dict, now: datetime) -> bool:
    ts = event.get("timestamp")
    if not ts:
        return False
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (now - dt) <= timedelta(minutes=30)
