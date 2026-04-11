from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import math
from typing import Any


SEVERITY_WEIGHT = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    return datetime.now(timezone.utc)


def _safe_std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def compute_ueba_summary(events: list[dict], alerts: list[dict], top_n: int = 10) -> dict:
    """Compute UEBA-style user behavior analytics from event and alert streams."""
    if not events:
        return {
            "total_users": 0,
            "high_risk_users": 0,
            "users": [],
            "event_type_distribution": {},
        }

    event_by_id: dict[int, dict] = {}
    user_event_count: Counter = Counter()
    user_unique_ips: dict[str, set[str]] = defaultdict(set)
    user_event_types: dict[str, Counter] = defaultdict(Counter)
    user_geo_swings: Counter = Counter()

    for event in events:
        event_id = event.get("id")
        if isinstance(event_id, int):
            event_by_id[event_id] = event

        user = event.get("user_id") or "unknown"
        event_type = event.get("type") or "unknown"
        raw = event.get("raw") or {}

        user_event_count[user] += 1
        user_event_types[user][event_type] += 1

        ip = raw.get("ip") or event.get("ip")
        if ip:
            user_unique_ips[user].add(str(ip))

        if raw.get("geo_mismatch"):
            user_geo_swings[user] += 1

    user_alert_score: Counter = Counter()
    user_alert_count: Counter = Counter()

    for alert in alerts:
        event_id = alert.get("event_id")
        severity = str(alert.get("severity") or "medium").lower()
        event = event_by_id.get(event_id)
        user = (event or {}).get("user_id") or "unknown"
        user_alert_score[user] += SEVERITY_WEIGHT.get(severity, 1.0)
        user_alert_count[user] += 1

    global_types = Counter(event.get("type") or "unknown" for event in events)

    users = []
    for user, event_count in user_event_count.items():
        unique_ip_count = len(user_unique_ips.get(user, set()))
        diversity_score = min(20.0, float(len(user_event_types[user]) * 3.0))
        ip_churn_score = min(20.0, float(max(unique_ip_count - 1, 0) * 4.0))
        geo_score = min(20.0, float(user_geo_swings[user] * 5.0))
        alert_score = min(40.0, float(user_alert_score[user] * 5.0))

        behavior_risk_score = round(min(100.0, diversity_score + ip_churn_score + geo_score + alert_score), 2)
        risk_band = "low"
        if behavior_risk_score >= 75:
            risk_band = "critical"
        elif behavior_risk_score >= 55:
            risk_band = "high"
        elif behavior_risk_score >= 35:
            risk_band = "medium"

        users.append(
            {
                "user_id": user,
                "event_count": event_count,
                "alert_count": int(user_alert_count[user]),
                "unique_ip_count": unique_ip_count,
                "geo_mismatch_count": int(user_geo_swings[user]),
                "top_event_types": user_event_types[user].most_common(5),
                "behavior_risk_score": behavior_risk_score,
                "risk_band": risk_band,
            }
        )

    users.sort(key=lambda item: item["behavior_risk_score"], reverse=True)
    high_risk_users = len([u for u in users if u["risk_band"] in {"high", "critical"}])

    return {
        "total_users": len(users),
        "high_risk_users": high_risk_users,
        "users": users[: max(1, top_n)],
        "event_type_distribution": dict(global_types),
    }


def detect_ml_anomalies(events: list[dict], min_points: int = 6) -> dict:
    """Detect anomalies with lightweight statistical scoring (safe, deterministic ML-style)."""
    if not events:
        return {"total_anomalies": 0, "anomalies": []}

    events_by_hour: Counter = Counter()
    user_hour_counter: dict[str, Counter] = defaultdict(Counter)

    for event in events:
        ts = _parse_ts(event.get("timestamp"))
        bucket = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        user = event.get("user_id") or "unknown"

        events_by_hour[bucket] += 1
        user_hour_counter[user][bucket] += 1

    hour_values = [float(v) for v in events_by_hour.values()]
    mean = sum(hour_values) / len(hour_values)
    std = _safe_std(hour_values)

    anomalies: list[dict] = []

    for hour, count in events_by_hour.items():
        if std <= 0:
            break
        z = (float(count) - mean) / std
        if z >= 2.0 and count >= min_points:
            anomalies.append(
                {
                    "kind": "volume_spike",
                    "hour": hour,
                    "value": int(count),
                    "baseline_mean": round(mean, 3),
                    "z_score": round(z, 3),
                    "severity": "high" if z >= 3 else "medium",
                }
            )

    user_totals = {user: sum(counter.values()) for user, counter in user_hour_counter.items()}
    user_values = [float(v) for v in user_totals.values()]
    user_mean = sum(user_values) / len(user_values)
    user_std = _safe_std(user_values)

    if user_std > 0:
        for user, total in user_totals.items():
            z = (float(total) - user_mean) / user_std
            if z >= 2.2 and total >= min_points:
                anomalies.append(
                    {
                        "kind": "user_activity_outlier",
                        "user_id": user,
                        "value": int(total),
                        "baseline_mean": round(user_mean, 3),
                        "z_score": round(z, 3),
                        "severity": "critical" if z >= 3 else "high",
                    }
                )

    anomalies.sort(key=lambda item: item.get("z_score", 0), reverse=True)
    return {
        "total_anomalies": len(anomalies),
        "anomalies": anomalies[:50],
    }


def build_advanced_analytics(events: list[dict], alerts: list[dict], incidents: list[dict]) -> dict:
    ueba = compute_ueba_summary(events, alerts, top_n=15)
    ml = detect_ml_anomalies(events)

    severity_dist = Counter((item.get("severity") or "unknown") for item in alerts)
    incident_status_dist = Counter((item.get("status") or "unknown") for item in incidents)

    return {
        "overview": {
            "event_count": len(events),
            "alert_count": len(alerts),
            "incident_count": len(incidents),
        },
        "distributions": {
            "alert_severity": dict(severity_dist),
            "incident_status": dict(incident_status_dist),
        },
        "ueba": ueba,
        "ml": ml,
    }
