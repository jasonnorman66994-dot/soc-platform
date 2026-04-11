import json
import os
from datetime import datetime, timezone
from typing import Any

import redis

REDIS_URL = os.getenv("SOC_CORE_REDIS_URL", "redis://redis:6379/0")
REDIS_CHANNEL = os.getenv("SOC_CORE_REALTIME_CHANNEL", "soc-core:alerts")

_redis_client: redis.Redis | None = None


def _get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


def publish_alert_update(
    event: dict[str, Any],
    alerts: list[dict[str, Any]],
    baseline_alerts: list[dict[str, Any]] | None = None,
    correlated_alerts: list[dict[str, Any]] | None = None,
) -> None:
    """Publish a structured real-time alert payload to the shared Redis channel."""
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "alerts": alerts,
        "baseline_alerts": baseline_alerts or [],
        "correlated_alerts": correlated_alerts or [],
    }
    _get_redis_client().publish(REDIS_CHANNEL, json.dumps(payload))
