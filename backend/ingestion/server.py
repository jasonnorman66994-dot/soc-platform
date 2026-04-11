from datetime import datetime
import json
import os

from fastapi import FastAPI
from pydantic import BaseModel

from detection.rules import detect
from ingestion.store import append_event, list_events

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


app = FastAPI(title="SOC Ingestion Service", version="0.1.0")


class LogEvent(BaseModel):
    source: str
    event_type: str
    user: str | None = None
    ip: str | None = None
    timestamp: datetime
    raw: dict


REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
_stream_client = redis.Redis.from_url(REDIS_URL, decode_responses=True) if redis else None


@app.post("/ingest")
def ingest(event: LogEvent):
    payload = event.model_dump(mode="json")
    alerts = detect(payload)
    count = append_event(payload)

    if _stream_client:
        try:
            _stream_client.xadd("soc:ingestion:events", {"event": json.dumps(payload)})
        except Exception:
            # Keep ingestion available even if stream backend is unavailable.
            pass

    return {"status": "received", "count": count, "alerts": alerts}


@app.get("/events")
def get_events():
    return list_events()
