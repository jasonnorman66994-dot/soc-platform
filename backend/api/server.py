from datetime import datetime
import asyncio
import json
import os

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import redis.asyncio as redis_async

from ingestion.producer import send_event
from storage.db import SessionLocal
from storage.models import Alert, Event, Incident

app = FastAPI(title="SOC Core API", version="0.2.0")

SOC_CORE_REDIS_URL = os.getenv("SOC_CORE_REDIS_URL", "redis://redis:6379/0")
SOC_CORE_REALTIME_CHANNEL = os.getenv("SOC_CORE_REALTIME_CHANNEL", "soc-core:alerts")


class LogEvent(BaseModel):
    source: str
    event_type: str
    user: str | None = None
    ip: str | None = None
    location: str | None = None
    timestamp: datetime
    raw: dict


@app.get("/health")
def health():
    return {"status": "ok", "service": "soc-core-api"}


@app.post("/ingest")
def ingest(event: LogEvent):
    payload = event.model_dump(mode="json")
    try:
        send_event(payload)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Failed to queue event: {exc}")
    return {"status": "queued"}


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    redis_client = redis_async.from_url(SOC_CORE_REDIS_URL, decode_responses=True)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(SOC_CORE_REALTIME_CHANNEL)

    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=10.0)
            if message and message.get("type") == "message":
                raw = message.get("data")
                if isinstance(raw, str):
                    await websocket.send_text(raw)
                else:
                    await websocket.send_text(json.dumps(raw))
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(SOC_CORE_REALTIME_CHANNEL)
        await pubsub.close()
        await redis_client.close()


@app.get("/events")
def get_events(limit: int = 200):
    safe_limit = max(1, min(limit, 1000))
    with SessionLocal() as db:
        rows = db.query(Event).order_by(Event.id.desc()).limit(safe_limit).all()
        return [
            {
                "id": row.id,
                "source": row.source,
                "event_type": row.event_type,
                "user": row.user,
                "ip": row.ip,
                "location": row.location,
                "timestamp": row.timestamp.isoformat(),
                "raw": row.raw,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]


@app.get("/alerts")
def get_alerts(limit: int = 200):
    safe_limit = max(1, min(limit, 1000))
    with SessionLocal() as db:
        rows = db.query(Alert).order_by(Alert.id.desc()).limit(safe_limit).all()
        return [
            {
                "id": row.id,
                "event_id": row.event_id,
                "type": row.alert_type,
                "severity": row.severity,
                "details": row.details,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]


@app.get("/incidents")
def get_incidents(limit: int = 200):
    safe_limit = max(1, min(limit, 1000))
    with SessionLocal() as db:
        rows = db.query(Incident).order_by(Incident.last_seen.desc()).limit(safe_limit).all()
        return [
            {
                "id": row.id,
                "fingerprint": row.fingerprint,
                "status": row.status,
                "severity": row.severity,
                "title": row.title,
                "description": row.description,
                "first_seen": row.first_seen.isoformat(),
                "last_seen": row.last_seen.isoformat(),
                "event_count": row.event_count,
                "alert_count": row.alert_count,
                "context": row.context,
                "created_at": row.created_at.isoformat(),
                "updated_at": row.updated_at.isoformat(),
            }
            for row in rows
        ]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    with SessionLocal() as db:
        row = db.query(Incident).filter(Incident.id == incident_id).first()
        if row is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {
            "id": row.id,
            "fingerprint": row.fingerprint,
            "status": row.status,
            "severity": row.severity,
            "title": row.title,
            "description": row.description,
            "first_seen": row.first_seen.isoformat(),
            "last_seen": row.last_seen.isoformat(),
            "event_count": row.event_count,
            "alert_count": row.alert_count,
            "context": row.context,
            "created_at": row.created_at.isoformat(),
            "updated_at": row.updated_at.isoformat(),
        }
