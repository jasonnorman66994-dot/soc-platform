import json
import os
from datetime import datetime, timezone

from kafka import KafkaConsumer
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert

from api.realtime import publish_alert_update
from correlation.engine import build_incident, correlate
from detection.rules import detect
from storage.db import SessionLocal, engine
from storage.models import Alert, Base, Event, Incident

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_LOGS_TOPIC = os.getenv("KAFKA_LOGS_TOPIC", "logs")


def _parse_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    return datetime.now(timezone.utc)


def _merge_alerts(baseline_alerts: list[dict], correlated_alerts: list[dict]) -> list[dict]:
    merged: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for item in baseline_alerts:
        normalized = dict(item)
        normalized.setdefault("source", "detection")
        signature = (
            normalized.get("type", "detection"),
            normalized.get("severity", "medium"),
            normalized.get("source", "detection"),
        )
        if signature not in seen:
            seen.add(signature)
            merged.append(normalized)

    for item in correlated_alerts:
        normalized = dict(item)
        normalized.setdefault("source", "correlation")
        signature = (
            normalized.get("type", "detection"),
            normalized.get("severity", "medium"),
            normalized.get("source", "correlation"),
        )
        if signature not in seen:
            seen.add(signature)
            merged.append(normalized)

    return merged


def run() -> None:
    Base.metadata.create_all(bind=engine)

    consumer = KafkaConsumer(
        KAFKA_LOGS_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        group_id="soc-core-workers",
    )

    for message in consumer:
        event = message.value
        baseline_alerts = detect(event)
        correlated_alerts = correlate(event)
        alerts = _merge_alerts(baseline_alerts, correlated_alerts)

        with SessionLocal() as db:
            event_row = Event(
                source=event.get("source", "unknown"),
                event_type=event.get("event_type", "unknown"),
                user=event.get("user"),
                ip=event.get("ip"),
                location=event.get("location"),
                timestamp=_parse_timestamp(event.get("timestamp")),
                raw=event,
            )
            db.add(event_row)
            db.flush()

            for item in alerts:
                db.add(
                    Alert(
                        event_id=event_row.id,
                        alert_type=item.get("type", "detection"),
                        severity=item.get("severity", "medium"),
                        details=item,
                    )
                )

            incident_payload = build_incident(event, alerts)
            if incident_payload is not None:
                upsert_incident = insert(Incident).values(**incident_payload)
                db.execute(
                    upsert_incident.on_conflict_do_update(
                        index_elements=[Incident.fingerprint],
                        set_={
                            "last_seen": func.greatest(Incident.last_seen, incident_payload["last_seen"]),
                            "event_count": Incident.event_count + 1,
                            "alert_count": Incident.alert_count + len(alerts),
                            "severity": incident_payload["severity"],
                            "description": incident_payload["description"],
                            "context": incident_payload["context"],
                            "updated_at": datetime.now(timezone.utc),
                        },
                    )
                )

            db.commit()

        try:
            publish_alert_update(
                event=event,
                alerts=alerts,
                baseline_alerts=baseline_alerts,
                correlated_alerts=correlated_alerts,
            )
        except Exception:
            # Real-time streaming failures should not block ingestion and persistence.
            continue


if __name__ == "__main__":
    run()
