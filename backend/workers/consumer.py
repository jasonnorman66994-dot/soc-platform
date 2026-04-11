import json
import os
from datetime import datetime, timezone

from kafka import KafkaConsumer

from detection.rules import detect
from storage.db import SessionLocal, engine
from storage.models import Alert, Base, Event

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_LOGS_TOPIC = os.getenv("KAFKA_LOGS_TOPIC", "logs")


def _parse_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    return datetime.now(timezone.utc)


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
        alerts = detect(event)

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

            db.commit()


if __name__ == "__main__":
    run()
