import json
import os

try:
    from kafka import KafkaProducer
except Exception:  # pragma: no cover
    KafkaProducer = None  # type: ignore[assignment,misc]

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_LOGS_TOPIC = os.getenv("KAFKA_LOGS_TOPIC", "logs")

_producer: KafkaProducer | None = None


def _get_producer() -> KafkaProducer:
    global _producer
    if KafkaProducer is None:
        raise RuntimeError("Kafka client library is unavailable in this Python environment")
    if _producer is None:
        _producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
    return _producer


def send_event(event: dict) -> None:
    producer = _get_producer()
    producer.send(KAFKA_LOGS_TOPIC, event)
    producer.flush(timeout=5)
