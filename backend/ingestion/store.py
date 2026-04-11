from collections import deque
from typing import Any

# In-memory FIFO store for Phase 1 ingestion prototype.
_EVENTS = deque(maxlen=5000)


def append_event(event: Any) -> int:
    _EVENTS.append(event)
    return len(_EVENTS)


def list_events() -> list[Any]:
    return list(_EVENTS)
