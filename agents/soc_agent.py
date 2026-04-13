#!/usr/bin/env python3
"""
SOC Distributed Agent — lightweight endpoint telemetry collector.

Captures process starts and network connections, streams to the
Command Center via POST /telemetry/ingest.

Usage:
    python soc_agent.py \
        --api-url http://localhost:8000 \
        --api-key YOUR_API_KEY \
        --tenant-id YOUR_TENANT_ID \
        --interval 15

Requires: psutil, requests
    pip install psutil requests
"""

import argparse
import logging
import os
import platform
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("soc-agent")

AGENT_ID = os.getenv("SOC_AGENT_ID", f"agent-{uuid.uuid4().hex[:8]}")
HOSTNAME = platform.node()
DEFAULT_BATCH_SIZE = int(os.getenv("SOC_AGENT_BATCH_SIZE", "100"))
DEFAULT_MAX_RETRIES = int(os.getenv("SOC_AGENT_MAX_RETRIES", "2"))
DEFAULT_RETRY_BASE_DELAY = float(os.getenv("SOC_AGENT_RETRY_BASE_DELAY", "1.0"))
DEFAULT_RETRY_MAX_DELAY = float(os.getenv("SOC_AGENT_RETRY_MAX_DELAY", "8.0"))

TelemetryEvent = dict[str, Any]
RequestHeaders = dict[str, str]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iter_batches(events: list[TelemetryEvent], batch_size: int = DEFAULT_BATCH_SIZE) -> Iterable[list[TelemetryEvent]]:
    for start in range(0, len(events), batch_size):
        yield events[start:start + batch_size]


def flush_event_batches(
    api_url: str,
    headers: RequestHeaders,
    events: list[TelemetryEvent],
    batch_size: int,
    send_func: Callable[[str, RequestHeaders, list[TelemetryEvent]], bool],
    max_retries: int,
    retry_base_delay: float,
    retry_max_delay: float,
    sleep_func: Callable[[float], None] = time.sleep,
) -> tuple[int, int]:
    """Send all events in bounded batches with retry/backoff, returning (sent, failed)."""
    sent_batches = 0
    failed_batches = 0

    for batch in _iter_batches(events, batch_size):
        attempt = 0
        while True:
            if send_func(api_url, headers, batch):
                sent_batches += 1
                break

            if attempt >= max_retries:
                failed_batches += 1
                break

            delay = min(retry_max_delay, retry_base_delay * (2 ** attempt))
            attempt += 1
            log.warning(
                "Retrying failed batch (%d/%d) in %.1fs.",
                attempt,
                max_retries,
                delay,
            )
            sleep_func(delay)

    return sent_batches, failed_batches


def collect_process_events(known_pids: set[int]) -> tuple[list[TelemetryEvent], set[int]]:
    """Return new process-start events since last poll."""
    if psutil is None:
        return [], known_pids
    events: list[TelemetryEvent] = []
    current_pids: set[int] = set()
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            info = proc.as_dict(attrs=["pid", "name", "create_time"])
            pid = info["pid"]
            current_pids.add(pid)
            if pid not in known_pids:
                events.append({
                    "agent_id": AGENT_ID,
                    "hostname": HOSTNAME,
                    "event_type": "process_start",
                    "timestamp": _now_iso(),
                    "pid": pid,
                    "process_name": info.get("name") or "unknown",
                    "remote_ip": None,
                    "remote_port": None,
                    "local_port": None,
                    "meta": {},
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return events, current_pids


def collect_network_events() -> list[TelemetryEvent]:
    """Return network connection events (outbound ESTABLISHED)."""
    if psutil is None:
        return []
    events: list[TelemetryEvent] = []
    seen = set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != "ESTABLISHED":
            continue
        if not conn.raddr:
            continue
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        local_port = conn.laddr.port if conn.laddr else None
        key = (remote_ip, remote_port, local_port, conn.pid)
        if key in seen:
            continue
        seen.add(key)

        proc_name = "unknown"
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        events.append({
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "event_type": "network_connection",
            "timestamp": _now_iso(),
            "pid": conn.pid,
            "process_name": proc_name,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local_port": local_port,
            "meta": {},
        })
    return events


def send_heartbeat(api_url: str, headers: RequestHeaders) -> None:
    """Send a heartbeat event so the Command Center knows we're alive."""
    if requests is None:
        return
    payload: list[TelemetryEvent] = [{
        "agent_id": AGENT_ID,
        "hostname": HOSTNAME,
        "event_type": "heartbeat",
        "timestamp": _now_iso(),
        "pid": os.getpid(),
        "process_name": "soc_agent",
        "remote_ip": None,
        "remote_port": None,
        "local_port": None,
        "meta": {"platform": platform.system(), "version": "1.0.0"},
    }]
    try:
        resp = requests.post(
            f"{api_url}/telemetry/ingest", json=payload, headers=headers, timeout=10
        )
        resp.raise_for_status()
        log.info("Heartbeat sent — agents active: %s", resp.json().get("agents_active"))
    except requests.exceptions.Timeout:
        log.warning("Heartbeat timed out.")
    except requests.exceptions.ConnectionError as exc:
        log.warning("Heartbeat connection error: %s", exc)
    except requests.exceptions.HTTPError as exc:
        log.warning("Heartbeat HTTP error: %s", exc)
    except requests.exceptions.RequestException as exc:
        log.warning("Heartbeat failed: %s", exc)


def send_events(api_url: str, headers: RequestHeaders, events: list[TelemetryEvent]) -> bool:
    """Post collected events to the telemetry ingest endpoint."""
    if requests is None or not events:
        return True
    try:
        resp = requests.post(f"{api_url}/telemetry/ingest", json=events, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        log.info(
            "Sent %d events — threat matches: %s",
            data.get("processed", 0),
            data.get("threat_matches", 0),
        )
        return True
    except requests.exceptions.Timeout:
        log.warning("Send timed out for %d events.", len(events))
    except requests.exceptions.ConnectionError as exc:
        log.warning("Connection error sending %d events: %s", len(events), exc)
    except requests.exceptions.HTTPError as exc:
        log.warning("HTTP error sending %d events: %s", len(events), exc)
    except requests.exceptions.RequestException as exc:
        log.warning("Failed to send %d events: %s", len(events), exc)
    return False


def main():
    parser = argparse.ArgumentParser(description="SOC Distributed Agent")
    parser.add_argument("--api-url", default=os.getenv("SOC_API_URL", "http://localhost:8000"), help="Command Center API URL")
    parser.add_argument("--api-key", default=os.getenv("SOC_API_KEY", ""), help="API key for authentication")
    parser.add_argument("--tenant-id", default=os.getenv("SOC_TENANT_ID", ""), help="Tenant ID for authentication")
    parser.add_argument("--interval", type=int, default=int(os.getenv("SOC_AGENT_INTERVAL", "15")), help="Poll interval in seconds")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Max telemetry events per ingest request")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES, help="Retry attempts per failed telemetry batch")
    parser.add_argument("--retry-base-delay", type=float, default=DEFAULT_RETRY_BASE_DELAY, help="Initial retry delay in seconds")
    parser.add_argument("--retry-max-delay", type=float, default=DEFAULT_RETRY_MAX_DELAY, help="Upper bound for retry delay in seconds")
    args = parser.parse_args()

    if requests is None:
        log.error("requests library is required: pip install requests")
        return
    if psutil is None:
        log.warning("psutil not installed — telemetry will be limited. pip install psutil")
    if not args.api_key.strip():
        log.error("API key is required. Provide --api-key or set SOC_API_KEY.")
        return
    if not args.tenant_id.strip():
        log.error("Tenant ID is required. Provide --tenant-id or set SOC_TENANT_ID.")
        return
    if args.batch_size <= 0:
        log.error("Batch size must be greater than 0.")
        return
    if args.max_retries < 0:
        log.error("Max retries must be 0 or greater.")
        return
    if args.retry_base_delay <= 0 or args.retry_max_delay <= 0:
        log.error("Retry delays must be greater than 0.")
        return
    if args.retry_base_delay > args.retry_max_delay:
        log.error("Retry base delay cannot exceed retry max delay.")
        return

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": args.api_key,
        "X-Tenant-Id": args.tenant_id,
    }

    log.info("SOC Agent %s starting on %s — polling every %ds", AGENT_ID, HOSTNAME, args.interval)
    log.info("Reporting to %s", args.api_url)

    known_pids: set[int] = set()
    heartbeat_counter = 0

    while True:
        try:
            # Heartbeat every 4 cycles
            if heartbeat_counter % 4 == 0:
                send_heartbeat(args.api_url, headers)

            proc_events, known_pids = collect_process_events(known_pids)
            net_events = collect_network_events()
            all_events = proc_events + net_events

            if all_events:
                sent_batches, failed_batches = flush_event_batches(
                    args.api_url,
                    headers,
                    all_events,
                    args.batch_size,
                    send_events,
                    args.max_retries,
                    args.retry_base_delay,
                    args.retry_max_delay,
                )
                if failed_batches:
                    log.warning(
                        "Dropped %d telemetry batches after retries (sent=%d).",
                        failed_batches,
                        sent_batches,
                    )

            heartbeat_counter += 1
            time.sleep(args.interval)

        except KeyboardInterrupt:
            log.info("Agent shutting down.")
            break
        except (OSError, RuntimeError) as exc:
            log.error("Agent loop error: %s", exc)
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
