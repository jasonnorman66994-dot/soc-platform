#!/usr/bin/env python3
"""
SOC Distributed Agent — lightweight endpoint telemetry collector.

Captures process starts and network connections, streams to the
Command Center via POST /telemetry/ingest.

Usage:
    python soc_agent.py \
        --api-url http://localhost:8000 \
        --api-key YOUR_API_KEY \
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


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def collect_process_events(known_pids: set):
    """Return new process-start events since last poll."""
    if psutil is None:
        return [], known_pids
    events = []
    current_pids = set()
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            info = proc.info
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


def collect_network_events():
    """Return network connection events (outbound ESTABLISHED)."""
    if psutil is None:
        return []
    events = []
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


def send_heartbeat(api_url, headers):
    """Send a heartbeat event so the Command Center knows we're alive."""
    payload = [{
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
        resp = requests.post(f"{api_url}/telemetry/ingest", json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        log.info("Heartbeat sent — agents active: %s", resp.json().get("agents_active"))
    except Exception as exc:
        log.warning("Heartbeat failed: %s", exc)


def send_events(api_url, headers, events):
    """Post collected events to the telemetry ingest endpoint."""
    if not events:
        return
    try:
        resp = requests.post(f"{api_url}/telemetry/ingest", json=events, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        log.info(
            "Sent %d events — threat matches: %s",
            data.get("processed", 0),
            data.get("threat_matches", 0),
        )
    except Exception as exc:
        log.warning("Failed to send %d events: %s", len(events), exc)


def main():
    parser = argparse.ArgumentParser(description="SOC Distributed Agent")
    parser.add_argument("--api-url", default=os.getenv("SOC_API_URL", "http://localhost:8000"), help="Command Center API URL")
    parser.add_argument("--api-key", default=os.getenv("SOC_API_KEY", ""), help="API key for authentication")
    parser.add_argument("--interval", type=int, default=int(os.getenv("SOC_AGENT_INTERVAL", "15")), help="Poll interval in seconds")
    args = parser.parse_args()

    if requests is None:
        log.error("requests library is required: pip install requests")
        return
    if psutil is None:
        log.warning("psutil not installed — telemetry will be limited. pip install psutil")
    if not args.api_key.strip():
        log.error("API key is required. Provide --api-key or set SOC_API_KEY.")
        return

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": args.api_key,
        "X-Tenant-Id": os.getenv("SOC_TENANT_ID", "default"),
    }

    log.info("SOC Agent %s starting on %s — polling every %ds", AGENT_ID, HOSTNAME, args.interval)
    log.info("Reporting to %s", args.api_url)

    known_pids: set = set()
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
                # Cap batch size
                send_events(args.api_url, headers, all_events[:100])

            heartbeat_counter += 1
            time.sleep(args.interval)

        except KeyboardInterrupt:
            log.info("Agent shutting down.")
            break
        except Exception as exc:
            log.error("Agent loop error: %s", exc)
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
