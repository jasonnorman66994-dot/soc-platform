from datetime import datetime, timedelta, timezone
import asyncio
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Header, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, ConfigDict, constr
import json
import os
import hmac
import hashlib
import secrets
import io
import csv
import math
import re
from pathlib import Path
from typing import Literal, Any
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
import redis
import yaml
from jose import jwt, JWTError
from passlib.context import CryptContext

try:
    import stripe
except Exception:
    stripe = None

try:
    from apscheduler.schedulers.background import BackgroundScheduler
except Exception:  # pragma: no cover
    BackgroundScheduler = None  # type: ignore[assignment,misc]

from auth.jwt import create_access_token, create_refresh_token, verify_token
from auth.rbac import authorize
from engine.detect import detect
from engine.correlate import correlate
from engine.ai import analyze_incident
from engine.analytics import build_advanced_analytics, compute_ueba_summary, detect_ml_anomalies
from soar.playbooks import execute_playbook_for_incident, get_execution_history
from incidents.service import (
    add_timeline_event,
    add_analyst_note,
    close_incident,
    get_response_summary,
    log_response_action,
)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://soc:socpass@db:5432/socdb")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

app = FastAPI(title="SOC API Gateway", version="1.0.0")


def render_board_report_markdown(report: dict) -> str:
    incidents = report["incident_summary"]
    tenants = report["tenant_summary"]
    commercial = report["commercial_summary"]
    webhook_lines = report["webhook_summary_last_window"]
    recent_lines = report["recent_incidents"]

    markdown = [
        "# Board Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Window: last {report['window_days']} days",
        "",
        "## Platform KPIs",
        f"- Total tenants: {tenants['total_tenants']}",
        f"- Active tenants: {tenants['active_tenants']}",
        f"- Trialing tenants: {tenants['trialing_tenants']}",
        f"- Past due tenants: {tenants['past_due_tenants']}",
        "",
        "## Security Operations",
        f"- Total incidents: {incidents['total_incidents']}",
        f"- Open incidents: {incidents['open_incidents']}",
        f"- Critical incidents: {incidents['critical_incidents']}",
        f"- High incidents: {incidents['high_incidents']}",
        f"- MTTD seconds: {incidents['mttd_seconds']:.2f}",
        f"- MTTR seconds: {incidents['mttr_seconds']:.2f}",
        "",
        "## Commercial Funnel",
        f"- Total leads: {commercial['total_leads']}",
        f"- Converted signups: {commercial['converted_signups']}",
        f"- Conversion rate: {commercial['conversion_rate']:.2%}",
        "",
        "## Top Lead Sources",
    ]

    for row in commercial["by_source"][:5]:
        markdown.append(f"- {row['source']}: {row['count']} leads / {row['converted'] or 0} converted")

    markdown.extend(["", "## Webhook Health"])
    if webhook_lines:
        for row in webhook_lines:
            reason = f" ({row['reason']})" if row.get("reason") else ""
            markdown.append(f"- {row['status']}{reason}: {row['count']}")
    else:
        markdown.append("- No webhook activity recorded in this window")

    markdown.extend(["", "## Recent Incidents"])
    if recent_lines:
        for row in recent_lines:
            markdown.append(
                f"- [{row['severity']}/{row['status']}] {row['tenant_id']} :: {row['entity']} :: assigned to {row['assigned_to'] or 'unassigned'}"
            )
    else:
        markdown.append("- No incidents recorded in this window")

    return "\n".join(markdown) + "\n"


def _event_story_title(event_type: str) -> str:
    titles = {
        "email": "Suspicious email delivery observed",
        "email_click": "User engaged with suspicious content",
        "login_anomaly": "Impossible-travel login pattern detected",
        "oauth_grant": "Untrusted OAuth consent granted",
        "powershell_exec": "Encoded PowerShell execution detected",
        "file_download": "Sensitive file access detected",
        "data_exfil": "Outbound exfiltration behavior detected",
    }
    return titles.get(event_type, f"{event_type} observed")


def _event_story_severity(event_type: str) -> str:
    if event_type in {"powershell_exec", "data_exfil", "login_anomaly"}:
        return "high"
    if event_type in {"oauth_grant", "email_click", "file_download"}:
        return "medium"
    return "low"


def _severity_rank(level: str | None) -> int:
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get((level or "").lower(), 1)


def _max_severity(current: str | None, incoming: str | None) -> str:
    return current if _severity_rank(current) >= _severity_rank(incoming) else (incoming or current or "low")


def _calculate_risk_score(critical_alerts: int, high_alerts: int, total_alerts: int) -> int:
    medium_or_lower = max(total_alerts - critical_alerts - high_alerts, 0)
    score = (critical_alerts * 50) + (high_alerts * 30) + (medium_or_lower * 10)
    return min(score, 100)


def _normalize_intelligence_events(rows: list[dict]) -> list[dict]:
    normalized = []
    for row in rows:
        raw = row.get("raw")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:  # noqa: BLE001
                raw = {}
        raw = raw or {}
        payload_raw = raw.get("raw") if isinstance(raw.get("raw"), dict) else {}
        user = row.get("user_id") or "unknown-user"
        ip = raw.get("ip") or payload_raw.get("ip")
        geo = raw.get("from") or raw.get("location") or payload_raw.get("from") or payload_raw.get("location")
        normalized.append(
            {
                "id": row["id"],
                "timestamp": row["timestamp"].isoformat(),
                "action": row["type"],
                "actor": {"user": user, "ip": ip},
                "metadata": {"geo": geo},
            }
        )
    return normalized


def _build_entity_contexts(events: list[dict]) -> dict[str, dict]:
    contexts: dict[str, dict] = {}
    for event in events:
        actor = event.get("actor") or {}
        user = actor.get("user")
        if not user:
            continue
        ctx = contexts.setdefault(
            user,
            {
                "user": user,
                "ips": set(),
                "geos": set(),
                "actions": [],
                "last_seen": event.get("timestamp"),
            },
        )

        if actor.get("ip"):
            ctx["ips"].add(actor.get("ip"))
        geo = (event.get("metadata") or {}).get("geo")
        if geo:
            ctx["geos"].add(geo)
        action = event.get("action")
        if action:
            ctx["actions"].append(action)
        ctx["last_seen"] = event.get("timestamp")

    return contexts


def _detect_behavior_patterns(ctx: dict) -> list[str]:
    patterns = []
    actions = ctx.get("actions") or []

    has_login = any(item in actions for item in ["login_success", "login_anomaly"])
    if len(ctx.get("geos") or set()) > 1 and has_login:
        patterns.append("IMPOSSIBLE_TRAVEL_CHAIN")

    if has_login and "data_exfil" in actions:
        patterns.append("ACCOUNT_TAKEOVER")

    return patterns


def _calculate_context_risk(ctx: dict, alerts: list[dict], patterns: list[str]) -> int:
    score = 0

    for alert in alerts:
        severity = (alert.get("severity") or "").lower()
        if severity == "critical":
            score += 40
        elif severity == "high":
            score += 25
        elif severity == "medium":
            score += 10

    for pattern in patterns:
        if pattern == "ACCOUNT_TAKEOVER":
            score += 50
        elif pattern == "IMPOSSIBLE_TRAVEL_CHAIN":
            score += 30

    if len(ctx.get("ips") or set()) > 2:
        score += 10

    return min(score, 100)


def _build_incident_intelligence_graph(events: list[dict], risk_by_user: dict[str, int]) -> dict:
    nodes_by_id: dict[str, dict] = {}
    edges: list[dict] = []

    for event in events:
        event_id = f"event:{event['id']}"
        action = event.get("action") or "event"
        actor = event.get("actor") or {}
        user = actor.get("user")
        ip = actor.get("ip")

        nodes_by_id[event_id] = {
            "id": event_id,
            "type": "event",
            "label": action,
            "event_id": event.get("id"),
            "timestamp": event.get("timestamp"),
        }

        user_id = None
        if user:
            user_id = f"user:{user}"
            nodes_by_id[user_id] = {
                "id": user_id,
                "type": "user",
                "label": user,
                "risk_score": risk_by_user.get(user, 0),
            }
            edges.append({"from": user_id, "to": event_id, "label": action})

        if ip:
            ip_id = f"ip:{ip}"
            nodes_by_id[ip_id] = {
                "id": ip_id,
                "type": "ip",
                "label": ip,
            }
            if user_id:
                relation = "login_from" if action in {"login_success", "login_anomaly"} else "seen_from"
                edges.append({"from": user_id, "to": ip_id, "label": relation})

    dedup_edges = []
    seen = set()
    for edge in edges:
        key = (edge["from"], edge["to"], edge["label"])
        if key in seen:
            continue
        seen.add(key)
        dedup_edges.append(edge)

    return {"nodes": list(nodes_by_id.values()), "edges": dedup_edges}


AUTO_RESPONSE_ENABLED = os.getenv("AUTO_RESPONSE_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
_raw_threshold = os.getenv("AUTO_RESPONSE_RISK_THRESHOLD", "85")
try:
    AUTO_RESPONSE_RISK_THRESHOLD = int(_raw_threshold)
except (ValueError, TypeError):
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "AUTO_RESPONSE_RISK_THRESHOLD=%r is not a valid integer; defaulting to 85", _raw_threshold
    )
    AUTO_RESPONSE_RISK_THRESHOLD = 85


def _select_playbook_title(patterns: list[str], event_type: str | None, policy: dict | None = None) -> str:
    active_policy = policy if isinstance(policy, dict) else _normalize_soar_policy(policy)
    pattern_overrides = active_policy.get("pattern_overrides") or {}
    for pattern in patterns:
        candidate = pattern_overrides.get(pattern)
        if candidate in VALID_PLAYBOOK_TYPES:
            return candidate

    event_overrides = active_policy.get("event_type_overrides") or {}
    if event_type and event_overrides.get(event_type) in VALID_PLAYBOOK_TYPES:
        return event_overrides[event_type]

    if "ACCOUNT_TAKEOVER" in patterns:
        return "account_takeover"
    if "IMPOSSIBLE_TRAVEL_CHAIN" in patterns:
        return "suspicious_ip"
    if event_type == "data_exfil":
        return "data_exfiltration"
    if event_type in {"email", "email_click"}:
        return "phishing"
    return "generic_alert"


def _should_auto_respond(
    incident_row: dict | None,
    risk_score: int,
    patterns: list[str],
    playbook_title: str,
    policy: dict | None = None,
    ml_anomaly_score: float | None = None,
    tenant_id: str | None = None,
) -> bool | str:
    """Return True to auto-respond, False to skip, or 'pending_review' for ML gate block."""
    active_policy = policy if isinstance(policy, dict) else _normalize_soar_policy(policy)
    if not AUTO_RESPONSE_ENABLED or not incident_row:
        return False
    if not active_policy.get("auto_response_enabled", True):
        return False
    if (incident_row.get("status") or "").lower() in {"responded", "closed", "resolved"}:
        return False
    if incident_row.get("responded_at"):
        return False

    playbook_policy = (active_policy.get("playbooks") or {}).get(playbook_title, {})
    if isinstance(playbook_policy, dict) and playbook_policy.get("enabled") is False:
        return False

    threshold = active_policy.get("default_risk_threshold", AUTO_RESPONSE_RISK_THRESHOLD)
    if isinstance(playbook_policy, dict) and isinstance(playbook_policy.get("min_risk"), int):
        threshold = playbook_policy.get("min_risk")

    # ML anomaly gate: if ml_risk_threshold is set and ML score is below it, halt execution
    ml_risk_threshold = None
    if isinstance(playbook_policy, dict) and isinstance(playbook_policy.get("ml_risk_threshold"), (int, float)):
        ml_risk_threshold = playbook_policy["ml_risk_threshold"]
    elif isinstance(active_policy.get("ml_risk_threshold"), (int, float)):
        ml_risk_threshold = active_policy["ml_risk_threshold"]

    if ml_risk_threshold is not None and ml_anomaly_score is not None:
        if ml_anomaly_score < ml_risk_threshold:
            # Log deflection for audit
            if tenant_id and incident_row:
                log_action(
                    tenant_id, None, "soar.deflected",
                    f"incidents/{incident_row.get('id', 'unknown')}",
                    {
                        "reason": "ml_risk_below_threshold",
                        "ml_anomaly_score": ml_anomaly_score,
                        "ml_risk_threshold": ml_risk_threshold,
                        "playbook": playbook_title,
                        "risk_score": risk_score,
                        "status": "Pending Manual Review",
                    },
                )
            return "pending_review"

    if risk_score >= max(0, min(int(threshold), 100)):
        return True
    return any(item in {"ACCOUNT_TAKEOVER", "IMPOSSIBLE_TRAVEL_CHAIN"} for item in patterns)


def _build_playbook_inputs(
    incident_row: dict,
    payload: dict,
    patterns: list[str],
    risk_score: int,
    playbook_title: str | None = None,
    policy: dict | None = None,
) -> tuple[dict, dict]:
    event_type = payload.get("event_type")
    selected_playbook = playbook_title or _select_playbook_title(patterns, event_type, policy)
    incident_payload = {
        "id": incident_row.get("id"),
        "title": selected_playbook,
        "severity": incident_row.get("severity") or "medium",
        "status": incident_row.get("status") or "open",
        "context": {
            "user": payload.get("user_id"),
            "ip": payload.get("ip"),
            "sender_domain": payload.get("sender_domain"),
            "patterns": patterns,
            "risk_score": risk_score,
        },
    }
    event_payload = {
        "user": payload.get("user_id"),
        "ip": payload.get("ip"),
        "sender_domain": payload.get("sender_domain"),
        "event_type": event_type,
    }
    return incident_payload, event_payload


# ---------------------------------------------------------------------------
# Incident context enrichment — Geo-IP + Identity metadata
# ---------------------------------------------------------------------------
_GEO_IP_DB: dict[str, dict] = {
    "203.0.113.42": {"country": "RU", "city": "Moscow", "isp": "Evil Corp ISP", "latitude": 55.75, "longitude": 37.62},
    "198.51.100.7": {"country": "CN", "city": "Shanghai", "isp": "ChinaNet", "latitude": 31.23, "longitude": 121.47},
    "10.0.0.1": {"country": "US", "city": "Internal", "isp": "Private Network", "latitude": 37.77, "longitude": -122.42},
    "192.168.1.1": {"country": "US", "city": "Internal", "isp": "Private Network", "latitude": 40.71, "longitude": -74.01},
}

_IDENTITY_DB: dict[str, dict] = {
    "demo.user": {"full_name": "Alice Demo", "department": "Engineering", "title": "Senior Engineer", "manager": "Bob Manager"},
    "admin": {"full_name": "Admin User", "department": "IT Operations", "title": "System Administrator", "manager": "CTO"},
    "analyst": {"full_name": "Security Analyst", "department": "Security", "title": "SOC Analyst L2", "manager": "CISO"},
}


def enrich_incident_context(incident_row: dict | None, payload: dict | None = None) -> dict:
    """Auto-fetch Geo-IP and Identity metadata for an incident."""
    enriched: dict = {"geo_ip": None, "identity": None}
    if not incident_row and not payload:
        return enriched

    # Resolve IP from incident entity or payload
    ip = None
    user_id = None
    if payload:
        ip = payload.get("ip")
        user_id = payload.get("user_id")
    if not ip and incident_row:
        entity = incident_row.get("entity") or ""
        # entity may itself be an IP
        if entity and entity.count(".") == 3:
            ip = entity
    if not user_id and incident_row:
        user_id = incident_row.get("entity")

    # Geo-IP lookup (simulated)
    if ip:
        geo = _GEO_IP_DB.get(ip)
        if geo:
            enriched["geo_ip"] = {**geo, "ip": ip}
        else:
            # Default enrichment for unknown IPs
            enriched["geo_ip"] = {"ip": ip, "country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    # Identity metadata lookup (simulated)
    if user_id:
        identity = _IDENTITY_DB.get(user_id)
        if identity:
            enriched["identity"] = {**identity, "user_id": user_id}
        else:
            enriched["identity"] = {"user_id": user_id, "full_name": user_id, "department": "Unknown", "title": "Unknown"}

    return enriched


def render_executive_story_markdown(report: dict) -> str:
    summary = report["summary"]
    timeline = report["timeline"]
    key_findings = report["key_findings"]

    markdown = [
        "# Executive Attack Story Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Tenant: {report['tenant_id']}",
        f"Window: last {report['window_minutes']} minutes",
        "",
        "## Summary",
        f"- Events analyzed: {summary['total_events']}",
        f"- Alerts in window: {summary['total_alerts']}",
        f"- Critical alerts: {summary['critical_alerts']}",
        f"- Risk score: {summary['risk_score']} / 100",
        f"- Open incidents: {summary['open_incidents']}",
        "",
        "## Key Findings",
    ]

    for finding in key_findings:
        markdown.append(f"- {finding}")

    markdown.extend(["", "## Attack Timeline"])
    if timeline:
        for item in timeline:
            actor = item.get("user") or "unknown-user"
            location = item.get("location") or "n/a"
            markdown.append(
                f"- {item['timestamp']} [{item['severity']}] {item['title']} :: user={actor}, location={location}"
            )
    else:
        markdown.append("- No events in selected window")

    return "\n".join(markdown) + "\n"


def build_executive_attack_story_report(tenant_id: str, window_minutes: int = 180, event_limit: int = 140) -> dict:
    safe_window_minutes = max(15, min(window_minutes, 1440))
    safe_event_limit = max(20, min(event_limit, 400))

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, type, raw, timestamp
                FROM events
                WHERE tenant_id=%s
                  AND timestamp >= NOW() - (%s * INTERVAL '1 minute')
                ORDER BY timestamp ASC
                LIMIT %s
                """,
                (tenant_id, safe_window_minutes, safe_event_limit),
            )
            rows = cur.fetchall()

            cur.execute(
                """
                SELECT COUNT(*) AS total_alerts,
                       SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical_alerts,
                       SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high_alerts
                FROM alerts
                WHERE tenant_id=%s
                  AND detected_at >= NOW() - (%s * INTERVAL '1 minute')
                """,
                (tenant_id, safe_window_minutes),
            )
            alert_summary = cur.fetchone()

            cur.execute(
                """
                SELECT COUNT(*) AS open_incidents
                FROM incidents
                WHERE tenant_id=%s
                  AND status <> 'resolved'
                """,
                (tenant_id,),
            )
            incident_summary = cur.fetchone()

    normalized_events = []
    event_type_counts: dict[str, int] = {}
    user_counts: dict[str, int] = {}
    scenario_counts: dict[str, int] = {}

    for row in rows:
        raw = row.get("raw")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:  # noqa: BLE001
                raw = {}
        raw = raw or {}
        payload_raw = raw.get("raw") if isinstance(raw.get("raw"), dict) else {}
        event_type = row["type"]
        user = row.get("user_id") or "unknown-user"
        scenario = raw.get("scenario") or payload_raw.get("scenario")

        normalized_events.append(
            {
                "id": row["id"],
                "timestamp": row["timestamp"].isoformat(),
                "event_type": event_type,
                "title": _event_story_title(event_type),
                "severity": _event_story_severity(event_type),
                "user": user,
                "ip": raw.get("ip") or payload_raw.get("ip"),
                "location": raw.get("from") or raw.get("location") or payload_raw.get("from") or payload_raw.get("location"),
                "scenario": scenario,
            }
        )

        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        user_counts[user] = user_counts.get(user, 0) + 1
        if scenario:
            scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1

    top_event_types = [
        {"event_type": key, "count": value}
        for key, value in sorted(event_type_counts.items(), key=lambda item: item[1], reverse=True)[:4]
    ]
    top_users = [
        {"user": key, "count": value}
        for key, value in sorted(user_counts.items(), key=lambda item: item[1], reverse=True)[:4]
    ]
    top_scenarios = [
        {"scenario": key, "count": value}
        for key, value in sorted(scenario_counts.items(), key=lambda item: item[1], reverse=True)[:3]
    ]

    total_alerts = int(alert_summary.get("total_alerts") or 0)
    critical_alerts = int(alert_summary.get("critical_alerts") or 0)
    high_alerts = int(alert_summary.get("high_alerts") or 0)
    open_incidents = int(incident_summary.get("open_incidents") or 0)
    risk_score = _calculate_risk_score(critical_alerts, high_alerts, total_alerts)

    findings = [
        f"{critical_alerts} critical alerts and {high_alerts} high alerts were detected in the selected window.",
        f"{open_incidents} incidents remain open and require analyst follow-up.",
        "No dominant attack scenario observed yet.",
    ]
    if top_scenarios:
        findings[2] = f"Most active scenario: {top_scenarios[0]['scenario']} ({top_scenarios[0]['count']} events)."

    return {
        "generated_at": now_utc().isoformat(),
        "tenant_id": tenant_id,
        "window_minutes": safe_window_minutes,
        "summary": {
            "total_events": len(normalized_events),
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "risk_score": risk_score,
            "open_incidents": open_incidents,
            "top_event_types": top_event_types,
            "top_users": top_users,
            "top_scenarios": top_scenarios,
        },
        "key_findings": findings,
        "timeline": normalized_events,
    }


def get_report_schedule_row(cur, schedule_id: int) -> dict:
    cur.execute(
        """
        SELECT id, name, description, format, frequency, day_of_week, day_of_month, hour_of_day,
               window_days, incident_limit, recipients, enabled, last_run, next_run,
               created_at, updated_at
        FROM report_schedules
        WHERE id = %s
        """,
        (schedule_id,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return row


def run_report_schedule_export(cur, schedule_id: int) -> dict:
    schedule = get_report_schedule_row(cur, schedule_id)
    report = build_board_report(
        window_days=schedule["window_days"],
        incident_limit=schedule["incident_limit"],
    )
    executed_at = now_utc()
    next_run = (
        compute_next_report_run(
            frequency=schedule["frequency"],
            hour_of_day=schedule["hour_of_day"],
            day_of_week=schedule.get("day_of_week"),
            day_of_month=schedule.get("day_of_month"),
            reference_time=executed_at,
        )
        if schedule["enabled"]
        else None
    )

    cur.execute(
        """
        UPDATE report_schedules
        SET last_run = %s,
            next_run = %s,
            updated_at = NOW()
        WHERE id = %s
        RETURNING id, name, description, format, frequency, day_of_week, day_of_month, hour_of_day,
                  window_days, incident_limit, recipients, enabled, last_run, next_run,
                  created_at, updated_at
        """,
        (executed_at, next_run, schedule_id),
    )
    updated_schedule = cur.fetchone()

    return {
        "schedule": ReportScheduleResponse(**updated_schedule).model_dump(mode="json"),
        "format": schedule["format"],
        "report": report,
        "content": render_board_report_markdown(report) if schedule["format"] == "markdown" else None,
    }

rdb = redis.Redis.from_url(REDIS_URL, decode_responses=True)
clients: list[dict] = []
RATE_LIMITS: dict[str, list[datetime]] = {}
RULES_DIR = Path(__file__).parent / "rules"
LIVE_SIMULATION_TASKS: dict[str, asyncio.Task] = {}
LIVE_SIMULATION_STATE: dict[str, dict[str, Any]] = {}
SOAR_POLICY_CACHE: dict[str, dict[str, Any]] = {}
SOAR_POLICY_CACHE_TTL_SECONDS = 30

ROLE_ORDER = {"viewer": 1, "analyst": 2, "admin": 3, "owner": 4}
VALID_PLANS = {"free", "pro", "enterprise"}
VALID_LEAD_SOURCES = {"landing", "webinar", "partner", "unknown"}
VALID_REPORT_SCHEDULE_FORMATS = {"markdown", "json"}
VALID_REPORT_SCHEDULE_FREQUENCIES = {"daily", "weekly", "monthly"}
VALID_PLAYBOOK_TYPES = {"account_takeover", "suspicious_ip", "phishing", "data_exfiltration", "generic_alert"}
ADMIN_SESSION_ALG = "HS256"
SECURITY_WARNINGS: list[str] = []
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginBody(BaseModel):
    email: constr(strip_whitespace=True, min_length=6, max_length=255)
    password: constr(min_length=8, max_length=128)


class RefreshBody(BaseModel):
    refresh_token: str


class SignupBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    company: constr(strip_whitespace=True, min_length=2, max_length=120)
    email: constr(strip_whitespace=True, min_length=6, max_length=255)
    password: constr(min_length=8, max_length=128)
    plan: str = "free"


class CreateUserBody(BaseModel):
    email: constr(strip_whitespace=True, min_length=6, max_length=255)
    password: constr(min_length=8, max_length=128)
    role: str = Field(pattern="^(admin|analyst|viewer)$")


class IngestEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_id: str = Field(min_length=2, max_length=128)
    event_type: str = Field(min_length=2, max_length=64)
    subject: str | None = Field(default=None, max_length=500)
    sender_domain: str | None = Field(default=None, max_length=255)
    ip: str | None = Field(default=None, max_length=64)
    raw: dict | None = None


class RespondBody(BaseModel):
    incident_id: int
    action: str = Field(min_length=2, max_length=64)
    target: str = Field(min_length=1, max_length=255)


class NoteBody(BaseModel):
    note: str = Field(min_length=2, max_length=1000)


class IncidentNoteBody(NoteBody):
    tags: list[str] | None = None


class DemoAttackBody(BaseModel):
    user_id: str = "demo.user"
    source_country: str = "UK"
    destination_country: str = "US"
    scenario: Literal[
        "credential_compromise_chain",
        "impossible_travel_burst",
        "insider_data_exfiltration",
        "password_spray_wave",
        "suspicious_oauth_app",
        "powershell_execution_chain",
    ] = "credential_compromise_chain"
    iterations: int = Field(default=1, ge=1, le=5)
    include_noise: bool = False
    dry_run: bool = False


class DemoSeedBody(BaseModel):
    rounds: int = Field(default=2, ge=1, le=6)
    include_noise: bool = True


class LiveSimulationBody(BaseModel):
    interval_seconds: int = Field(default=25, ge=5, le=300)
    include_noise: bool = True
    scenarios: list[str] | None = None


class WaitlistLeadBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    company: constr(strip_whitespace=True, min_length=2, max_length=120)
    email: constr(strip_whitespace=True, min_length=6, max_length=255)
    role: constr(strip_whitespace=True, min_length=2, max_length=120) = "security_lead"
    source: str = "landing"


class TenantSubscriptionBody(BaseModel):
    plan: str = Field(pattern="^(free|pro|enterprise)$")
    status: str = Field(pattern="^(trialing|active|past_due|canceled)$")


class AnalyticsEventBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_name: constr(strip_whitespace=True, min_length=2, max_length=80)
    page: constr(strip_whitespace=True, min_length=1, max_length=200) = "/"
    meta: dict | None = None


class AdminSessionBody(BaseModel):
    admin_token: str


class AdminSessionRefreshBody(BaseModel):
    refresh_token: str


class AdminSessionRevokeBody(BaseModel):
    refresh_token: str


class AdminDemoBody(BaseModel):
    source_country: str = "UK"
    destination_country: str = "US"
    user_id: str = "demo.user"
    scenario: Literal[
        "credential_compromise_chain",
        "impossible_travel_burst",
        "insider_data_exfiltration",
        "password_spray_wave",
        "suspicious_oauth_app",
        "powershell_execution_chain",
    ] = "credential_compromise_chain"
    iterations: int = Field(default=1, ge=1, le=5)
    include_noise: bool = False
    dry_run: bool = False


class DemoResetBody(BaseModel):
    regenerate_api_key: bool = False


class ReportScheduleCreate(BaseModel):
    name: str
    description: str | None = None
    format: str = "markdown"  # markdown or json
    frequency: str = "weekly"  # daily, weekly, monthly
    day_of_week: int | None = None  # 0=Monday, 6=Sunday (for weekly)
    day_of_month: int | None = None  # 1-28 (for monthly)
    hour_of_day: int = 9
    window_days: int = 30
    incident_limit: int = 10
    recipients: str | None = None
    enabled: bool = True


class ReportScheduleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    format: str | None = None
    frequency: str | None = None
    day_of_week: int | None = None
    day_of_month: int | None = None
    hour_of_day: int | None = None
    window_days: int | None = None
    incident_limit: int | None = None
    recipients: str | None = None
    enabled: bool | None = None


class ReportScheduleResponse(BaseModel):
    id: int
    name: str
    description: str | None
    format: str
    frequency: str
    day_of_week: int | None
    day_of_month: int | None
    hour_of_day: int
    window_days: int
    incident_limit: int
    recipients: str | None
    enabled: bool
    last_run: datetime | None
    next_run: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookPolicyPatch(BaseModel):
    enabled: bool | None = None
    min_risk: int | None = Field(default=None, ge=0, le=100)
    ml_risk_threshold: float | None = Field(default=None, ge=0, le=100)
    deception_enabled: bool | None = None


class SoarPolicyUpdateBody(BaseModel):
    auto_response_enabled: bool | None = None
    default_risk_threshold: int | None = Field(default=None, ge=0, le=100)
    ml_risk_threshold: float | None = Field(default=None, ge=0, le=100)
    ghost_mode: bool | None = None
    playbooks: dict[str, PlaybookPolicyPatch] | None = None
    event_type_overrides: dict[str, str] | None = None
    pattern_overrides: dict[str, str] | None = None


class VoiceCommandBody(BaseModel):
    command: str = Field(..., min_length=2, max_length=200)
    context_user: str | None = Field(default=None, max_length=128)
    target_tenant: str | None = Field(default=None, max_length=128)
    percent_delta: float | None = Field(default=None, ge=0.1, le=100)
    confirm: bool = False


class ThresholdUpdateBody(BaseModel):
    target_tenant: str | None = Field(default=None, max_length=128)
    percent_delta: float = Field(..., ge=0.1, le=100)
    confirm: bool = False


class TelemetryEvent(BaseModel):
    agent_id: str = Field(min_length=2, max_length=128)
    hostname: str = Field(min_length=1, max_length=256)
    event_type: str = Field(min_length=2, max_length=64)  # process_start | network_connection | heartbeat
    timestamp: str | None = None
    user_id: str | None = Field(default=None, max_length=128)
    pid: int | None = None
    process_name: str | None = Field(default=None, max_length=256)
    remote_ip: str | None = Field(default=None, max_length=64)
    remote_port: int | None = None
    local_port: int | None = None
    meta: dict | None = None


class DrillRequest(BaseModel):
    drill_type: str = Field(min_length=2, max_length=64)  # brute_force | phishing_sim | ghost_mode_test | jit_test
    target_user: str | None = Field(default=None, max_length=128)
    iterations: int = Field(default=5, ge=1, le=50)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Threat Intelligence Service (The Oracle)
# ---------------------------------------------------------------------------
_THREAT_INTEL_FEED: dict[str, dict] = {}  # ip -> {source, category, risk, last_seen}
_THREAT_INTEL_LAST_POLL: float = 0.0
_THREAT_INTEL_POLL_INTERVAL = 300  # seconds

# Mock global blocklist (simulates AlienVault OTX / abuse.ch feeds)
_MOCK_THREAT_FEED = {
    "198.51.100.1": {"source": "AlienVault OTX", "category": "C2", "risk": 100, "tags": ["botnet", "c2-server"]},
    "203.0.113.66": {"source": "abuse.ch", "category": "malware", "risk": 100, "tags": ["ransomware", "dropper"]},
    "192.0.2.99": {"source": "AlienVault OTX", "category": "scanner", "risk": 85, "tags": ["mass-scanner"]},
    "198.51.100.200": {"source": "ThreatFox", "category": "phishing", "risk": 95, "tags": ["credential-harvester"]},
    "203.0.113.42": {"source": "abuse.ch", "category": "brute_force", "risk": 90, "tags": ["ssh-bruteforce"]},
}


def poll_threat_intel_feed() -> dict[str, dict]:
    """Poll global threat intel feed. Returns current feed state."""
    global _THREAT_INTEL_LAST_POLL
    import time as _time
    now = _time.time()
    if now - _THREAT_INTEL_LAST_POLL < _THREAT_INTEL_POLL_INTERVAL and _THREAT_INTEL_FEED:
        return _THREAT_INTEL_FEED
    # In production: fetch from AlienVault OTX API, abuse.ch, etc.
    _THREAT_INTEL_FEED.clear()
    _THREAT_INTEL_FEED.update(_MOCK_THREAT_FEED)
    _THREAT_INTEL_LAST_POLL = now
    return _THREAT_INTEL_FEED


def _upsert_shared_threat(ip: str, source_tenant: str, category: str, risk: int, reason: str, source: str = "Sovereign Diplomat") -> None:
    """Promote a critical indicator into shared herd-immunity intelligence."""
    if not ip:
        return
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO shared_threats (ip, source_tenant, category, risk, status, source, reason, first_seen, last_seen, meta)
                VALUES (%s, %s, %s, %s, 'critical', %s, %s, NOW(), NOW(), %s)
                ON CONFLICT (ip)
                DO UPDATE SET
                    source_tenant=EXCLUDED.source_tenant,
                    category=EXCLUDED.category,
                    risk=GREATEST(shared_threats.risk, EXCLUDED.risk),
                    status='critical',
                    source=EXCLUDED.source,
                    reason=EXCLUDED.reason,
                    last_seen=NOW(),
                    meta=COALESCE(shared_threats.meta, '{}'::jsonb) || COALESCE(EXCLUDED.meta, '{}'::jsonb)
                """,
                (ip, source_tenant, category, risk, source, reason, json.dumps({"shared_intelligence": True})),
            )
        conn.commit()


def _get_shared_threat(ip: str | None) -> dict | None:
    if not ip:
        return None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ip, source_tenant, category, risk, status, source, reason, last_seen
                FROM shared_threats
                WHERE ip=%s
                  AND status='critical'
                LIMIT 1
                """,
                (ip,),
            )
            row = cur.fetchone()
    if not row:
        return None
    return {
        "source": row.get("source") or "Sovereign Diplomat",
        "category": row.get("category") or "shared_critical",
        "risk": int(row.get("risk") or 100),
        "tags": ["shared-intelligence", "diplomat"],
        "shared_intelligence": True,
        "shared_source_tenant": row.get("source_tenant"),
        "reason": row.get("reason") or "critical threat propagated across tenants",
    }


def check_threat_intel(ip: str | None) -> dict | None:
    """Check if an IP matches global feed or shared sovereign threat intelligence."""
    if not ip:
        return None
    shared = _get_shared_threat(ip)
    if shared:
        return shared
    feed = poll_threat_intel_feed()
    return feed.get(ip)


def _safe_stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _telemetry_frequency_zscore(tenant_id: str, user_id: str, event_type: str, now_ts: datetime) -> tuple[float, dict]:
    """Calculate z-score for telemetry hourly frequency against 7-day user baseline."""
    current_hour = now_ts.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    baseline_map = {
        (current_hour - timedelta(hours=i)).isoformat(): 0
        for i in range(0, 168)
    }

    for item in _TELEMETRY_BUFFER:
        if item.get("tenant_id") != tenant_id:
            continue
        if item.get("event_type") != event_type:
            continue
        if item.get("user_id") != user_id:
            continue

        ts_raw = item.get("timestamp")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except Exception:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        hour_key = ts.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
        if hour_key in baseline_map:
            baseline_map[hour_key] = baseline_map.get(hour_key, 0) + 1

    values = list(reversed(list(baseline_map.values())))
    current_hour_count = baseline_map.get(current_hour.isoformat(), 0)
    mean = sum(values) / len(values)
    stddev = _safe_stddev([float(v) for v in values])
    if stddev <= 0:
        return 0.0, {"mean": mean, "stddev": stddev, "current": current_hour_count, "sample_size": len(values)}

    z_score = (current_hour_count - mean) / stddev
    return z_score, {"mean": mean, "stddev": stddev, "current": current_hour_count, "sample_size": len(values)}


def _event_frequency_zscore(tenant_id: str, user_id: str, event_type: str) -> tuple[float, dict]:
    """Calculate z-score for events table hourly frequency against 7-day user baseline."""
    now_hour = now_utc().astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    baseline_map = {
        (now_hour - timedelta(hours=i)).isoformat(): 0
        for i in range(0, 168)
    }

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT date_trunc('hour', timestamp) AS hour_bucket, COUNT(*) AS cnt
                FROM events
                WHERE tenant_id=%s
                  AND user_id=%s
                  AND type=%s
                  AND timestamp >= NOW() - INTERVAL '7 days'
                GROUP BY hour_bucket
                ORDER BY hour_bucket ASC
                """,
                (tenant_id, user_id, event_type),
            )
            rows = cur.fetchall()

    for row in rows:
        hour = row.get("hour_bucket")
        if hasattr(hour, "isoformat"):
            key = hour.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
            if key in baseline_map:
                baseline_map[key] = int(row.get("cnt") or 0)

    values = list(reversed(list(baseline_map.values())))
    current = baseline_map.get(now_hour.isoformat(), 0)
    mean = sum(values) / len(values)
    stddev = _safe_stddev([float(v) for v in values])
    if stddev <= 0:
        return 0.0, {"mean": mean, "stddev": stddev, "current": current, "sample_size": len(values)}

    z_score = (current - mean) / stddev
    return z_score, {"mean": mean, "stddev": stddev, "current": current, "sample_size": len(values)}


# ---------------------------------------------------------------------------
# Distributed Agent Registry (The Hunter)
# ---------------------------------------------------------------------------
_REGISTERED_AGENTS: dict[str, dict[str, dict]] = {}  # tenant_id -> agent_id -> {hostname, last_seen, status, event_count}
_TELEMETRY_BUFFER: list[dict] = []  # recent telemetry events (capped)
_TELEMETRY_BUFFER_MAX = 500


def register_agent_heartbeat(agent_id: str, hostname: str, tenant_id: str = "default"):
    """Update agent registry with heartbeat (tenant-scoped)."""
    if tenant_id not in _REGISTERED_AGENTS:
        _REGISTERED_AGENTS[tenant_id] = {}
    _REGISTERED_AGENTS[tenant_id][agent_id] = {
        "hostname": hostname,
        "last_seen": now_utc().isoformat(),
        "status": "active",
        "event_count": _REGISTERED_AGENTS.get(tenant_id, {}).get(agent_id, {}).get("event_count", 0),
    }


def buffer_telemetry(event: dict):
    """Add telemetry event to buffer."""
    _TELEMETRY_BUFFER.append(event)
    if len(_TELEMETRY_BUFFER) > _TELEMETRY_BUFFER_MAX:
        del _TELEMETRY_BUFFER[:len(_TELEMETRY_BUFFER) - _TELEMETRY_BUFFER_MAX]
    agent_id = event.get("agent_id")
    tenant_id = event.get("tenant_id", "default")
    if agent_id and tenant_id in _REGISTERED_AGENTS and agent_id in _REGISTERED_AGENTS[tenant_id]:
        _REGISTERED_AGENTS[tenant_id][agent_id]["event_count"] = _REGISTERED_AGENTS[tenant_id][agent_id].get("event_count", 0) + 1


# ---------------------------------------------------------------------------
# Simulation Engine (The Architect) — drill tracking
# ---------------------------------------------------------------------------
_DRILL_HISTORY: dict[str, list[dict]] = {}  # tenant_id -> list of drill results
_DRILL_HISTORY_MAX = 100


def record_drill(drill: dict, tenant_id: str = "default"):
    if tenant_id not in _DRILL_HISTORY:
        _DRILL_HISTORY[tenant_id] = []
    _DRILL_HISTORY[tenant_id].append(drill)
    if len(_DRILL_HISTORY[tenant_id]) > _DRILL_HISTORY_MAX:
        del _DRILL_HISTORY[tenant_id][:len(_DRILL_HISTORY[tenant_id]) - _DRILL_HISTORY_MAX]


# ---------------------------------------------------------------------------
# JIT (Just-In-Time) access — token revocation blacklist
# ---------------------------------------------------------------------------
_JIT_REVOKED_TOKENS: set[str] = set()  # in-memory set of revoked JTIs / user-IDs


def jit_revoke_user_sessions(tenant_id: str, user_id: str, reason: str = "risk_spike"):
    """Instantly revoke all active sessions for a user by blacklisting their user-id."""
    _JIT_REVOKED_TOKENS.add(f"{tenant_id}:{user_id}")
    log_action(tenant_id, None, "jit.session_revoked", f"users/{user_id}", {
        "reason": reason,
        "timestamp": now_utc().isoformat(),
    })


def is_jit_revoked(tenant_id: str, user_id: str) -> bool:
    return f"{tenant_id}:{user_id}" in _JIT_REVOKED_TOKENS


def jit_reinstate_user(tenant_id: str, user_id: str):
    _JIT_REVOKED_TOKENS.discard(f"{tenant_id}:{user_id}")
    log_action(tenant_id, None, "jit.session_reinstated", f"users/{user_id}", {})


def _default_soar_policy() -> dict:
    return {
        "auto_response_enabled": AUTO_RESPONSE_ENABLED,
        "default_risk_threshold": AUTO_RESPONSE_RISK_THRESHOLD,
        "ml_risk_threshold": 5.0,
        "ghost_mode": False,
        "playbooks": {
            "account_takeover": {"enabled": True, "min_risk": 70, "ml_risk_threshold": 4.0, "deception_enabled": False},
            "suspicious_ip": {"enabled": True, "min_risk": 80, "ml_risk_threshold": 5.0, "deception_enabled": False},
            "phishing": {"enabled": True, "min_risk": 85, "ml_risk_threshold": 6.0, "deception_enabled": False},
            "data_exfiltration": {"enabled": True, "min_risk": 75, "ml_risk_threshold": 5.0, "deception_enabled": False},
            "generic_alert": {"enabled": False, "min_risk": 95, "ml_risk_threshold": 8.0, "deception_enabled": False},
        },
        "event_type_overrides": {
            "data_exfil": "data_exfiltration",
            "email": "phishing",
            "email_click": "phishing",
        },
        "pattern_overrides": {
            "ACCOUNT_TAKEOVER": "account_takeover",
            "IMPOSSIBLE_TRAVEL_CHAIN": "suspicious_ip",
        },
    }


def _normalize_soar_policy(raw_policy: dict | str | None) -> dict:
    default = _default_soar_policy()
    candidate = {}
    if isinstance(raw_policy, dict):
        candidate = raw_policy
    elif isinstance(raw_policy, str):
        try:
            parsed_policy = json.loads(raw_policy)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed_policy = {}
        candidate = parsed_policy if isinstance(parsed_policy, dict) else {}

    auto_response_enabled = candidate.get("auto_response_enabled")
    if not isinstance(auto_response_enabled, bool):
        auto_response_enabled = default["auto_response_enabled"]

    default_risk_threshold = candidate.get("default_risk_threshold")
    if not isinstance(default_risk_threshold, int):
        default_risk_threshold = default["default_risk_threshold"]
    default_risk_threshold = max(0, min(default_risk_threshold, 100))

    ml_risk_threshold = candidate.get("ml_risk_threshold")
    if not isinstance(ml_risk_threshold, (int, float)):
        ml_risk_threshold = default["ml_risk_threshold"]
    ml_risk_threshold = max(0.0, min(float(ml_risk_threshold), 100.0))

    playbooks_in = candidate.get("playbooks") if isinstance(candidate.get("playbooks"), dict) else {}
    playbooks = {}
    for name, base in default["playbooks"].items():
        requested = playbooks_in.get(name) if isinstance(playbooks_in.get(name), dict) else {}
        enabled = requested.get("enabled") if isinstance(requested.get("enabled"), bool) else base["enabled"]
        min_risk = requested.get("min_risk") if isinstance(requested.get("min_risk"), int) else base["min_risk"]
        pb_ml_thresh = requested.get("ml_risk_threshold") if isinstance(requested.get("ml_risk_threshold"), (int, float)) else base.get("ml_risk_threshold", ml_risk_threshold)
        pb_deception = requested.get("deception_enabled") if isinstance(requested.get("deception_enabled"), bool) else base.get("deception_enabled", False)
        playbooks[name] = {
            "enabled": enabled,
            "min_risk": max(0, min(min_risk, 100)),
            "ml_risk_threshold": max(0.0, min(float(pb_ml_thresh), 100.0)),
            "deception_enabled": pb_deception,
        }

    event_type_overrides = dict(default["event_type_overrides"])
    if isinstance(candidate.get("event_type_overrides"), dict):
        for key, value in candidate["event_type_overrides"].items():
            if isinstance(key, str) and isinstance(value, str) and value in VALID_PLAYBOOK_TYPES:
                event_type_overrides[key] = value

    pattern_overrides = dict(default["pattern_overrides"])
    if isinstance(candidate.get("pattern_overrides"), dict):
        for key, value in candidate["pattern_overrides"].items():
            if isinstance(key, str) and isinstance(value, str) and value in VALID_PLAYBOOK_TYPES:
                pattern_overrides[key] = value

    ghost_mode = candidate.get("ghost_mode")
    if not isinstance(ghost_mode, bool):
        ghost_mode = default.get("ghost_mode", False)

    return {
        "auto_response_enabled": auto_response_enabled,
        "default_risk_threshold": default_risk_threshold,
        "ml_risk_threshold": ml_risk_threshold,
        "ghost_mode": ghost_mode,
        "playbooks": playbooks,
        "event_type_overrides": event_type_overrides,
        "pattern_overrides": pattern_overrides,
    }


def _get_or_create_soar_policy(tenant_id: str) -> dict:
    created_policy = _default_soar_policy()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT config FROM soar_policies WHERE tenant_id=%s", (tenant_id,))
            row = cur.fetchone()
            if row is not None and row.get("config") is not None:
                return _normalize_soar_policy(row.get("config"))

            cur.execute(
                """
                INSERT INTO soar_policies (tenant_id, config)
                VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO NOTHING
                """,
                (tenant_id, json.dumps(created_policy)),
            )
        conn.commit()
    return _normalize_soar_policy(created_policy)


def _save_soar_policy(tenant_id: str, policy: dict) -> dict:
    normalized = _normalize_soar_policy(policy)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO soar_policies (tenant_id, config, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (tenant_id)
                DO UPDATE SET config=EXCLUDED.config, updated_at=NOW()
                RETURNING config
                """,
                (tenant_id, json.dumps(normalized)),
            )
            row = cur.fetchone()
        conn.commit()
    saved = _normalize_soar_policy((row or {}).get("config"))
    SOAR_POLICY_CACHE[tenant_id] = {"policy": saved, "cached_at": now_utc()}
    return saved


def _get_cached_soar_policy(tenant_id: str) -> dict:
    cached = SOAR_POLICY_CACHE.get(tenant_id)
    if cached:
        cached_at = cached.get("cached_at")
        if isinstance(cached_at, datetime):
            age_seconds = (now_utc() - cached_at).total_seconds()
            if age_seconds <= SOAR_POLICY_CACHE_TTL_SECONDS and isinstance(cached.get("policy"), dict):
                return cached["policy"]

    policy = _get_or_create_soar_policy(tenant_id)
    SOAR_POLICY_CACHE[tenant_id] = {"policy": policy, "cached_at": now_utc()}
    return policy


def compute_next_report_run(
    frequency: str,
    hour_of_day: int,
    day_of_week: int | None = None,
    day_of_month: int | None = None,
    reference_time: datetime | None = None,
) -> datetime:
    reference = reference_time or now_utc()
    base = reference.replace(minute=0, second=0, microsecond=0)

    if frequency == "daily":
        candidate = base.replace(hour=hour_of_day)
        if candidate <= reference:
            candidate += timedelta(days=1)
        return candidate

    if frequency == "weekly":
        if day_of_week is None:
            raise HTTPException(status_code=422, detail="Weekly schedules require day_of_week")
        days_ahead = (day_of_week - reference.weekday()) % 7
        candidate = base.replace(hour=hour_of_day) + timedelta(days=days_ahead)
        if candidate <= reference:
            candidate += timedelta(days=7)
        return candidate

    if frequency == "monthly":
        if day_of_month is None:
            raise HTTPException(status_code=422, detail="Monthly schedules require day_of_month")
        current_month_candidate = base.replace(day=day_of_month, hour=hour_of_day)
        if current_month_candidate > reference:
            return current_month_candidate

        if reference.month == 12:
            return current_month_candidate.replace(year=reference.year + 1, month=1)
        return current_month_candidate.replace(month=reference.month + 1)

    raise HTTPException(status_code=422, detail="Unsupported schedule frequency")


def normalize_report_schedule_payload(payload: dict, existing: dict | None = None) -> dict:
    merged = dict(existing or {})
    merged.update(payload)

    normalized_name = str(merged.get("name") or "").strip()
    if not normalized_name:
        raise HTTPException(status_code=422, detail="Schedule name is required")
    merged["name"] = normalized_name

    merged["format"] = str(merged.get("format") or "markdown").strip().lower()
    if merged["format"] not in VALID_REPORT_SCHEDULE_FORMATS:
        raise HTTPException(status_code=422, detail="Schedule format must be markdown or json")

    merged["frequency"] = str(merged.get("frequency") or "weekly").strip().lower()
    if merged["frequency"] not in VALID_REPORT_SCHEDULE_FREQUENCIES:
        raise HTTPException(status_code=422, detail="Schedule frequency must be daily, weekly, or monthly")

    merged["hour_of_day"] = max(0, min(int(merged.get("hour_of_day", 9)), 23))
    merged["window_days"] = max(7, min(int(merged.get("window_days", 30)), 180))
    merged["incident_limit"] = max(3, min(int(merged.get("incident_limit", 10)), 50))
    merged["enabled"] = bool(merged.get("enabled", True))

    day_of_week = merged.get("day_of_week")
    merged["day_of_week"] = None if day_of_week is None else max(0, min(int(day_of_week), 6))

    day_of_month = merged.get("day_of_month")
    merged["day_of_month"] = None if day_of_month is None else max(1, min(int(day_of_month), 28))

    if merged["frequency"] == "weekly" and merged["day_of_week"] is None:
        raise HTTPException(status_code=422, detail="Weekly schedules require day_of_week")
    if merged["frequency"] == "monthly" and merged["day_of_month"] is None:
        raise HTTPException(status_code=422, detail="Monthly schedules require day_of_month")

    if merged["frequency"] != "weekly":
        merged["day_of_week"] = None
    if merged["frequency"] != "monthly":
        merged["day_of_month"] = None

    merged["next_run"] = (
        compute_next_report_run(
            frequency=merged["frequency"],
            hour_of_day=merged["hour_of_day"],
            day_of_week=merged.get("day_of_week"),
            day_of_month=merged.get("day_of_month"),
        )
        if merged["enabled"]
        else None
    )
    return merged


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def is_password_hash(value: str) -> bool:
    return value.startswith("$2")


def verify_password(plain_password: str, stored_password: str) -> bool:
    if is_password_hash(stored_password):
        return pwd_context.verify(plain_password, stored_password)
    return plain_password == stored_password


def evaluate_security_posture() -> list[str]:
    warnings = []
    if os.getenv("JWT_SECRET", "change-me-in-production") == "change-me-in-production":
        warnings.append("JWT_SECRET uses insecure default")
    if os.getenv("INTERNAL_ADMIN_TOKEN", "dev-admin-token") == "dev-admin-token":
        warnings.append("INTERNAL_ADMIN_TOKEN uses insecure default")
    if os.getenv("ALLOW_INSECURE_HTTP", "false").lower() == "true":
        warnings.append("ALLOW_INSECURE_HTTP=true")
    return warnings


def enforce_security_policy():
    global SECURITY_WARNINGS
    SECURITY_WARNINGS = evaluate_security_posture()
    if os.getenv("STRICT_SECURITY_MODE", "false").lower() == "true" and SECURITY_WARNINGS:
        raise RuntimeError(f"Strict security mode failed: {', '.join(SECURITY_WARNINGS)}")


def get_conn():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    plan TEXT NOT NULL DEFAULT 'free',
                    status TEXT NOT NULL DEFAULT 'active',
                    stripe_customer_id TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id),
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    UNIQUE(tenant_id, email)
                );

                CREATE TABLE IF NOT EXISTS events (
                    id SERIAL PRIMARY KEY,
                    tenant_id TEXT,
                    user_id TEXT,
                    type TEXT,
                    raw JSONB,
                    timestamp TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    tenant_id TEXT,
                    rule_id TEXT,
                    severity TEXT,
                    confidence INT,
                    mitre TEXT,
                    summary TEXT,
                    event_id INT REFERENCES events(id),
                    detected_at TIMESTAMPTZ DEFAULT NOW(),
                    responded_at TIMESTAMPTZ,
                    timestamp TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id SERIAL PRIMARY KEY,
                    tenant_id TEXT,
                    entity TEXT,
                    severity TEXT,
                    status TEXT,
                    story JSONB,
                    assigned_to TEXT,
                    notes JSONB DEFAULT '[]'::jsonb,
                    first_seen TIMESTAMPTZ DEFAULT NOW(),
                    last_seen TIMESTAMPTZ DEFAULT NOW(),
                    detected_at TIMESTAMPTZ DEFAULT NOW(),
                    responded_at TIMESTAMPTZ,
                    timestamp TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(id),
                    key TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    meta JSONB,
                    timestamp TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS lead_captures (
                    id SERIAL PRIMARY KEY,
                    company TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT,
                    source TEXT,
                    tenant_id TEXT,
                    converted_to_signup BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS billing_events (
                    id SERIAL PRIMARY KEY,
                    tenant_id TEXT,
                    stripe_event_id TEXT,
                    event_type TEXT,
                    payload JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS analytics_events (
                    id SERIAL PRIMARY KEY,
                    event_name TEXT NOT NULL,
                    page TEXT,
                    visitor_ip TEXT,
                    user_agent TEXT,
                    meta JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS admin_sessions (
                    id SERIAL PRIMARY KEY,
                    jti TEXT NOT NULL UNIQUE,
                    revoked BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS webhook_replays (
                    id SERIAL PRIMARY KEY,
                    fingerprint TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS webhook_metrics (
                    id SERIAL PRIMARY KEY,
                    tenant_id TEXT,
                    stripe_event_id TEXT,
                    event_type TEXT,
                    status TEXT NOT NULL,
                    reason TEXT,
                    fingerprint TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS report_schedules (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    format TEXT NOT NULL DEFAULT 'markdown',
                    frequency TEXT NOT NULL DEFAULT 'weekly',
                    day_of_week INTEGER,
                    day_of_month INTEGER,
                    hour_of_day INTEGER DEFAULT 9,
                    window_days INTEGER DEFAULT 30,
                    incident_limit INTEGER DEFAULT 10,
                    recipients TEXT,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    last_run TIMESTAMPTZ,
                    next_run TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS soar_policies (
                    tenant_id TEXT PRIMARY KEY,
                    config JSONB NOT NULL,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS shared_threats (
                    ip TEXT PRIMARY KEY,
                    source_tenant TEXT,
                    category TEXT,
                    risk INT NOT NULL DEFAULT 100,
                    status TEXT NOT NULL DEFAULT 'critical',
                    source TEXT,
                    reason TEXT,
                    first_seen TIMESTAMPTZ DEFAULT NOW(),
                    last_seen TIMESTAMPTZ DEFAULT NOW(),
                    meta JSONB DEFAULT '{}'::jsonb
                );

                ALTER TABLE lead_captures ADD COLUMN IF NOT EXISTS tenant_id TEXT;
                ALTER TABLE lead_captures ADD COLUMN IF NOT EXISTS converted_to_signup BOOLEAN NOT NULL DEFAULT FALSE;
                ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS day_of_month INTEGER;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_events_event_id ON billing_events (stripe_event_id) WHERE stripe_event_id IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_shared_threats_status_risk ON shared_threats (status, risk DESC, last_seen DESC);

                ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_id TEXT;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id TEXT;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ DEFAULT NOW();
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS responded_at TIMESTAMPTZ;
                ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id TEXT;
                ALTER TABLE incidents ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ DEFAULT NOW();
                ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT NOW();
                ALTER TABLE incidents ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ DEFAULT NOW();
                ALTER TABLE incidents ADD COLUMN IF NOT EXISTS responded_at TIMESTAMPTZ;
                """
            )
        conn.commit()

    seed_demo_data()


def seed_demo_data():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM tenants WHERE id=%s", ("demo-corp",))
            tenant = cur.fetchone()
            if not tenant:
                cur.execute(
                    "INSERT INTO tenants (id, name, plan, status, stripe_customer_id) VALUES (%s, %s, %s, %s, %s)",
                    ("demo-corp", "Demo Corp", "enterprise", "active", "cus_demo_001"),
                )

            demo_users = [
                ("u-owner", "owner@company.com", "owner1234", "owner"),
                ("u-admin", "admin@company.com", "admin123", "admin"),
                ("u-analyst", "analyst@company.com", "analyst123", "analyst"),
                ("u-viewer", "viewer@company.com", "viewer123", "viewer"),
            ]
            for uid, email, password, role in demo_users:
                cur.execute("SELECT id FROM users WHERE id=%s", (uid,))
                if not cur.fetchone():
                    cur.execute(
                        "INSERT INTO users (id, tenant_id, email, password, role) VALUES (%s, %s, %s, %s, %s)",
                        (uid, "demo-corp", email, hash_password(password), role),
                    )

            cur.execute("SELECT id FROM api_keys WHERE tenant_id=%s", ("demo-corp",))
            if not cur.fetchone():
                cur.execute(
                    "INSERT INTO api_keys (tenant_id, key) VALUES (%s, %s)",
                    ("demo-corp", _generate_api_key()),
                )

            cur.execute("SELECT id FROM incidents WHERE tenant_id=%s LIMIT 1", ("demo-corp",))
            if not cur.fetchone():
                cur.execute(
                    """
                    INSERT INTO incidents (tenant_id, entity, severity, status, story, assigned_to, notes)
                    VALUES
                    (%s, %s, %s, %s, %s, %s, %s),
                    (%s, %s, %s, %s, %s, %s, %s),
                    (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        "demo-corp", "sarah.chen", "high", "open", json.dumps({"scenario": "phishing attack"}), "u-analyst", json.dumps([]),
                        "demo-corp", "devops.user", "critical", "open", json.dumps({"scenario": "account takeover"}), "u-admin", json.dumps([]),
                        "demo-corp", "host-221", "high", "open", json.dumps({"scenario": "lateral movement"}), "u-analyst", json.dumps([]),
                    ),
                )

        conn.commit()


def get_tenant(tenant_id: str | None = Header(default=None, alias="X-Tenant-ID")) -> str:
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing X-Tenant-ID header")
    return tenant_id


def fetch_tenant(tenant_id: str) -> dict:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM tenants WHERE id=%s", (tenant_id,))
            tenant = cur.fetchone()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def check_plan(tenant: dict, feature: str):
    if tenant["plan"] == "free" and feature == "advanced_detection":
        raise HTTPException(status_code=402, detail="Upgrade required for advanced_detection")


def tenant_from_stripe_customer(stripe_customer_id: str | None) -> dict | None:
    if not stripe_customer_id:
        return None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM tenants WHERE stripe_customer_id=%s", (stripe_customer_id,))
            return cur.fetchone()


def verify_stripe_signature(payload: bytes, signature_header: str | None):
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        return

    tolerance = int(os.getenv("STRIPE_WEBHOOK_TOLERANCE_SECONDS", "300"))

    # Prefer Stripe's official parser when available.
    if stripe:
        try:
            stripe.Webhook.construct_event(payload, signature_header, secret, tolerance=tolerance)
            return
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid Stripe webhook: {exc}")

    if not signature_header:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature")

    parts = dict(item.split("=", 1) for item in signature_header.split(",") if "=" in item)
    timestamp = parts.get("t")
    sig = parts.get("v1")
    if not timestamp or not sig:
        raise HTTPException(status_code=400, detail="Invalid Stripe-Signature")

    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Stripe timestamp")

    now_ts = int(now_utc().timestamp())
    if abs(now_ts - ts) > tolerance:
        raise HTTPException(status_code=400, detail="Stripe signature expired")

    signed_payload = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=400, detail="Webhook signature mismatch")


def webhook_fingerprint(signature_header: str | None, payload: bytes, event_id: str | None) -> str | None:
    if event_id:
        return f"event:{event_id}"
    if not signature_header:
        return None
    base = f"{signature_header}:{hashlib.sha256(payload).hexdigest()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def register_webhook_fingerprint(fingerprint: str | None) -> bool:
    if not fingerprint:
        return False
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM webhook_replays WHERE fingerprint=%s", (fingerprint,))
            if cur.fetchone():
                return True
            cur.execute("INSERT INTO webhook_replays (fingerprint) VALUES (%s)", (fingerprint,))
        conn.commit()
    return False


def cleanup_webhook_replays() -> int:
    ttl_days = int(os.getenv("WEBHOOK_REPLAY_TTL_DAYS", "7"))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM webhook_replays WHERE created_at < NOW() - (%s * INTERVAL '1 day') RETURNING id",
                (ttl_days,),
            )
            deleted = cur.fetchall()
        conn.commit()
    return len(deleted)


def record_webhook_metric(
    status: str,
    reason: str | None = None,
    tenant_id: str | None = None,
    stripe_event_id: str | None = None,
    event_type: str | None = None,
    fingerprint: str | None = None,
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO webhook_metrics (tenant_id, stripe_event_id, event_type, status, reason, fingerprint) VALUES (%s, %s, %s, %s, %s, %s)",
                (tenant_id, stripe_event_id, event_type, status, reason, fingerprint),
            )
        conn.commit()


def map_plan_from_event(obj: dict) -> str:
    metadata = obj.get("metadata") or {}
    requested = (metadata.get("plan") or "").lower()
    if requested in VALID_PLANS:
        return requested

    price_ids = json.dumps(obj)
    if "enterprise" in price_ids:
        return "enterprise"
    if "pro" in price_ids:
        return "pro"
    return "free"


def get_current_user(
    tenant_id: str = Depends(get_tenant),
    authorization: str | None = Header(default=None),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.replace("Bearer ", "")
    try:
        claims = verify_token(token, token_type="access")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, tenant_id, email, role FROM users WHERE id=%s", (claims.get("sub"),))
            user = cur.fetchone()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    if is_jit_revoked(tenant_id, user["id"]):
        raise HTTPException(status_code=401, detail="Session revoked by JIT policy")
    return user


def require_action(action: str):
    def dep(user=Depends(get_current_user)):
        try:
            authorize(user, action)
        except PermissionError:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return dep


def validate_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    tenant_id: str = Depends(get_tenant),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM api_keys WHERE key=%s", (x_api_key,))
            key = cur.fetchone()
    if not key or key["tenant_id"] != tenant_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return key


def _generate_api_key() -> str:
    return f"sk_live_{secrets.token_urlsafe(24)}"


def log_action(tenant_id: str, user_id: str | None, action: str, resource: str, meta: dict | None = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_logs (tenant_id, user_id, action, resource, meta) VALUES (%s, %s, %s, %s, %s)",
                (tenant_id, user_id, action, resource, json.dumps(meta or {})),
            )
        conn.commit()


def load_rules() -> list[dict]:
    if not RULES_DIR.exists():
        return []
    rules = []
    for fpath in RULES_DIR.rglob("*"):
        if not fpath.is_file() or fpath.suffix.lower() not in {".yaml", ".yml", ".json"}:
            continue
        raw = fpath.read_text(encoding="utf-8")
        item = yaml.safe_load(raw) if fpath.suffix.lower() in {".yaml", ".yml"} else json.loads(raw)
        item["pack"] = str(fpath.parent.relative_to(RULES_DIR)).replace("\\", "/")
        item["id"] = item.get("id") or fpath.stem
        rules.append(item)
    return rules


def rate_limit_key(request: Request) -> str:
    client = request.client.host if request.client else "unknown"
    return f"{client}:{request.url.path}"


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    enforce_https = os.getenv("ENFORCE_HTTPS", "false").lower() == "true"
    allow_insecure = os.getenv("ALLOW_INSECURE_HTTP", "false").lower() == "true"
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if enforce_https and not allow_insecure and proto != "https":
        raise HTTPException(status_code=400, detail="HTTPS required")

    if request.url.path.startswith("/health"):
        return await call_next(request)

    max_requests = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
    key = rate_limit_key(request)
    now = now_utc()
    cutoff = now - timedelta(minutes=1)
    window = [t for t in RATE_LIMITS.get(key, []) if t > cutoff]
    if len(window) >= max_requests:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    window.append(now)
    RATE_LIMITS[key] = window
    return await call_next(request)


_scheduler: "BackgroundScheduler | None" = None


def execute_due_report_schedules() -> dict:
    """Execute all currently due and enabled report schedules, returning a summary."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM report_schedules
                WHERE enabled = TRUE
                  AND next_run IS NOT NULL
                  AND next_run <= NOW()
                ORDER BY next_run ASC
                """
            )
            due_ids = [row["id"] for row in cur.fetchall()]

    executed_ids = []
    failures = []
    for schedule_id in due_ids:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    run_report_schedule_export(cur, schedule_id)
                    conn.commit()
            executed_ids.append(schedule_id)
        except Exception as exc:  # noqa: BLE001
            failures.append({"schedule_id": schedule_id, "error": str(exc)})

    return {
        "found": len(due_ids),
        "executed_count": len(executed_ids),
        "failed_count": len(failures),
        "executed_schedule_ids": executed_ids,
        "failures": failures,
    }


def _fire_due_schedules() -> None:
    """Query enabled schedules whose next_run is past and execute each one."""
    try:
        summary = execute_due_report_schedules()
        if summary["executed_count"] or summary["failed_count"]:
            print(
                f"[scheduler] due run summary found={summary['found']} executed={summary['executed_count']} failed={summary['failed_count']}",
                flush=True,
            )
    except Exception as exc:  # noqa: BLE001
        print(f"[scheduler] error running due schedules: {exc}", flush=True)


@app.on_event("startup")
def startup_event():
    global _scheduler
    init_db()
    cleanup_webhook_replays()
    enforce_security_policy()
    if BackgroundScheduler is not None:
        _scheduler = BackgroundScheduler(job_defaults={"misfire_grace_time": 30})
        _scheduler.add_job(_fire_due_schedules, "interval", minutes=1, id="fire_due_schedules")
        _scheduler.start()


@app.on_event("shutdown")
def shutdown_event():
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=False)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "api-gateway",
        "ts": datetime.now(timezone.utc).isoformat(),
        "security_warnings": SECURITY_WARNINGS,
    }


def create_admin_access_token(jti: str) -> str:
    secret = os.getenv("ADMIN_SESSION_SECRET", os.getenv("JWT_SECRET", "change-me-in-production"))
    payload = {
        "sub": "internal-admin",
        "token_type": "admin_access",
        "jti": jti,
        "exp": now_utc() + timedelta(minutes=60),
    }
    return jwt.encode(payload, secret, algorithm=ADMIN_SESSION_ALG)


def create_admin_refresh_token(jti: str) -> str:
    secret = os.getenv("ADMIN_SESSION_SECRET", os.getenv("JWT_SECRET", "change-me-in-production"))
    payload = {
        "sub": "internal-admin",
        "token_type": "admin_refresh",
        "jti": jti,
        "exp": now_utc() + timedelta(days=7),
    }
    return jwt.encode(payload, secret, algorithm=ADMIN_SESSION_ALG)


def verify_admin_session_token(token: str, token_type: str = "admin_access") -> dict | None:
    secret = os.getenv("ADMIN_SESSION_SECRET", os.getenv("JWT_SECRET", "change-me-in-production"))
    try:
        payload = jwt.decode(token, secret, algorithms=[ADMIN_SESSION_ALG])
    except JWTError:
        return None

    if payload.get("token_type") != token_type or payload.get("sub") != "internal-admin":
        return None

    jti = payload.get("jti")
    if not jti:
        return None

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT revoked, expires_at FROM admin_sessions WHERE jti=%s", (jti,))
            row = cur.fetchone()
    if not row:
        return None
    if row["revoked"]:
        return None
    if row["expires_at"] < now_utc():
        return None
    return payload


def create_admin_session_pair() -> dict:
    jti = uuid4().hex
    expires_at = now_utc() + timedelta(days=7)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO admin_sessions (jti, expires_at) VALUES (%s, %s)", (jti, expires_at))
        conn.commit()
    return {
        "access_token": create_admin_access_token(jti),
        "refresh_token": create_admin_refresh_token(jti),
        "token_type": "bearer",
        "expires_in_seconds": 3600,
    }


def revoke_admin_session(jti: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE admin_sessions SET revoked=TRUE WHERE jti=%s", (jti,))
        conn.commit()


def require_internal_admin_token(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    authorization: str | None = Header(default=None),
):
    expected = os.getenv("INTERNAL_ADMIN_TOKEN", "dev-admin-token")
    if authorization and authorization.startswith("Bearer "):
        if verify_admin_session_token(authorization.replace("Bearer ", ""), token_type="admin_access"):
            return True
    if x_admin_token and x_admin_token == expected:
        return True
    raise HTTPException(status_code=403, detail="Forbidden")


@app.post("/admin/session")
def create_admin_session(body: AdminSessionBody):
    expected = os.getenv("INTERNAL_ADMIN_TOKEN", "dev-admin-token")
    if body.admin_token != expected:
        raise HTTPException(status_code=403, detail="Forbidden")
    return create_admin_session_pair()


@app.post("/admin/session/refresh")
def refresh_admin_session(body: AdminSessionRefreshBody):
    claims = verify_admin_session_token(body.refresh_token, token_type="admin_refresh")
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid admin refresh token")
    old_jti = claims.get("jti")
    if old_jti:
        revoke_admin_session(old_jti)
    return create_admin_session_pair()


@app.post("/admin/session/revoke")
def revoke_admin(body: AdminSessionRevokeBody):
    claims = verify_admin_session_token(body.refresh_token, token_type="admin_refresh")
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid admin refresh token")
    revoke_admin_session(claims.get("jti"))
    return {"revoked": True}


def mark_lead_converted(email: str, tenant_id: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE lead_captures
                SET tenant_id=%s, converted_to_signup=TRUE
                WHERE id = (
                    SELECT id FROM lead_captures WHERE lower(email)=lower(%s) ORDER BY id DESC LIMIT 1
                )
                """,
                (tenant_id, email),
            )
        conn.commit()


def has_lead_for_email(email: str) -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM lead_captures WHERE lower(email)=lower(%s) ORDER BY id DESC LIMIT 1", (email,))
            return cur.fetchone() is not None


def map_source_to_plan(source: str | None, default_plan: str) -> str:
    if default_plan in {"pro", "enterprise"}:
        return default_plan
    if source == "partner":
        return "pro"
    return default_plan


def _scenario_catalog() -> list[dict]:
    return [
        {
            "id": "credential_compromise_chain",
            "name": "Credential Compromise Chain",
            "description": "Phishing email click followed by login anomaly and exfiltration.",
            "safety": "synthetic-only",
            "expected_detections": ["SIGMA-001", "SIGMA-004", "SIGMA-002", "SIGMA-003"],
        },
        {
            "id": "impossible_travel_burst",
            "name": "Impossible Travel Burst",
            "description": "Multiple impossible-travel login anomalies in short succession.",
            "safety": "synthetic-only",
            "expected_detections": ["SIGMA-002"],
        },
        {
            "id": "insider_data_exfiltration",
            "name": "Insider Data Exfiltration",
            "description": "Sensitive file access and outbound transfer pattern.",
            "safety": "synthetic-only",
            "expected_detections": ["SIGMA-005", "SIGMA-003"],
        },
        {
            "id": "password_spray_wave",
            "name": "Password Spray Wave",
            "description": "Coordinated login anomalies across multiple identities.",
            "safety": "synthetic-only",
            "expected_detections": ["SIGMA-002"],
        },
        {
            "id": "suspicious_oauth_app",
            "name": "Suspicious OAuth Application",
            "description": "Untrusted OAuth consent followed by suspicious account activity.",
            "safety": "synthetic-only",
            "expected_detections": ["SIGMA-006", "SIGMA-002"],
        },
        {
            "id": "powershell_execution_chain",
            "name": "PowerShell Execution Chain",
            "description": "Encoded PowerShell execution leading to outbound exfiltration.",
            "safety": "synthetic-only",
            "expected_detections": ["SIGMA-007", "SIGMA-003"],
        },
    ]


def _build_scenario_events(body: AdminDemoBody, iteration: int) -> tuple[list[dict], list[str]]:
    scenario = body.scenario
    base_user = body.user_id
    source_country = body.source_country
    destination_country = body.destination_country
    ip_suffix = 9 + iteration
    timeline: list[str] = []

    if scenario == "credential_compromise_chain":
        events = [
            {
                "user_id": base_user,
                "event_type": "email",
                "subject": "URGENT: Security policy update",
                "sender_domain": "comp-security-check.net",
                "raw": {"stage": "email_delivered", "scenario": scenario, "iteration": iteration},
            },
            {
                "user_id": base_user,
                "event_type": "email_click",
                "subject": "Clicked suspicious link",
                "sender_domain": "comp-security-check.net",
                "raw": {"stage": "link_clicked", "scenario": scenario, "iteration": iteration},
            },
            {
                "user_id": base_user,
                "event_type": "login_anomaly",
                "ip": f"198.51.100.{ip_suffix}",
                "raw": {
                    "from": source_country,
                    "to": destination_country,
                    "geo_mismatch": True,
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
            {
                "user_id": base_user,
                "event_type": "data_exfil",
                "ip": f"198.51.100.{ip_suffix}",
                "raw": {
                    "stage": "file_download",
                    "sensitive": True,
                    "file": f"finance_q{(iteration % 4) + 1}.xlsx",
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
        ]
        timeline = [
            "Email delivered",
            "Link clicked",
            f"Login anomaly {source_country} -> {destination_country}",
            "Sensitive file download",
        ]
    elif scenario == "impossible_travel_burst":
        events = [
            {
                "user_id": base_user,
                "event_type": "login_anomaly",
                "ip": f"203.0.113.{20 + iteration}",
                "raw": {
                    "from": source_country,
                    "to": destination_country,
                    "geo_mismatch": True,
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
            {
                "user_id": base_user,
                "event_type": "login_anomaly",
                "ip": f"203.0.113.{30 + iteration}",
                "raw": {
                    "from": destination_country,
                    "to": "JP",
                    "geo_mismatch": True,
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
            {
                "user_id": base_user,
                "event_type": "login_anomaly",
                "ip": f"203.0.113.{40 + iteration}",
                "raw": {
                    "from": "JP",
                    "to": "US",
                    "geo_mismatch": True,
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
        ]
        timeline = ["Impossible travel event #1", "Impossible travel event #2", "Impossible travel event #3"]
    elif scenario == "insider_data_exfiltration":
        events = [
            {
                "user_id": base_user,
                "event_type": "file_download",
                "raw": {
                    "sensitive": True,
                    "file": "payroll_master.csv",
                    "stage": "bulk_access",
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
            {
                "user_id": base_user,
                "event_type": "data_exfil",
                "ip": f"198.51.100.{60 + iteration}",
                "raw": {
                    "sensitive": True,
                    "channel": "https_upload",
                    "bytes": 25000000,
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
        ]
        timeline = ["Sensitive file accessed", "Large outbound exfiltration"]
    elif scenario == "suspicious_oauth_app":
        events = [
            {
                "user_id": base_user,
                "event_type": "oauth_grant",
                "raw": {
                    "untrusted_app": True,
                    "app_name": "DocuSync Pro",
                    "scope": "mail.read files.read.all offline_access",
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
            {
                "user_id": base_user,
                "event_type": "login_anomaly",
                "ip": f"198.51.100.{70 + iteration}",
                "raw": {
                    "from": source_country,
                    "to": destination_country,
                    "geo_mismatch": True,
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
        ]
        timeline = ["OAuth consent granted to untrusted app", "Follow-on impossible-travel login detected"]
    elif scenario == "powershell_execution_chain":
        events = [
            {
                "user_id": base_user,
                "event_type": "powershell_exec",
                "raw": {
                    "encoded_command": True,
                    "command": "powershell -enc SQBFAFgA",
                    "host": "wkstn-22",
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
            {
                "user_id": base_user,
                "event_type": "data_exfil",
                "ip": f"203.0.113.{90 + iteration}",
                "raw": {
                    "channel": "https_upload",
                    "bytes": 42000000,
                    "sensitive": True,
                    "scenario": scenario,
                    "iteration": iteration,
                },
            },
        ]
        timeline = ["Encoded PowerShell executed", "Outbound exfiltration channel observed"]
    else:
        events = [
            {
                "user_id": f"spray.user{iteration}.1",
                "event_type": "login_anomaly",
                "ip": f"203.0.113.{80 + iteration}",
                "raw": {"geo_mismatch": True, "source": "password_spray", "scenario": scenario, "iteration": iteration},
            },
            {
                "user_id": f"spray.user{iteration}.2",
                "event_type": "login_anomaly",
                "ip": f"203.0.113.{80 + iteration}",
                "raw": {"geo_mismatch": True, "source": "password_spray", "scenario": scenario, "iteration": iteration},
            },
            {
                "user_id": f"spray.user{iteration}.3",
                "event_type": "login_anomaly",
                "ip": f"203.0.113.{80 + iteration}",
                "raw": {"geo_mismatch": True, "source": "password_spray", "scenario": scenario, "iteration": iteration},
            },
        ]
        timeline = ["Spray attempt user 1", "Spray attempt user 2", "Spray attempt user 3"]

    if body.include_noise:
        events.append(
            {
                "user_id": "normal.user",
                "event_type": "email",
                "subject": "Quarterly newsletter",
                "sender_domain": "company.com",
                "raw": {"benign": True, "scenario": "noise", "iteration": iteration},
            }
        )
        timeline.append("Benign background activity")

    return events, timeline


async def _run_demo_attack_flow(tenant_id: str, body: AdminDemoBody) -> dict:
    outcomes = []
    timeline = []
    emitted_events = 0

    for idx in range(body.iterations):
        events, local_timeline = _build_scenario_events(body, idx)
        timeline.extend(local_timeline)
        emitted_events += len(events)

        if body.dry_run:
            continue

        for evt in events:
            model = IngestEvent(**evt)
            result = await ingest(model, tenant_id=tenant_id, _key={"tenant_id": tenant_id})
            outcomes.append(result)

    return {
        "tenant_id": tenant_id,
        "scenario": body.scenario,
        "iterations": body.iterations,
        "include_noise": body.include_noise,
        "dry_run": body.dry_run,
        "safe_lab": True,
        "event_count": emitted_events,
        "timeline": timeline,
        "outcomes": outcomes,
    }


def _scenario_ids() -> list[str]:
    return [item["id"] for item in _scenario_catalog()]


def _normalize_live_scenarios(requested: list[str] | None) -> list[str]:
    available = set(_scenario_ids())
    defaults = [
        "credential_compromise_chain",
        "impossible_travel_burst",
        "suspicious_oauth_app",
        "powershell_execution_chain",
    ]
    if not requested:
        return [item for item in defaults if item in available]
    normalized = [item for item in requested if item in available]
    return normalized or [item for item in defaults if item in available]


async def _live_simulation_worker(tenant_id: str) -> None:
    cursor = 0
    while True:
        state = LIVE_SIMULATION_STATE.get(tenant_id) or {}
        if not state.get("running"):
            return

        scenarios = state.get("scenarios") or _normalize_live_scenarios(None)
        if not scenarios:
            return
        scenario = scenarios[cursor % len(scenarios)]
        cursor += 1

        body = AdminDemoBody(
            user_id="demo.user",
            source_country="UK",
            destination_country="US",
            scenario=scenario,
            iterations=1,
            include_noise=bool(state.get("include_noise", True)),
            dry_run=False,
        )

        try:
            await _run_demo_attack_flow(tenant_id, body)
            state["last_emitted_at"] = now_utc().isoformat()
            state["last_scenario"] = scenario
            state["emitted_count"] = int(state.get("emitted_count", 0)) + 1
            LIVE_SIMULATION_STATE[tenant_id] = state
        except Exception as exc:  # noqa: BLE001
            state["last_error"] = str(exc)
            LIVE_SIMULATION_STATE[tenant_id] = state

        await asyncio.sleep(int(state.get("interval_seconds", 25)))


async def _stop_live_simulation(tenant_id: str) -> None:
    task = LIVE_SIMULATION_TASKS.get(tenant_id)
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    LIVE_SIMULATION_TASKS.pop(tenant_id, None)


def reset_demo_tenant_data(regenerate_api_key: bool = False) -> dict:
    tenant_id = "demo-corp"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM alerts WHERE tenant_id=%s", (tenant_id,))
            cur.execute("DELETE FROM incidents WHERE tenant_id=%s", (tenant_id,))
            cur.execute("DELETE FROM events WHERE tenant_id=%s", (tenant_id,))
            cur.execute("DELETE FROM audit_logs WHERE tenant_id=%s", (tenant_id,))

            if regenerate_api_key:
                cur.execute("DELETE FROM api_keys WHERE tenant_id=%s", (tenant_id,))
                cur.execute("INSERT INTO api_keys (tenant_id, key) VALUES (%s, %s)", (tenant_id, _generate_api_key()))

            cur.execute("SELECT key FROM api_keys WHERE tenant_id=%s ORDER BY id DESC LIMIT 1", (tenant_id,))
            key_row = cur.fetchone()

            baseline = [
                ("sarah.chen", "high", "open", {"scenario": "phishing attack"}, "u-analyst"),
                ("devops.user", "critical", "open", {"scenario": "account takeover"}, "u-admin"),
                ("host-221", "high", "open", {"scenario": "lateral movement"}, "u-analyst"),
            ]
            for entity, sev, status, story, assignee in baseline:
                cur.execute(
                    "INSERT INTO incidents (tenant_id, entity, severity, status, story, assigned_to, notes) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (tenant_id, entity, sev, status, json.dumps(story), assignee, json.dumps([])),
                )
        conn.commit()

    return {"tenant_id": tenant_id, "api_key": key_row["key"] if key_row else None, "baseline_incidents": 3}


@app.post("/public/waitlist")
def capture_waitlist_lead(body: WaitlistLeadBody):
    source = body.source if body.source in VALID_LEAD_SOURCES else "unknown"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO lead_captures (company, email, role, source) VALUES (%s, %s, %s, %s) RETURNING id, created_at",
                (body.company, body.email, body.role, source),
            )
            lead = cur.fetchone()
        conn.commit()

    return {"status": "captured", "lead_id": lead["id"], "created_at": lead["created_at"].isoformat()}


@app.post("/public/analytics")
def capture_analytics_event(body: AnalyticsEventBody, request: Request):
    visitor_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO analytics_events (event_name, page, visitor_ip, user_agent, meta) VALUES (%s, %s, %s, %s, %s) RETURNING id, created_at",
                (body.event_name, body.page, visitor_ip, user_agent, json.dumps(body.meta or {})),
            )
            evt = cur.fetchone()
        conn.commit()

    return {"status": "captured", "event_id": evt["id"], "created_at": evt["created_at"].isoformat()}


@app.post("/auth/login")
def login(body: LoginBody, tenant_id: str = Depends(get_tenant)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, tenant_id, email, password, role FROM users WHERE tenant_id=%s AND email=%s",
                (tenant_id, body.email),
            )
            user = cur.fetchone()
    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # One-time migration path for old plaintext passwords.
    if not is_password_hash(user["password"]):
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password=%s WHERE id=%s", (hash_password(body.password), user["id"]))
            conn.commit()

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    log_action(tenant_id, user["id"], "auth.login", "users")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "tenant_id": user["tenant_id"],
            "email": user["email"],
            "role": user["role"],
        },
    }


@app.post("/auth/refresh")
def refresh(body: RefreshBody, tenant_id: str = Depends(get_tenant)):
    try:
        claims = verify_token(body.refresh_token, token_type="refresh")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, tenant_id, email, role FROM users WHERE id=%s", (claims.get("sub"),))
            user = cur.fetchone()
    if not user or user["tenant_id"] != tenant_id:
        raise HTTPException(status_code=401, detail="Invalid refresh context")

    access_token = create_access_token(user)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/signup")
def signup(body: SignupBody):
    plan = body.plan.lower()
    if plan not in VALID_PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    attributed = has_lead_for_email(body.email)
    if attributed:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT source FROM lead_captures WHERE lower(email)=lower(%s) ORDER BY id DESC LIMIT 1", (body.email,))
                row = cur.fetchone()
        plan = map_source_to_plan((row or {}).get("source") if row else None, plan)

    tenant_id = f"tenant-{uuid4().hex[:10]}"
    user_id = f"u-{uuid4().hex[:10]}"
    api_key = _generate_api_key()
    stripe_customer_id = f"cus_{uuid4().hex[:12]}"

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (id, name, plan, status, stripe_customer_id) VALUES (%s, %s, %s, %s, %s)",
                (tenant_id, body.company, plan, "active", stripe_customer_id),
            )
            cur.execute(
                "INSERT INTO users (id, tenant_id, email, password, role) VALUES (%s, %s, %s, %s, %s)",
                (user_id, tenant_id, body.email, hash_password(body.password), "owner"),
            )
            cur.execute(
                "INSERT INTO api_keys (tenant_id, key) VALUES (%s, %s)",
                (tenant_id, api_key),
            )
        conn.commit()

    if attributed:
        mark_lead_converted(body.email, tenant_id)

    log_action(tenant_id, user_id, "tenant.signup", "tenants", {"plan": plan})
    return {
        "tenant_id": tenant_id,
        "admin_user_id": user_id,
        "api_key": api_key,
        "plan": plan,
        "stripe_customer_id": stripe_customer_id,
        "lead_attributed": attributed,
    }


@app.post("/billing/stripe/webhook")
async def stripe_webhook(request: Request, stripe_signature: str | None = Header(default=None, alias="Stripe-Signature")):
    payload = await request.body()
    try:
        verify_stripe_signature(payload, stripe_signature)
    except HTTPException as exc:
        record_webhook_metric(status="rejected", reason=f"signature:{exc.detail}")
        raise

    try:
        event = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    event_type = event.get("type", "unknown")
    stripe_event_id = event.get("id")
    replay_fp = webhook_fingerprint(stripe_signature, payload, stripe_event_id)
    if register_webhook_fingerprint(replay_fp):
        record_webhook_metric(
            status="duplicate",
            reason="replay_fingerprint",
            stripe_event_id=stripe_event_id,
            event_type=event_type,
            fingerprint=replay_fp,
        )
        return {"received": True, "duplicate": True, "duplicate_reason": "replay_fingerprint", "event_type": event_type}

    obj = ((event.get("data") or {}).get("object") or {})
    stripe_customer_id = obj.get("customer")
    tenant = tenant_from_stripe_customer(stripe_customer_id)

    update_plan = None
    update_status = None
    if event_type in {"customer.subscription.created", "customer.subscription.updated", "checkout.session.completed"}:
        update_plan = map_plan_from_event(obj)
        update_status = (obj.get("status") or "active").lower()
        if update_status not in {"trialing", "active", "past_due", "canceled"}:
            update_status = "active"
    elif event_type in {"customer.subscription.deleted"}:
        update_plan = "free"
        update_status = "canceled"

    with get_conn() as conn:
        with conn.cursor() as cur:
            if stripe_event_id:
                cur.execute("SELECT id FROM billing_events WHERE stripe_event_id=%s", (stripe_event_id,))
                if cur.fetchone():
                    record_webhook_metric(
                        status="duplicate",
                        reason="event_id",
                        tenant_id=tenant["id"] if tenant else None,
                        stripe_event_id=stripe_event_id,
                        event_type=event_type,
                        fingerprint=replay_fp,
                    )
                    return {"received": True, "duplicate": True, "event_type": event_type, "tenant_id": tenant["id"] if tenant else None}

            cur.execute(
                "INSERT INTO billing_events (tenant_id, stripe_event_id, event_type, payload) VALUES (%s, %s, %s, %s)",
                (tenant["id"] if tenant else None, stripe_event_id, event_type, json.dumps(event)),
            )

            if tenant and update_plan and update_status:
                cur.execute(
                    "UPDATE tenants SET plan=%s, status=%s WHERE id=%s",
                    (update_plan, update_status, tenant["id"]),
                )
        conn.commit()

    if tenant:
        log_action(
            tenant["id"],
            None,
            "billing.webhook",
            "tenants/subscription",
            {"event_type": event_type, "stripe_event_id": event.get("id")},
        )

    record_webhook_metric(
        status="accepted",
        tenant_id=tenant["id"] if tenant else None,
        stripe_event_id=stripe_event_id,
        event_type=event_type,
        fingerprint=replay_fp,
    )

    return {"received": True, "event_type": event_type, "tenant_id": tenant["id"] if tenant else None}


@app.post("/ingest")
async def ingest(event: IngestEvent, tenant_id: str = Depends(get_tenant), _key=Depends(validate_api_key)):
    tenant = fetch_tenant(tenant_id)
    check_plan(tenant, "advanced_detection")

    payload = event.model_dump()
    payload["tenant_id"] = tenant_id
    payload["timestamp"] = now_utc().isoformat()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO events (tenant_id, user_id, type, raw) VALUES (%s, %s, %s, %s) RETURNING id, timestamp",
                (tenant_id, event.user_id, event.event_type, json.dumps(payload)),
            )
            saved_event = cur.fetchone()

            alerts = detect(payload, rules=load_rules())
            alert_rows = []
            for a in alerts:
                cur.execute(
                    """
                    INSERT INTO alerts (tenant_id, rule_id, severity, confidence, mitre, summary, event_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id, tenant_id, rule_id, severity, confidence, mitre, summary, event_id, timestamp
                    """,
                    (tenant_id, a["rule_id"], a["severity"], a["confidence"], a["mitre"], a["summary"], saved_event["id"]),
                )
                alert_rows.append(cur.fetchone())

            cur.execute(
                "SELECT id, user_id, type, raw, timestamp FROM events WHERE tenant_id=%s ORDER BY id DESC LIMIT 30",
                (tenant_id,),
            )
            recent_events = [
                {
                    "id": e["id"],
                    "user_id": e["user_id"],
                    "event_type": e["type"],
                    "ip": ((e.get("raw") or {}).get("ip") if isinstance(e.get("raw"), dict) else None),
                    "timestamp": e["timestamp"].isoformat(),
                }
                for e in cur.fetchall()
            ]

            incident = correlate(recent_events, alerts)
            incident_row = None
            if incident:
                entity = incident.get("entity") or "unknown"
                incoming_story = incident.get("story") or {}

                cur.execute(
                    """
                                        SELECT id, tenant_id, entity, severity, status, story, assigned_to, responded_at, timestamp
                    FROM incidents
                    WHERE tenant_id=%s
                      AND entity=%s
                                            AND status IN ('open', 'investigating')
                      AND last_seen >= NOW() - INTERVAL '30 minutes'
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (tenant_id, entity),
                )
                existing_incident = cur.fetchone()

                if existing_incident:
                    existing_story = existing_incident.get("story")
                    if isinstance(existing_story, str):
                        try:
                            existing_story = json.loads(existing_story)
                        except Exception:  # noqa: BLE001
                            existing_story = {}
                    existing_story = existing_story if isinstance(existing_story, dict) else {}

                    merged_users = list({*(existing_story.get("users") or []), *(incoming_story.get("users") or [])})
                    merged_ips = list({*(existing_story.get("ips") or []), *(incoming_story.get("ips") or [])})
                    merged_stages = [*(existing_story.get("stages") or []), *(incoming_story.get("stages") or [])][-12:]
                    merged_story = {
                        "users": merged_users,
                        "ips": merged_ips,
                        "stages": merged_stages,
                    }
                    merged_severity = _max_severity(existing_incident.get("severity"), incident.get("severity"))

                    cur.execute(
                        """
                        UPDATE incidents
                        SET severity=%s,
                            story=%s,
                            status='open',
                            last_seen=NOW()
                        WHERE id=%s
                        RETURNING id, tenant_id, entity, severity, status, story, assigned_to, responded_at, timestamp
                        """,
                        (merged_severity, json.dumps(merged_story), existing_incident["id"]),
                    )
                    incident_row = cur.fetchone()
                else:
                    cur.execute(
                        """
                        INSERT INTO incidents (tenant_id, entity, severity, status, story, assigned_to)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id, tenant_id, entity, severity, status, story, assigned_to, responded_at, timestamp
                        """,
                        (tenant_id, entity, incident["severity"], incident["status"], json.dumps(incoming_story), None),
                    )
                    incident_row = cur.fetchone()

        conn.commit()

    rdb.xadd(f"soc:{tenant_id}:events", {"event": json.dumps(payload)})
    for a in alerts:
        await broadcast(tenant_id, {"kind": "alert", **a})

    context_events = [item for item in recent_events if item.get("user_id") == event.user_id]
    context = _build_entity_contexts(
        [
            {
                "id": item.get("id"),
                "timestamp": item.get("timestamp"),
                "action": item.get("event_type"),
                "actor": {"user": item.get("user_id"), "ip": item.get("ip")},
                "metadata": {"geo": None},
            }
            for item in context_events
        ]
    ).get(event.user_id)

    ml_risk_boost = 0
    risk_score = 0
    patterns = []
    _ml_boost_result = {"anomalies": []}

    # Threat Intel check: if IP matches known bad actor, force max risk + JIT revoke.
    _threat_match = check_threat_intel(event.ip)
    if _threat_match:
        risk_score = 100
        ml_risk_boost = max(ml_risk_boost, 15)
        if event.user_id:
            jit_revoke_user_sessions(tenant_id, event.user_id, reason="threat_intel_match")
        log_action(tenant_id, None, "threat_intel.match", f"events/{saved_event['id']}", {
            "ip": event.ip,
            "source": _threat_match.get("source"),
            "category": _threat_match.get("category"),
            "tags": _threat_match.get("tags"),
            "shared_intelligence": bool(_threat_match.get("shared_intelligence")),
        })
        if int(_threat_match.get("risk") or 0) >= 90 and event.ip:
            _upsert_shared_threat(
                event.ip,
                source_tenant=tenant_id,
                category=_threat_match.get("category") or "unknown",
                risk=int(_threat_match.get("risk") or 100),
                reason="Critical indicator observed in tenant ingest",
            )

    # Diplomat: any critical incident IP is promoted to shared blocklist across tenants.
    if incident_row and (incident_row.get("severity") or "").lower() == "critical" and event.ip:
        _upsert_shared_threat(
            event.ip,
            source_tenant=tenant_id,
            category="critical_incident",
            risk=100,
            reason="IP linked to critical incident in tenant",
        )

    # Sentinel: telemetry event z-score > 3σ auto-enables ghost mode.
    if event.user_id and event.event_type in ("process_start", "network_connection", "net_connect"):
        sentinel_z, sentinel_baseline = _event_frequency_zscore(tenant_id, event.user_id, event.event_type)
        if sentinel_z > 3.0:
            policy = _get_or_create_soar_policy(tenant_id)
            if not policy.get("ghost_mode"):
                policy["ghost_mode"] = True
                _save_soar_policy(tenant_id, policy)
            log_action(tenant_id, None, "sentinel.baseline_deviation", f"events/{saved_event['id']}", {
                "user_id": event.user_id,
                "event_type": event.event_type,
                "z_score": round(sentinel_z, 2),
                "baseline": sentinel_baseline,
                "auto_ghost_mode": True,
                "reason": "Deviation > 3σ from 7-day baseline",
            })
            if incident_row and incident_row.get("severity") in ("critical", "high"):
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE incidents SET status='sandboxed' WHERE id=%s AND tenant_id=%s",
                            (incident_row["id"], tenant_id),
                        )
                    conn.commit()
                incident_row["status"] = "sandboxed"

    if context:
        patterns = _detect_behavior_patterns(context)
        user_alerts = [
            {"severity": item.get("severity"), "summary": item.get("summary")}
            for item in alert_rows
        ]
        risk_score = max(risk_score, _calculate_context_risk(context, user_alerts, patterns))
        # ML anomaly boost: if this user is a statistical outlier in recent traffic, raise risk score
        _ml_boost_result = detect_ml_anomalies(events=[
            {"id": item.get("id"), "user_id": item.get("user_id"),
             "timestamp": item.get("timestamp"), "type": item.get("event_type"), "raw": {}}
            for item in recent_events
        ])
        for _anom in _ml_boost_result.get("anomalies", []):
            if _anom.get("kind") == "user_activity_outlier" and _anom.get("user_id") == event.user_id:
                ml_risk_boost = int(min(15, round(_anom["z_score"] * 3.0)))
                break
        risk_score = min(100, risk_score + ml_risk_boost)

        # JIT auto-revocation: if risk spikes above 90, revoke the user's sessions
        if risk_score >= 90 and event.user_id:
            jit_revoke_user_sessions(tenant_id, event.user_id, reason="automated_risk_spike")

        active_soar_policy = _get_cached_soar_policy(tenant_id)
        selected_playbook = _select_playbook_title(patterns, payload.get("event_type"), active_soar_policy)

        # Compute ML anomaly score for gate check
        _ml_anomaly_score = None
        for _anom in _ml_boost_result.get("anomalies", []):
            if _anom.get("kind") == "user_activity_outlier" and _anom.get("user_id") == event.user_id:
                _ml_anomaly_score = _anom.get("z_score", 0.0)
                break

        auto_respond_decision = _should_auto_respond(
            incident_row, risk_score, patterns, selected_playbook, active_soar_policy,
            ml_anomaly_score=_ml_anomaly_score, tenant_id=tenant_id,
        )

        if auto_respond_decision == "pending_review":
            # ML gate blocked — set incident to pending_review status
            if incident_row:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE incidents SET status='pending_review' WHERE id=%s AND tenant_id=%s",
                            (incident_row["id"], tenant_id),
                        )
                    conn.commit()
                incident_row["status"] = "pending_review"
                await broadcast(tenant_id, {
                    "kind": "soar_ml_gate_block",
                    "incident_id": incident_row["id"],
                    "ml_anomaly_score": _ml_anomaly_score,
                    "playbook": selected_playbook,
                    "status": "Pending Manual Review",
                })

        elif auto_respond_decision is True:
            # Atomically claim the incident for auto-response to prevent concurrent duplicates
            claimed_for_response = False
            previous_incident_status = (incident_row.get("status") or "open") if incident_row else "open"
            if incident_row:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE incidents
                            SET status='responding'
                            WHERE id=%s
                              AND tenant_id=%s
                              AND responded_at IS NULL
                              AND COALESCE(status, '') NOT IN ('responding', 'responded')
                            """,
                            (incident_row["id"], tenant_id),
                        )
                        claimed_for_response = cur.rowcount == 1
                    conn.commit()
                if claimed_for_response:
                    incident_row["status"] = "responding"

            if claimed_for_response:
                incident_payload, event_payload = _build_playbook_inputs(
                    incident_row,
                    payload,
                    patterns,
                    risk_score,
                    selected_playbook,
                    active_soar_policy,
                )
                playbook_result = execute_playbook_for_incident(incident_payload, event_payload)
                playbook_status = playbook_result.get("status", "unknown")

                # Ghost-mode deception for auto-response on critical/high incidents
                _ghost_global = active_soar_policy.get("ghost_mode", False)
                _pb_deception = (active_soar_policy.get("playbooks", {}).get(selected_playbook) or {}).get("deception_enabled", False)
                if (_ghost_global or _pb_deception) and incident_row.get("severity") in ("critical", "high"):
                    playbook_result["ghost_mode"] = True
                    playbook_result["deception_status"] = "sandboxed"
                    playbook_result["original_actions"] = playbook_result.get("actions", [])
                    playbook_result["actions"] = [{"type": "sandbox_proxy", "detail": "Threat actor redirected to deception sandbox"}]
                    with get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE incidents SET status='sandboxed' WHERE id=%s AND tenant_id=%s",
                                (incident_row["id"], tenant_id),
                            )
                        conn.commit()
                    incident_row["status"] = "sandboxed"
                    log_action(tenant_id, None, "soar.ghost_mode_activated", f"incidents/{incident_row['id']}", {"playbook": selected_playbook, "auto": True})
                elif playbook_status == "success":
                    with get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE incidents SET status='responded', responded_at=NOW() WHERE id=%s AND tenant_id=%s AND status='responding'",
                                (incident_row["id"], tenant_id),
                            )
                        conn.commit()
                    incident_row["status"] = "responded"
                    incident_row["responded_at"] = now_utc().isoformat()
                else:
                    # Restore previous status if playbook did not succeed
                    with get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE incidents SET status=%s WHERE id=%s AND tenant_id=%s AND status='responding'",
                                (previous_incident_status, incident_row["id"], tenant_id),
                            )
                        conn.commit()
                    incident_row["status"] = previous_incident_status

                log_response_action(
                    incident_row["id"],
                    "auto_playbook",
                    playbook_status,
                    playbook_result,
                )

                await broadcast(
                    tenant_id,
                    {
                        "kind": "soar_auto_response",
                        "incident_id": incident_row["id"] if incident_row else None,
                        "status": playbook_status,
                        "playbook": playbook_result.get("playbook"),
                        "actions": len(playbook_result.get("actions", [])),
                    },
                )

                log_action(
                    tenant_id,
                    None,
                    "soar.auto_playbook",
                    f"incidents/{incident_row['id']}" if incident_row else "incidents/unknown",
                    {
                        "risk_score": risk_score,
                        "patterns": patterns,
                        "playbook": playbook_result.get("playbook"),
                        "status": playbook_status,
                    },
                )

        await broadcast(
            tenant_id,
            {
                "kind": "intelligence_update",
                "user": event.user_id,
                "risk_score": risk_score,
                "patterns": patterns,
                "ml_risk_boost": ml_risk_boost,
            },
        )

    log_action(tenant_id, None, "event.ingest", "events", {"event_id": saved_event["id"], "alerts": len(alert_rows)})

    # Enrich incident with Geo-IP and Identity metadata
    enriched_data = enrich_incident_context(incident_row, payload)

    return {
        "event": {"id": saved_event["id"], "timestamp": saved_event["timestamp"].isoformat(), **payload},
        "alerts": alert_rows,
        "incident": incident_row,
        "ml_risk_boost": ml_risk_boost,
        "enriched_data": enriched_data,
    }


@app.get("/alerts")
def get_alerts(tenant_id: str = Depends(get_tenant), _user=Depends(require_action("view_incidents"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE tenant_id=%s ORDER BY id DESC LIMIT 200", (tenant_id,))
            return cur.fetchall()


@app.get("/events")
def get_events(
    limit: int = 80,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    safe_limit = max(1, min(limit, 500))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, user_id, type, raw, timestamp FROM events WHERE tenant_id=%s ORDER BY id DESC LIMIT %s",
                (tenant_id, safe_limit),
            )
            rows = cur.fetchall()

    normalized = []
    for row in rows:
        raw = row.get("raw")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:  # noqa: BLE001
                raw = {}
        raw = raw or {}
        payload_raw = raw.get("raw") if isinstance(raw.get("raw"), dict) else {}
        normalized.append(
            {
                "id": row["id"],
                "timestamp": row["timestamp"].isoformat(),
                "event_type": row["type"],
                "user": row.get("user_id"),
                "ip": raw.get("ip") or payload_raw.get("ip"),
                "location": raw.get("from") or raw.get("location") or payload_raw.get("from") or payload_raw.get("location"),
                "raw": raw,
            }
        )
    return normalized


@app.get("/reports/executive/story")
def get_executive_attack_story(
    window_minutes: int = 180,
    event_limit: int = 140,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    return build_executive_attack_story_report(
        tenant_id=tenant_id,
        window_minutes=window_minutes,
        event_limit=event_limit,
    )


@app.get("/reports/executive/story.md")
def download_executive_attack_story_markdown(
    window_minutes: int = 180,
    event_limit: int = 140,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    report = build_executive_attack_story_report(
        tenant_id=tenant_id,
        window_minutes=window_minutes,
        event_limit=event_limit,
    )
    filename = f"executive-attack-story-{tenant_id}.md"
    return PlainTextResponse(
        content=render_executive_story_markdown(report),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/intelligence/overview")
def get_intelligence_overview(
    window_minutes: int = 180,
    event_limit: int = 300,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    safe_window_minutes = max(15, min(window_minutes, 1440))
    safe_event_limit = max(20, min(event_limit, 500))

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, type, raw, timestamp
                FROM events
                WHERE tenant_id=%s
                  AND timestamp >= NOW() - (%s * INTERVAL '1 minute')
                ORDER BY timestamp ASC
                LIMIT %s
                """,
                (tenant_id, safe_window_minutes, safe_event_limit),
            )
            event_rows = cur.fetchall()

            cur.execute(
                """
                SELECT a.id, a.severity, a.summary, e.user_id
                FROM alerts a
                JOIN events e ON e.id = a.event_id
                WHERE a.tenant_id=%s
                  AND a.detected_at >= NOW() - (%s * INTERVAL '1 minute')
                ORDER BY a.id DESC
                LIMIT 500
                """,
                (tenant_id, safe_window_minutes),
            )
            alert_rows = cur.fetchall()

    events = _normalize_intelligence_events(event_rows)
    contexts = _build_entity_contexts(events)

    alerts_by_user: dict[str, list[dict]] = {}
    for row in alert_rows:
        user = row.get("user_id") or "unknown-user"
        alerts_by_user.setdefault(user, []).append(
            {
                "id": row.get("id"),
                "severity": row.get("severity"),
                "summary": row.get("summary"),
            }
        )

    intelligence = []
    risk_by_user: dict[str, int] = {}
    for user, ctx in contexts.items():
        patterns = _detect_behavior_patterns(ctx)
        user_alerts = alerts_by_user.get(user, [])
        risk_score = _calculate_context_risk(ctx, user_alerts, patterns)
        risk_by_user[user] = risk_score
        intelligence.append(
            {
                "user": user,
                "risk_score": risk_score,
                "patterns": patterns,
                "context": {
                    "ips": sorted(list(ctx.get("ips") or set())),
                    "geos": sorted(list(ctx.get("geos") or set())),
                    "actions": (ctx.get("actions") or [])[-12:],
                    "last_seen": ctx.get("last_seen"),
                },
                "alert_count": len(user_alerts),
            }
        )

    intelligence.sort(key=lambda item: item.get("risk_score", 0), reverse=True)
    graph = _build_incident_intelligence_graph(events, risk_by_user)

    return {
        "tenant_id": tenant_id,
        "window_minutes": safe_window_minutes,
        "event_count": len(events),
        "intelligence": intelligence,
        "graph": graph,
    }


@app.get("/incidents")
def get_incidents(tenant_id: str = Depends(get_tenant), _user=Depends(require_action("view_incidents"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM incidents WHERE tenant_id=%s ORDER BY id DESC LIMIT 200", (tenant_id,))
            return cur.fetchall()


@app.post("/incidents/{incident_id}/assign")
def assign_incident(
    incident_id: int,
    assignee: str,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incidents SET assigned_to=%s WHERE id=%s AND tenant_id=%s RETURNING *",
                (assignee, incident_id, tenant_id),
            )
            row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    log_action(tenant_id, user["id"], "incident.assign", f"incidents/{incident_id}", {"assignee": assignee})
    return row


@app.post("/incidents/{incident_id}/notes")
def add_note(
    incident_id: int,
    body: NoteBody,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT notes FROM incidents WHERE id=%s AND tenant_id=%s", (incident_id, tenant_id))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Incident not found")
            notes = row["notes"] or []
            notes.append({"at": now_utc().isoformat(), "text": body.note})
            cur.execute(
                "UPDATE incidents SET notes=%s WHERE id=%s AND tenant_id=%s RETURNING *",
                (json.dumps(notes), incident_id, tenant_id),
            )
            updated = cur.fetchone()
        conn.commit()
    log_action(tenant_id, user["id"], "incident.note", f"incidents/{incident_id}")
    return updated


@app.post("/respond")
def respond(
    body: RespondBody,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    result = _run_response(tenant_id, body.action, body.target, body.incident_id)
    log_action(tenant_id, user["id"], "response.execute", f"incidents/{body.incident_id}", {"action": body.action})
    return result


@app.post("/respond/block-ip")
def block_ip(
    ip: str,
    incident_id: int,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    result = _run_response(tenant_id, "block-ip", ip, incident_id)
    log_action(tenant_id, user["id"], "response.execute", f"incidents/{incident_id}", {"action": "block-ip"})
    return result


@app.post("/automate/incident/{incident_id}")
def automate_incident_response(
    incident_id: int,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    """Execute automated SOAR playbooks for incident."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, tenant_id, entity, severity, status, story, assigned_to, responded_at, last_seen, timestamp FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
            incident_row = cur.fetchone()

    if not incident_row:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch recent events for this incident's entity to build proper context
    entity = incident_row.get("entity") or ""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, type, raw, timestamp
                FROM events
                WHERE tenant_id=%s AND (user_id=%s OR raw::text ILIKE %s)
                ORDER BY id DESC LIMIT 20
                """,
                (tenant_id, entity, f"%{entity}%"),
            )
            event_rows = cur.fetchall()

    if not event_rows:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, user_id, type, raw, timestamp FROM events WHERE tenant_id=%s ORDER BY id DESC LIMIT 1",
                    (tenant_id,),
                )
                event_rows = cur.fetchall()

    if not event_rows:
        return {"status": "warning", "message": "No events found for incident"}

    latest_event = event_rows[0]
    raw = latest_event.get("raw") or {}
    payload = {
        "user_id": latest_event.get("user_id"),
        "event_type": latest_event.get("type"),
        "ip": raw.get("ip"),
        "sender_domain": raw.get("sender_domain"),
    }

    # Detect patterns and build proper payloads matching ingest-time shape
    patterns: list[str] = []
    if incident_row.get("story"):
        story = incident_row["story"].lower()
        if "account_takeover" in story or "account takeover" in story:
            patterns.append("ACCOUNT_TAKEOVER")
        if "impossible_travel" in story or "impossible travel" in story:
            patterns.append("IMPOSSIBLE_TRAVEL_CHAIN")

    active_soar_policy = _get_cached_soar_policy(tenant_id)
    selected_playbook = _select_playbook_title(patterns, payload.get("event_type"), active_soar_policy)
    incident_payload, event_payload = _build_playbook_inputs(
        incident_row,
        payload,
        patterns,
        0,
        selected_playbook,
        active_soar_policy,
    )
    result = execute_playbook_for_incident(incident_payload, event_payload)

    # Ghost-mode deception: sandbox instead of hard lockout for critical incidents
    ghost_mode_active = active_soar_policy.get("ghost_mode", False)
    pb_deception = (active_soar_policy.get("playbooks", {}).get(selected_playbook) or {}).get("deception_enabled", False)
    if (ghost_mode_active or pb_deception) and incident_row.get("severity") in ("critical", "high"):
        result["ghost_mode"] = True
        result["deception_status"] = "sandboxed"
        result["original_actions"] = result.get("actions", [])
        result["actions"] = [{"type": "sandbox_proxy", "detail": "Threat actor redirected to deception sandbox"}]
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE incidents SET status='sandboxed' WHERE id=%s AND tenant_id=%s",
                    (incident_id, tenant_id),
                )
            conn.commit()
        log_action(
            tenant_id,
            user["id"],
            "soar.ghost_mode_activated",
            f"incidents/{incident_id}",
            {"playbook": selected_playbook, "severity": incident_row.get("severity")},
        )

    log_response_action(incident_id, "manual_playbook", result.get("status", "unknown"), result)
    log_action(
        tenant_id,
        user["id"],
        "soar.playbook_executed",
        f"incidents/{incident_id}",
        {"playbook": result.get("playbook"), "actions": len(result.get("actions", []))},
    )

    if result.get("status") == "success":
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE incidents SET status='responded', responded_at=NOW() WHERE id=%s AND tenant_id=%s",
                    (incident_id, tenant_id),
                )
            conn.commit()

    return result


@app.post("/automate/incident/{incident_id}/playbook/{playbook_type}")
def execute_specific_playbook(
    incident_id: int,
    playbook_type: str,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    """Execute a specific SOAR playbook."""
    valid_playbooks = [
        "account_takeover",
        "suspicious_ip",
        "phishing",
        "data_exfiltration",
    ]
    
    if playbook_type not in valid_playbooks:
        raise HTTPException(status_code=400, detail=f"Invalid playbook: {playbook_type}")
    
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
            incident_row = cur.fetchone()
    
    if not incident_row:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Note: In production, would dispatch to specific playbook executor
    result = {
        "status": "success",
        "incident_id": incident_id,
        "playbook": playbook_type,
        "message": f"Playbook {playbook_type} queued for execution",
        "timestamp": now_utc().isoformat(),
    }
    
    log_action(
        tenant_id,
        user["id"],
        f"soar.{playbook_type}_queued",
        f"incidents/{incident_id}",
        {},
    )
    
    return result


@app.get("/soar/executions/{incident_id}")
def get_soar_execution_history(
    incident_id: int,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Get SOAR automation execution history for incident."""
    history = get_execution_history(incident_id)
    return {
        "incident_id": incident_id,
        "execution_count": len(history),
        "executions": history,
    }


@app.get("/soar/policies")
def get_soar_policies(
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("respond")),
):
    policy = _get_or_create_soar_policy(tenant_id)
    return {"tenant_id": tenant_id, "policy": policy}


@app.put("/soar/policies")
def update_soar_policies(
    body: SoarPolicyUpdateBody,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    merged = _get_or_create_soar_policy(tenant_id)

    if body.auto_response_enabled is not None:
        merged["auto_response_enabled"] = body.auto_response_enabled
    if body.default_risk_threshold is not None:
        merged["default_risk_threshold"] = body.default_risk_threshold
    if body.ml_risk_threshold is not None:
        merged["ml_risk_threshold"] = body.ml_risk_threshold
    if body.ghost_mode is not None:
        merged["ghost_mode"] = body.ghost_mode

    if body.playbooks:
        for name, patch in body.playbooks.items():
            if name not in VALID_PLAYBOOK_TYPES:
                raise HTTPException(status_code=400, detail=f"Unknown playbook type: {name}")
            target = merged["playbooks"].setdefault(name, {"enabled": True, "min_risk": merged["default_risk_threshold"]})
            if patch.enabled is not None:
                target["enabled"] = patch.enabled
            if patch.min_risk is not None:
                target["min_risk"] = patch.min_risk
            if patch.ml_risk_threshold is not None:
                target["ml_risk_threshold"] = patch.ml_risk_threshold
            if patch.deception_enabled is not None:
                target["deception_enabled"] = patch.deception_enabled

    if body.event_type_overrides is not None:
        merged["event_type_overrides"].clear()
        for event_type, playbook in body.event_type_overrides.items():
            if playbook not in VALID_PLAYBOOK_TYPES:
                raise HTTPException(status_code=400, detail=f"Invalid event_type override target: {playbook}")
            merged["event_type_overrides"][event_type] = playbook

    if body.pattern_overrides is not None:
        merged["pattern_overrides"].clear()
        for pattern, playbook in body.pattern_overrides.items():
            if playbook not in VALID_PLAYBOOK_TYPES:
                raise HTTPException(status_code=400, detail=f"Invalid pattern override target: {playbook}")
            merged["pattern_overrides"][pattern] = playbook

    saved = _save_soar_policy(tenant_id, merged)
    log_action(tenant_id, user["id"], "soar.policy_update", "soar/policies", {"updated": True})
    return {"tenant_id": tenant_id, "policy": saved}


@app.get("/soar/audit")
def get_soar_audit(
    window_days: int = 30,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Return SOAR execution audit statistics for this tenant."""
    from collections import Counter as _Counter
    safe_window = max(1, min(window_days, 90))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT action, meta, timestamp
                FROM audit_logs
                WHERE tenant_id=%s
                  AND action LIKE 'soar.%%'
                  AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY timestamp DESC
                LIMIT 500
                """,
                (tenant_id, safe_window),
            )
            rows = cur.fetchall()

    total = len(rows)
    successes = sum(1 for r in rows if (r.get("meta") or {}).get("status") == "success")
    failures = sum(1 for r in rows if (r.get("meta") or {}).get("status") not in ("success", None, "unknown"))

    by_playbook: dict[str, dict] = {}
    daily: _Counter = _Counter()
    for r in rows:
        meta = r.get("meta") or {}
        playbook = meta.get("playbook") or "unknown"
        status = meta.get("status") or "unknown"
        if playbook not in by_playbook:
            by_playbook[playbook] = {"total": 0, "success": 0, "failed": 0}
        by_playbook[playbook]["total"] += 1
        if status == "success":
            by_playbook[playbook]["success"] += 1
        elif status not in ("unknown", None):
            by_playbook[playbook]["failed"] += 1
        ts = r.get("timestamp")
        if ts:
            day = ts.strftime("%Y-%m-%d") if hasattr(ts, "strftime") else str(ts)[:10]
            daily[day] += 1

    recent = [
        {
            "action": r.get("action"),
            "playbook": (r.get("meta") or {}).get("playbook"),
            "status": (r.get("meta") or {}).get("status"),
            "risk_score": (r.get("meta") or {}).get("risk_score"),
            "timestamp": r["timestamp"].isoformat() if hasattr(r.get("timestamp"), "isoformat") else str(r.get("timestamp")),
        }
        for r in rows[:20]
    ]

    return {
        "tenant_id": tenant_id,
        "window_days": safe_window,
        "total_executions": total,
        "successful_executions": successes,
        "failed_executions": failures,
        "success_rate": round(successes / total * 100, 1) if total else 0.0,
        "by_playbook": by_playbook,
        "daily_trend": [{"day": d, "count": c} for d, c in sorted(daily.items())],
        "recent_actions": recent,
    }


@app.get("/soar/stats")
def get_soar_stats(
    window_days: int = 30,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Aggregated SOAR statistics: deflected threats, success rate, active monitored users."""
    safe_window = max(1, min(window_days, 90))
    with get_conn() as conn:
        with conn.cursor() as cur:
            # Total executions and deflections
            cur.execute(
                """
                SELECT action, meta
                FROM audit_logs
                WHERE tenant_id=%s
                  AND action LIKE 'soar.%%'
                  AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY timestamp DESC
                LIMIT 1000
                """,
                (tenant_id, safe_window),
            )
            soar_rows = cur.fetchall()

            # Active monitored users (distinct entities from recent incidents)
            cur.execute(
                """
                SELECT COUNT(DISTINCT entity) AS active_users
                FROM incidents
                WHERE tenant_id=%s
                  AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                """,
                (tenant_id, safe_window),
            )
            user_row = cur.fetchone()

    total_executions = 0
    total_successes = 0
    total_deflected = 0
    deflected_details: list[dict] = []

    for r in soar_rows:
        action = r.get("action") or ""
        meta = r.get("meta") or {}
        if action == "soar.deflected":
            total_deflected += 1
            deflected_details.append({
                "reason": meta.get("reason"),
                "playbook": meta.get("playbook"),
                "ml_anomaly_score": meta.get("ml_anomaly_score"),
                "ml_risk_threshold": meta.get("ml_risk_threshold"),
                "risk_score": meta.get("risk_score"),
            })
        elif action.startswith("soar."):
            total_executions += 1
            if meta.get("status") == "success":
                total_successes += 1

    active_users = (user_row or {}).get("active_users", 0) if user_row else 0
    success_rate = round(total_successes / total_executions * 100, 1) if total_executions else 0.0

    return {
        "tenant_id": tenant_id,
        "window_days": safe_window,
        "total_executions": total_executions,
        "total_deflected_threats": total_deflected,
        "success_rate": success_rate,
        "active_monitored_users": active_users,
        "deflected_details": deflected_details[:20],
    }


# ---------------------------------------------------------------------------
# JIT Session Revocation Endpoints
# ---------------------------------------------------------------------------

@app.post("/jit/revoke")
def jit_revoke_endpoint(
    target_user_id: str,
    reason: str = "manual_revocation",
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    """Revoke all active sessions for a user via JIT policy."""
    jit_revoke_user_sessions(tenant_id, target_user_id, reason)
    log_action(tenant_id, user["id"], "jit.revoke", f"users/{target_user_id}", {"reason": reason})
    return {"status": "revoked", "target_user_id": target_user_id, "reason": reason}


@app.post("/jit/reinstate")
def jit_reinstate_endpoint(
    target_user_id: str,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    """Reinstate a previously JIT-revoked user."""
    jit_reinstate_user(tenant_id, target_user_id)
    log_action(tenant_id, user["id"], "jit.reinstate", f"users/{target_user_id}", {})
    return {"status": "reinstated", "target_user_id": target_user_id}


@app.get("/jit/status")
def jit_status_endpoint(
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """List all currently JIT-revoked sessions for this tenant."""
    revoked = [uid for key, uid in ((k, k.split(":", 1)[-1]) for k in _JIT_REVOKED_TOKENS) if key.startswith(f"{tenant_id}:")]
    return {"tenant_id": tenant_id, "revoked_users": revoked, "count": len(revoked)}


# ---------------------------------------------------------------------------
# Voice Command Endpoint
# ---------------------------------------------------------------------------


def _resolve_tenant_alias(raw_alias: str | None, fallback_tenant: str) -> str:
    if not raw_alias:
        return fallback_tenant
    cleaned = raw_alias.strip().lower().replace(" ", "-").replace("_", "-")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM tenants WHERE lower(id)=lower(%s) OR lower(name)=lower(%s) LIMIT 1",
                (cleaned, raw_alias.strip()),
            )
            row = cur.fetchone()
    return (row or {}).get("id") or fallback_tenant


def _latest_isolated_user(tenant_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT resource
                FROM audit_logs
                WHERE tenant_id=%s
                  AND action='jit.revoke'
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (tenant_id,),
            )
            row = cur.fetchone()
    resource = (row or {}).get("resource") or ""
    if resource.startswith("users/"):
        return resource.split("/", 1)[1]
    return None


def _build_isolation_reasoning(tenant_id: str, user_id: str) -> list[str]:
    reasons: list[str] = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT action, resource, meta, timestamp
                FROM audit_logs
                WHERE tenant_id=%s
                  AND (
                    resource=%s
                    OR action IN ('threat_intel.match', 'sentinel.baseline_deviation', 'soar.auto_playbook', 'jit.revoke')
                  )
                ORDER BY timestamp DESC
                LIMIT 120
                """,
                (tenant_id, f"users/{user_id}"),
            )
            rows = cur.fetchall()

    for row in rows:
        action = row.get("action") or ""
        meta = row.get("meta") or {}
        if action == "jit.revoke":
            r = meta.get("reason") or "automated response"
            reasons.append(f"JIT isolation triggered ({r})")
        elif action == "sentinel.baseline_deviation" and (meta.get("user_id") == user_id or not meta.get("user_id")):
            z = meta.get("z_score")
            reasons.append(f"Baseline deviation detected by Sentinel (z-score {z})")
        elif action == "threat_intel.match":
            ip = meta.get("ip") or "unknown"
            cat = meta.get("category") or "unknown"
            shared = " via shared intelligence" if meta.get("shared_intelligence") else ""
            reasons.append(f"Threat Intel matched IP {ip} ({cat}){shared}")
        elif action == "soar.auto_playbook":
            patterns = meta.get("patterns") or []
            if "IMPOSSIBLE_TRAVEL_CHAIN" in patterns:
                reasons.append("Geo-shift detected (impossible travel pattern)")
            if "ACCOUNT_TAKEOVER" in patterns:
                reasons.append("Account takeover pattern detected")

    unique: list[str] = []
    for reason in reasons:
        if reason not in unique:
            unique.append(reason)
    return unique[:6]


@app.post("/voice/command")
async def voice_command_endpoint(
    body: VoiceCommandBody,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    """Process voice commands from the WebSpeech API frontend."""
    command = body.command.strip().lower().replace(" ", "_")
    result: dict = {"command": command, "status": "unknown"}

    if command in ("lock_down", "lockdown"):
        policy = _get_or_create_soar_policy(tenant_id)
        for pb in policy.get("playbooks", {}).values():
            pb["enabled"] = True
            pb["min_risk"] = 0
        policy["auto_response_enabled"] = True
        _save_soar_policy(tenant_id, policy)
        await broadcast(tenant_id, {"kind": "voice_command", "command": "lock_down", "status": "engaged"})
        result = {"command": "lock_down", "status": "engaged", "detail": "All playbooks armed, min_risk zeroed"}

    elif command in ("status_report", "status"):
        policy = _get_or_create_soar_policy(tenant_id)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS cnt FROM incidents WHERE tenant_id=%s AND status IN ('open','investigating')",
                    (tenant_id,),
                )
                open_count = (cur.fetchone() or {}).get("cnt", 0)
        result = {
            "command": "status_report",
            "status": "ok",
            "open_incidents": open_count,
            "auto_response": policy.get("auto_response_enabled", False),
            "ghost_mode": policy.get("ghost_mode", False),
        }

    elif command in ("enable_ghost_mode", "ghost_mode", "ghost"):
        policy = _get_or_create_soar_policy(tenant_id)
        policy["ghost_mode"] = True
        _save_soar_policy(tenant_id, policy)
        await broadcast(tenant_id, {"kind": "voice_command", "command": "enable_ghost_mode", "status": "active"})
        result = {"command": "enable_ghost_mode", "status": "active", "detail": "Ghost-mode deception enabled globally"}

    elif command in ("disable_ghost_mode", "disable_ghost"):
        policy = _get_or_create_soar_policy(tenant_id)
        policy["ghost_mode"] = False
        _save_soar_policy(tenant_id, policy)
        result = {"command": "disable_ghost_mode", "status": "disabled"}

    elif command in ("run_security_drill", "security_drill", "run_drill"):
        drill_result = await _execute_security_drill(tenant_id, "brute_force", user, iterations=5)
        result = {"command": "run_security_drill", "status": "completed", "drill": drill_result}

    elif command in ("why_was_this_user_isolated", "why_user_isolated", "why_is_this_user_isolated"):
        target_user = body.context_user or _latest_isolated_user(tenant_id)
        if not target_user:
            result = {
                "command": command,
                "status": "no_target",
                "detail": "No isolated user found. Provide context_user to explain reasoning.",
            }
        else:
            reasons = _build_isolation_reasoning(tenant_id, target_user)
            result = {
                "command": "why_was_this_user_isolated",
                "status": "explained",
                "target_user": target_user,
                "reasoning": reasons or ["No direct isolation rationale found in current audit trail."],
            }

    elif command.startswith("lower_threshold"):
        parsed = re.search(r"lower_threshold_for_([a-z0-9\-_]+)_by_(\d+)_percent", command)
        target_raw = body.target_tenant or (parsed.group(1) if parsed else None)
        percent_delta = body.percent_delta if body.percent_delta is not None else (float(parsed.group(2)) if parsed else 10.0)
        target = _resolve_tenant_alias(target_raw, tenant_id)

        if target != tenant_id and (user.get("role") or "") not in ("owner", "admin"):
            raise HTTPException(status_code=403, detail="Cross-tenant policy updates require owner/admin role")

        policy = _get_or_create_soar_policy(target)
        old_default = int(policy.get("default_risk_threshold") or 85)
        old_ml = float(policy.get("ml_risk_threshold") or 5.0)
        new_default = max(0, int(round(old_default * (1 - (percent_delta / 100.0)))))
        new_ml = max(0.0, round(old_ml * (1 - (percent_delta / 100.0)), 2))

        if not body.confirm:
            result = {
                "command": "lower_threshold",
                "status": "pending_confirmation",
                "target_tenant": target,
                "proposed": {
                    "default_risk_threshold": {"from": old_default, "to": new_default},
                    "ml_risk_threshold": {"from": old_ml, "to": new_ml},
                },
                "detail": "Repeat with confirm=true to apply policy update.",
            }
        else:
            policy["default_risk_threshold"] = new_default
            policy["ml_risk_threshold"] = new_ml
            _save_soar_policy(target, policy)
            result = {
                "command": "lower_threshold",
                "status": "applied",
                "target_tenant": target,
                "default_risk_threshold": new_default,
                "ml_risk_threshold": new_ml,
            }
            log_action(tenant_id, user["id"], "voice.policy_update", f"tenants/{target}", {
                "operation": "lower_threshold",
                "percent_delta": percent_delta,
                "from_default": old_default,
                "to_default": new_default,
                "from_ml": old_ml,
                "to_ml": new_ml,
            })

    else:
        result = {
            "command": command,
            "status": "unrecognized",
            "detail": "Valid commands: lock_down, status_report, enable_ghost_mode, disable_ghost_mode, run_security_drill, why_was_this_user_isolated, lower_threshold_for_<tenant>_by_<percent>_percent",
        }

    log_action(tenant_id, user["id"], "voice.command", "voice", {"command": command, "result_status": result.get("status")})
    return result


@app.post("/policy/threshold-update")
def update_policy_threshold(
    body: ThresholdUpdateBody,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    target = _resolve_tenant_alias(body.target_tenant, tenant_id)

    if target != tenant_id and (user.get("role") or "") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Cross-tenant policy updates require owner/admin role")

    policy = _get_or_create_soar_policy(target)
    old_default = int(policy.get("default_risk_threshold") or 85)
    old_ml = float(policy.get("ml_risk_threshold") or 5.0)
    percent_delta = float(body.percent_delta)
    new_default = max(0, int(round(old_default * (1 - (percent_delta / 100.0)))))
    new_ml = max(0.0, round(old_ml * (1 - (percent_delta / 100.0)), 2))

    proposal = {
        "default_risk_threshold": {"from": old_default, "to": new_default},
        "ml_risk_threshold": {"from": old_ml, "to": new_ml},
    }
    if not body.confirm:
        return {
            "status": "pending_confirmation",
            "target_tenant": target,
            "proposed": proposal,
            "detail": "Repeat with confirm=true to apply policy update.",
        }

    policy["default_risk_threshold"] = new_default
    policy["ml_risk_threshold"] = new_ml
    _save_soar_policy(target, policy)
    log_action(tenant_id, user["id"], "policy.threshold_update", f"tenants/{target}", {
        "percent_delta": percent_delta,
        "from_default": old_default,
        "to_default": new_default,
        "from_ml": old_ml,
        "to_ml": new_ml,
        "confirmed": True,
    })
    return {
        "status": "applied",
        "target_tenant": target,
        "default_risk_threshold": new_default,
        "ml_risk_threshold": new_ml,
    }


# ---------------------------------------------------------------------------
# Telemetry Ingest — Distributed Agent Data (The Hunter)
# ---------------------------------------------------------------------------

@app.post("/telemetry/ingest")
async def telemetry_ingest(
    events: list[TelemetryEvent],
    tenant_id: str = Depends(get_tenant),
    _key=Depends(validate_api_key),
):
    """Ingest telemetry from distributed agents (process starts, network connections)."""
    processed = 0
    threat_matches = []
    sentinel_triggers = []
    for ev in events:
        register_agent_heartbeat(ev.agent_id, ev.hostname, tenant_id)
        effective_user = ev.user_id or ((ev.meta or {}).get("user_id") if isinstance(ev.meta, dict) else None)
        entry = {
            "agent_id": ev.agent_id,
            "hostname": ev.hostname,
            "event_type": ev.event_type,
            "timestamp": ev.timestamp or now_utc().isoformat(),
            "user_id": effective_user,
            "pid": ev.pid,
            "process_name": ev.process_name,
            "remote_ip": ev.remote_ip,
            "remote_port": ev.remote_port,
            "local_port": ev.local_port,
            "tenant_id": tenant_id,
            "meta": ev.meta,
        }
        buffer_telemetry(entry)

        # Sentinel: adaptive baseline z-score for telemetry process/network frequency.
        if effective_user and ev.event_type in ("process_start", "network_connection", "net_connect"):
            z_score, baseline = _telemetry_frequency_zscore(tenant_id, effective_user, ev.event_type, now_utc())
            if z_score > 3.0:
                policy = _get_or_create_soar_policy(tenant_id)
                if not policy.get("ghost_mode"):
                    policy["ghost_mode"] = True
                    _save_soar_policy(tenant_id, policy)
                sentinel_triggers.append({
                    "user_id": effective_user,
                    "event_type": ev.event_type,
                    "z_score": round(z_score, 2),
                })
                log_action(tenant_id, None, "sentinel.baseline_deviation", f"agents/{ev.agent_id}", {
                    "user_id": effective_user,
                    "event_type": ev.event_type,
                    "z_score": round(z_score, 2),
                    "baseline": baseline,
                    "auto_ghost_mode": True,
                    "reason": "Deviation > 3σ from 7-day baseline",
                })

        # Threat Intel cross-reference for network connections
        if ev.remote_ip:
            match = check_threat_intel(ev.remote_ip)
            if match:
                threat_matches.append({"ip": ev.remote_ip, **match, "agent_id": ev.agent_id})
                log_action(tenant_id, None, "threat_intel.agent_match", f"agents/{ev.agent_id}", {
                    "ip": ev.remote_ip, "source": match.get("source"),
                    "category": match.get("category"), "hostname": ev.hostname,
                    "shared_intelligence": bool(match.get("shared_intelligence")),
                })
                # Diplomat: herd immunity propagation for critical threats.
                if int(match.get("risk") or 0) >= 90:
                    _upsert_shared_threat(
                        ev.remote_ip,
                        source_tenant=tenant_id,
                        category=match.get("category") or "unknown",
                        risk=int(match.get("risk") or 100),
                        reason="Critical indicator observed via telemetry ingest",
                    )
        processed += 1

    if threat_matches:
        await broadcast(tenant_id, {
            "kind": "threat_intel_alert",
            "matches": threat_matches[:10],
            "count": len(threat_matches),
        })
    if sentinel_triggers:
        await broadcast(tenant_id, {
            "kind": "sentinel_baseline_deviation",
            "count": len(sentinel_triggers),
            "triggers": sentinel_triggers[:10],
        })

    return {
        "processed": processed,
        "threat_matches": len(threat_matches),
        "sentinel_triggers": len(sentinel_triggers),
        "agents_active": len(_REGISTERED_AGENTS.get(tenant_id, {})),
    }


@app.get("/agents/status")
def get_agent_status(
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Get status of all registered distributed agents."""
    tenant_agents = _REGISTERED_AGENTS.get(tenant_id, {})
    agents = []
    for agent_id, info in tenant_agents.items():
        last_seen = info.get("last_seen", "")
        agents.append({
            "agent_id": agent_id,
            "hostname": info.get("hostname"),
            "last_seen": last_seen,
            "status": info.get("status", "unknown"),
            "event_count": info.get("event_count", 0),
        })
    return {"agents": agents, "total": len(agents)}


@app.get("/telemetry/recent")
def get_recent_telemetry(
    limit: int = 50,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Get recent telemetry events from distributed agents."""
    safe_limit = max(1, min(limit, 200))
    filtered = [e for e in reversed(_TELEMETRY_BUFFER) if e.get("tenant_id") == tenant_id][:safe_limit]
    return {"events": filtered, "total_buffered": len(_TELEMETRY_BUFFER)}


# ---------------------------------------------------------------------------
# Threat Intelligence Service (The Oracle)
# ---------------------------------------------------------------------------

@app.get("/threat-intel/feed")
def get_threat_intel_feed(
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Get current global threat intelligence feed, including shared sovereign intelligence."""
    feed = poll_threat_intel_feed()
    indicators: dict[str, dict] = {}
    for ip, info in feed.items():
        indicators[ip] = {
            "ip": ip,
            "source": info.get("source"),
            "category": info.get("category"),
            "risk": info.get("risk"),
            "tags": info.get("tags", []),
            "shared_intelligence": False,
        }

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ip, source_tenant, category, risk, source, reason
                FROM shared_threats
                WHERE status='critical'
                ORDER BY risk DESC, last_seen DESC
                LIMIT 500
                """
            )
            shared_rows = cur.fetchall()

    for row in shared_rows:
        ip = row.get("ip")
        if not ip:
            continue
        existing = indicators.get(ip, {"ip": ip, "tags": []})
        merged_tags = list(dict.fromkeys([*(existing.get("tags") or []), "shared-intelligence", "diplomat"]))
        indicators[ip] = {
            "ip": ip,
            "source": row.get("source") or existing.get("source") or "Sovereign Diplomat",
            "category": row.get("category") or existing.get("category") or "shared_critical",
            "risk": max(int(existing.get("risk") or 0), int(row.get("risk") or 100)),
            "tags": merged_tags,
            "shared_intelligence": True,
            "shared_source_tenant": row.get("source_tenant"),
            "shared_reason": row.get("reason"),
        }

    sorted_indicators = sorted(indicators.values(), key=lambda i: int(i.get("risk") or 0), reverse=True)
    shared_count = sum(1 for i in sorted_indicators if i.get("shared_intelligence"))
    return {
        "indicators": sorted_indicators,
        "total": len(sorted_indicators),
        "shared_count": shared_count,
        "feed_sources": ["AlienVault OTX", "abuse.ch", "ThreatFox", "Sovereign Diplomat"],
    }


@app.post("/threat-intel/check")
def check_threat_intel_endpoint(
    ip: str,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Check if a specific IP is in the threat intelligence feed."""
    match = check_threat_intel(ip)
    if match:
        return {"ip": ip, "matched": True, **match}
    return {"ip": ip, "matched": False}


# ---------------------------------------------------------------------------
# Simulation Engine — Security Drills (The Architect)
# ---------------------------------------------------------------------------

async def _execute_security_drill(
    tenant_id: str,
    drill_type: str,
    user: dict,
    target_user: str | None = None,
    iterations: int = 5,
) -> dict:
    """Run a non-destructive security drill and validate system responses."""
    drill_id = f"drill_{now_utc().strftime('%Y%m%d_%H%M%S')}_{drill_type}"
    target = target_user or "drill.simulated.user"
    results: dict = {
        "drill_id": drill_id,
        "drill_type": drill_type,
        "target_user": target,
        "iterations": iterations,
        "started_at": now_utc().isoformat(),
        "checks": {},
    }

    if drill_type == "brute_force":
        # Simulate brute-force login attempts and explicitly exercise the JIT revocation path
        for i in range(iterations):
            log_action(tenant_id, None, "drill.brute_force_attempt", f"users/{target}", {
                "attempt": i + 1, "ip": f"198.51.100.{i + 10}", "drill_id": drill_id,
            })
        jit_revoke_user_sessions(tenant_id, target, reason=f"drill_{drill_id}")
        # Check: did JIT revocation engage?
        jit_engaged = is_jit_revoked(tenant_id, target)
        results["checks"]["jit_revocation"] = "pass" if jit_engaged else "not_triggered"
        # Keep the drill non-destructive by restoring access after validation
        if jit_engaged:
            jit_reinstate_user(tenant_id, target)
        # Check: is ghost mode available?
        policy = _get_or_create_soar_policy(tenant_id)
        results["checks"]["ghost_mode_available"] = "pass" if policy.get("ghost_mode") else "disabled"
        results["checks"]["auto_response_enabled"] = "pass" if policy.get("auto_response_enabled") else "disabled"

    elif drill_type == "phishing_sim":
        # Simulate phishing event ingest
        log_action(tenant_id, None, "drill.phishing_sim", f"users/{target}", {"drill_id": drill_id})
        policy = _get_or_create_soar_policy(tenant_id)
        pb = (policy.get("playbooks") or {}).get("phishing", {})
        results["checks"]["phishing_playbook_enabled"] = "pass" if pb.get("enabled") else "disabled"
        results["checks"]["deception_enabled"] = "pass" if pb.get("deception_enabled") else "disabled"

    elif drill_type == "ghost_mode_test":
        policy = _get_or_create_soar_policy(tenant_id)
        results["checks"]["ghost_mode_enabled"] = "pass" if policy.get("ghost_mode") else "disabled"
        for pb_name, pb_conf in (policy.get("playbooks") or {}).items():
            results["checks"][f"deception_{pb_name}"] = "pass" if pb_conf.get("deception_enabled") else "disabled"

    elif drill_type == "jit_test":
        # Temporarily revoke and reinstate to verify JIT pipeline
        jit_revoke_user_sessions(tenant_id, target, reason=f"drill_{drill_id}")
        results["checks"]["jit_revoke"] = "pass" if is_jit_revoked(tenant_id, target) else "fail"
        jit_reinstate_user(tenant_id, target)
        results["checks"]["jit_reinstate"] = "pass" if not is_jit_revoked(tenant_id, target) else "fail"

    else:
        results["checks"]["unknown_drill_type"] = "fail"

    # Score the drill
    checks = results["checks"]
    total_checks = len(checks)
    passed = sum(1 for v in checks.values() if v == "pass")
    results["completed_at"] = now_utc().isoformat()
    results["score"] = f"{passed}/{total_checks}"
    results["success_rate"] = round(passed / total_checks * 100, 1) if total_checks else 0.0
    results["overall"] = "pass" if passed == total_checks else "partial" if passed > 0 else "fail"

    record_drill(results, tenant_id)
    log_action(tenant_id, user.get("id"), "drill.completed", f"drills/{drill_id}", {
        "drill_id": drill_id, "drill_type": drill_type, "score": results["score"], "overall": results["overall"],
    })
    await broadcast(tenant_id, {"kind": "drill_completed", "drill_id": drill_id, "overall": results["overall"], "score": results["score"]})

    return results


@app.post("/drills/run")
async def run_security_drill(
    body: DrillRequest,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    """Run a non-destructive security drill to validate system responses."""
    valid_drills = {"brute_force", "phishing_sim", "ghost_mode_test", "jit_test"}
    if body.drill_type not in valid_drills:
        raise HTTPException(status_code=400, detail=f"Invalid drill type. Valid: {', '.join(sorted(valid_drills))}")
    result = await _execute_security_drill(tenant_id, body.drill_type, user, body.target_user, body.iterations)
    return result


@app.get("/drills/history")
def get_drill_history(
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Get history of security drill runs."""
    tenant_drills = _DRILL_HISTORY.get(tenant_id, [])
    return {"drills": list(reversed(tenant_drills)), "total": len(tenant_drills)}


@app.put("/incidents/{incident_id}/status")
def update_incident_status_endpoint(
    incident_id: int,
    new_status: str,
    reason: str = "",
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    """Update incident status and add timeline event."""
    valid_statuses = ["open", "investigating", "responded", "closed"]
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status: {new_status}")
    
    # Update in database
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incidents SET status=%s, updated_at=NOW() WHERE id=%s AND tenant_id=%s",
                (new_status, incident_id, tenant_id),
            )
        conn.commit()
    
    # Add timeline event
    add_timeline_event(
        incident_id,
        action="status_changed",
        description=f"Status changed to {new_status}: {reason}",
        actor=user.get("id") if user else None,
        details={"previous_status": "unknown", "new_status": new_status},
    )
    
    return {
        "incident_id": incident_id,
        "new_status": new_status,
        "timestamp": now_utc().isoformat(),
    }


@app.post("/incidents/{incident_id}/notes")
def add_incident_note(
    incident_id: int,
    body: IncidentNoteBody,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("view_incidents")),
):
    """Add analyst note to incident."""
    note = body.note
    tags = body.tags or []

    if not note or len(note) < 2:
        raise HTTPException(status_code=400, detail="Note must be at least 2 characters")

    note_entry = add_analyst_note(
        incident_id=incident_id,
        note=note,
        analyst_id=user.get("id") if user else None,
        tags=tags,
    )

    # Log the action
    log_action(
        tenant_id,
        user.get("id") if user else None,
        "incident.note_added",
        f"incidents/{incident_id}",
        {"note_length": len(note), "tags": tags},
    )

    return note_entry


def _build_behavioral_baseline_graph(tenant_id: str, user_id: str | None) -> dict:
    if not user_id:
        return {"user_id": None, "points": [], "z_scores": []}

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT date_trunc('day', timestamp) AS day_bucket, COUNT(*) AS cnt
                FROM events
                WHERE tenant_id=%s
                  AND user_id=%s
                  AND timestamp >= NOW() - INTERVAL '7 days'
                GROUP BY day_bucket
                ORDER BY day_bucket ASC
                """,
                (tenant_id, user_id),
            )
            rows = cur.fetchall()

    counts = [int(r.get("cnt") or 0) for r in rows]
    if not counts:
        return {"user_id": user_id, "points": [], "z_scores": []}

    mean = sum(counts) / len(counts)
    stddev = _safe_stddev([float(v) for v in counts])
    points = []
    z_scores = []
    for r in rows:
        day = r.get("day_bucket")
        cnt = int(r.get("cnt") or 0)
        z = ((cnt - mean) / stddev) if stddev > 0 else 0.0
        points.append({
            "day": day.strftime("%Y-%m-%d") if hasattr(day, "strftime") else str(day)[:10],
            "count": cnt,
        })
        z_scores.append(round(z, 2))

    return {
        "user_id": user_id,
        "mean": round(mean, 2),
        "stddev": round(stddev, 2),
        "points": points,
        "z_scores": z_scores,
        "latest_z_score": z_scores[-1] if z_scores else 0.0,
    }


@app.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: int,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Get incident timeline enriched with SOAR actions and audit log entries."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, entity, status, severity, story, assigned_to, responded_at, first_seen, last_seen FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
            incident = cur.fetchone()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT action, user_id, meta, timestamp
                FROM audit_logs
                WHERE tenant_id=%s
                  AND resource=%s
                ORDER BY timestamp ASC
                LIMIT 300
                """,
                (tenant_id, f"incidents/{incident_id}"),
            )
            audit_rows = cur.fetchall()

    timeline = []

    if incident.get("first_seen"):
        timeline.append({
            "timestamp": incident["first_seen"].isoformat(),
            "action": "incident_created",
            "category": "lifecycle",
            "description": f"Incident detected for entity: {incident.get('entity') or 'unknown'}",
            "severity": incident.get("severity"),
            "actor": "system",
        })

    for r in audit_rows:
        action = r.get("action") or ""
        meta = r.get("meta") or {}
        ts = r.get("timestamp")
        ts_iso = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        if action.startswith("soar."):
            playbook = meta.get("playbook") or "unknown"
            status = meta.get("status") or "unknown"
            risk = meta.get("risk_score")
            desc = f"SOAR playbook executed: {playbook} — {status}"
            if risk is not None:
                desc += f" (risk: {risk})"
            timeline.append({
                "timestamp": ts_iso,
                "action": action,
                "category": "soar",
                "description": desc,
                "playbook": playbook,
                "status": status,
                "risk_score": risk,
                "actor": r.get("user_id") or "system",
            })
        elif action.startswith("threat_intel."):
            ip = meta.get("ip") or "unknown"
            source = meta.get("source") or "unknown"
            cat = meta.get("category") or "unknown"
            shared = bool(meta.get("shared_intelligence"))
            timeline.append({
                "timestamp": ts_iso,
                "action": action,
                "category": "threat_intel",
                "description": f"Threat Intel match: {ip} ({cat}) via {source}",
                "ip": ip,
                "threat_source": source,
                "threat_category": cat,
                "shared_intelligence": shared,
                "actor": "system",
            })
        elif action.startswith("sentinel."):
            z_score = meta.get("z_score")
            timeline.append({
                "timestamp": ts_iso,
                "action": action,
                "category": "sentinel",
                "description": meta.get("reason") or f"Sentinel baseline deviation detected (z={z_score})",
                "z_score": z_score,
                "event_type": meta.get("event_type"),
                "actor": "system",
            })
        elif action.startswith("drill."): 
            drill_id = meta.get("drill_id") or ""
            timeline.append({
                "timestamp": ts_iso,
                "action": action,
                "category": "drill",
                "description": meta.get("description") or f"Security drill: {action.replace('drill.', '')}",
                "drill_id": drill_id,
                "score": meta.get("score"),
                "overall": meta.get("overall"),
                "actor": r.get("user_id") or "system",
            })
        else:
            timeline.append({
                "timestamp": ts_iso,
                "action": action,
                "category": "analyst" if r.get("user_id") else "system",
                "description": meta.get("description") or action.replace(".", " ").title(),
                "actor": r.get("user_id") or "system",
            })

    if incident.get("responded_at"):
        timeline.append({
            "timestamp": incident["responded_at"].isoformat(),
            "action": "incident_responded",
            "category": "lifecycle",
            "description": "Incident marked as responded",
            "actor": "system",
        })
    elif incident.get("last_seen"):
        timeline.append({
            "timestamp": incident["last_seen"].isoformat(),
            "action": "incident_updated",
            "category": "lifecycle",
            "description": "Last activity recorded",
            "actor": "system",
        })

    timeline.sort(key=lambda x: x.get("timestamp") or "")

    # Enrich with Geo-IP and Identity context
    enriched_data = enrich_incident_context(dict(incident), None)

    story = incident.get("story") or {}
    if isinstance(story, str):
        try:
            story = json.loads(story)
        except Exception:
            story = {}
    users = (story.get("users") if isinstance(story, dict) else None) or []
    baseline_user = users[0] if users else incident.get("entity")
    behavioral_baseline = _build_behavioral_baseline_graph(tenant_id, baseline_user)

    return {
        "incident_id": incident_id,
        "entity": incident.get("entity"),
        "status": incident.get("status"),
        "severity": incident.get("severity"),
        "enriched_data": enriched_data,
        "behavioral_baseline": behavioral_baseline,
        "timeline": timeline,
        "event_count": len(timeline),
    }


@app.get("/incidents/{incident_id}/reasoning")
def get_incident_reasoning(
    incident_id: int,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, entity, status, severity, story, assigned_to, responded_at, first_seen, last_seen FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
            incident = cur.fetchone()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    story = incident.get("story") or {}
    if isinstance(story, str):
        try:
            story = json.loads(story)
        except Exception:
            story = {}
    users = (story.get("users") if isinstance(story, dict) else None) or []
    reasoning_user = users[0] if users else incident.get("entity")
    behavioral_baseline = _build_behavioral_baseline_graph(tenant_id, reasoning_user)
    reasoning = _build_isolation_reasoning(tenant_id, reasoning_user) if reasoning_user else []
    enriched_data = enrich_incident_context(dict(incident), None)
    shared_intelligence = any("shared intelligence" in item.lower() for item in reasoning)

    return {
        "incident_id": incident_id,
        "entity": incident.get("entity"),
        "status": incident.get("status"),
        "severity": incident.get("severity"),
        "user_id": reasoning_user,
        "isolation_reason": reasoning[0] if reasoning else "No direct isolation rationale found in current audit trail.",
        "reasoning": reasoning,
        "behavioral_baseline": behavioral_baseline,
        "enriched_data": enriched_data,
        "shared_intelligence": shared_intelligence,
    }


@app.get("/incidents/{incident_id}/response-summary")
def get_incident_response_summary(
    incident_id: int,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Get summary of response actions taken on incident."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, status, responded_at FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
            incident = cur.fetchone()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    summary = get_response_summary(incident_id)
    
    return {
        "incident_id": incident_id,
        "status": incident["status"],
        "responded_at": incident["responded_at"].isoformat() if incident["responded_at"] else None,
        **summary,
    }


@app.post("/incidents/{incident_id}/close")
def close_incident_endpoint(
    incident_id: int,
    resolution: str,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("respond")),
):
    """Close an incident with resolution."""
    if not resolution or len(resolution) < 5:
        raise HTTPException(status_code=400, detail="Resolution must be at least 5 characters")
    
    # Update in database
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incidents SET status=%s, responded_at=NOW(), updated_at=NOW() WHERE id=%s AND tenant_id=%s",
                ("closed", incident_id, tenant_id),
            )
        conn.commit()
    
    # Log closure
    log_action(
        tenant_id,
        user.get("id") if user else None,
        "incident.closed",
        f"incidents/{incident_id}",
        {"resolution": resolution},
    )
    
    return {
        "incident_id": incident_id,
        "status": "closed",
        "resolution": resolution,
        "closed_at": now_utc().isoformat(),
    }


@app.get("/ai/analyze/{incident_id}")
def ai_analyze(
    incident_id: int,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM incidents WHERE id=%s AND tenant_id=%s", (incident_id, tenant_id))
            incident = cur.fetchone()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return analyze_incident(incident)


@app.get("/rules")
def get_rules(
    include_advanced: bool = True,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    tenant = fetch_tenant(tenant_id)
    if include_advanced:
        check_plan(tenant, "advanced_detection")
    return load_rules()


@app.get("/tenants/me")
def get_tenant_profile(tenant_id: str = Depends(get_tenant), _user=Depends(get_current_user)):
    return fetch_tenant(tenant_id)


@app.get("/tenants/subscription")
def get_subscription(tenant_id: str = Depends(get_tenant), _user=Depends(require_action("manage_users"))):
    tenant = fetch_tenant(tenant_id)
    return {
        "tenant_id": tenant["id"],
        "plan": tenant["plan"],
        "status": tenant["status"],
        "stripe_customer_id": tenant["stripe_customer_id"],
    }


@app.post("/tenants/subscription")
def update_subscription(
    body: TenantSubscriptionBody,
    tenant_id: str = Depends(get_tenant),
    user=Depends(require_action("manage_users")),
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE tenants SET plan=%s, status=%s WHERE id=%s RETURNING id, plan, status, stripe_customer_id",
                (body.plan, body.status, tenant_id),
            )
            updated = cur.fetchone()
        conn.commit()

    if not updated:
        raise HTTPException(status_code=404, detail="Tenant not found")
    log_action(tenant_id, user["id"], "billing.subscription.update", "tenants/subscription", {"plan": body.plan, "status": body.status})
    return updated


@app.get("/tenants/users")
def list_users(tenant_id: str = Depends(get_tenant), _user=Depends(require_action("manage_users"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, tenant_id, email, role, created_at FROM users WHERE tenant_id=%s ORDER BY created_at DESC", (tenant_id,))
            return cur.fetchall()


@app.post("/tenants/users")
def create_user(body: CreateUserBody, tenant_id: str = Depends(get_tenant), user=Depends(require_action("manage_users"))):
    uid = f"u-{uuid4().hex[:10]}"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (id, tenant_id, email, password, role) VALUES (%s, %s, %s, %s, %s) RETURNING id, tenant_id, email, role, created_at",
                (uid, tenant_id, body.email, hash_password(body.password), body.role),
            )
            created = cur.fetchone()
        conn.commit()
    log_action(tenant_id, user["id"], "user.create", f"users/{uid}", {"role": body.role})
    return created


@app.post("/tenants/api-keys")
def create_api_key(tenant_id: str = Depends(get_tenant), user=Depends(require_action("manage_users"))):
    key = _generate_api_key()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO api_keys (tenant_id, key) VALUES (%s, %s) RETURNING id, tenant_id, key, created_at", (tenant_id, key))
            created = cur.fetchone()
        conn.commit()
    log_action(tenant_id, user["id"], "apikey.create", "api_keys")
    return created


@app.get("/audit/logs")
def get_audit_logs(tenant_id: str = Depends(get_tenant), _user=Depends(require_action("manage_users"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM audit_logs WHERE tenant_id=%s ORDER BY id DESC LIMIT 500", (tenant_id,))
            return cur.fetchall()


def build_board_report(window_days: int = 30, incident_limit: int = 10) -> dict:
    safe_window_days = max(7, min(window_days, 180))
    safe_incident_limit = max(3, min(incident_limit, 50))

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  COUNT(*) AS total_tenants,
                  SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_tenants,
                  SUM(CASE WHEN status = 'trialing' THEN 1 ELSE 0 END) AS trialing_tenants,
                  SUM(CASE WHEN status = 'past_due' THEN 1 ELSE 0 END) AS past_due_tenants
                FROM tenants
                """
            )
            tenant_summary = cur.fetchone()

            cur.execute(
                """
                SELECT
                  COUNT(*) AS total_incidents,
                  SUM(CASE WHEN status <> 'resolved' THEN 1 ELSE 0 END) AS open_incidents,
                  SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_incidents,
                  SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_incidents
                FROM incidents
                WHERE detected_at >= NOW() - (%s * INTERVAL '1 day')
                """,
                (safe_window_days,),
            )
            incident_summary = cur.fetchone()

            cur.execute(
                """
                                SELECT
                                    (
                                        SELECT AVG(EXTRACT(EPOCH FROM (a.detected_at - e.timestamp)))
                                        FROM alerts a
                                        LEFT JOIN events e ON e.id = a.event_id
                                        WHERE a.detected_at >= NOW() - (%s * INTERVAL '1 day')
                                    ) AS mttd,
                                    (
                                        SELECT AVG(EXTRACT(EPOCH FROM (i.responded_at - i.detected_at)))
                                        FROM incidents i
                                        WHERE i.detected_at >= NOW() - (%s * INTERVAL '1 day')
                                    ) AS mttr
                """,
                                (safe_window_days, safe_window_days),
            )
            response_metrics = cur.fetchone()

            cur.execute(
                """
                SELECT source, COUNT(*) AS count,
                       SUM(CASE WHEN converted_to_signup THEN 1 ELSE 0 END) AS converted
                FROM lead_captures
                GROUP BY source
                ORDER BY count DESC
                """
            )
            leads_by_source = cur.fetchall()

            cur.execute("SELECT COUNT(*) AS total FROM lead_captures")
            total_leads = cur.fetchone()["total"]

            cur.execute("SELECT COUNT(*) AS converted FROM lead_captures WHERE converted_to_signup=TRUE")
            converted_leads = cur.fetchone()["converted"]

            cur.execute(
                """
                SELECT status, COALESCE(reason, '') AS reason, COUNT(*) AS count
                FROM webhook_metrics
                WHERE created_at >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY status, reason
                ORDER BY count DESC
                """,
                (safe_window_days,),
            )
            webhook_summary = cur.fetchall()

            cur.execute(
                """
                SELECT tenant_id, entity, severity, status, assigned_to, detected_at
                FROM incidents
                WHERE detected_at >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY detected_at DESC
                LIMIT %s
                """,
                (safe_window_days, safe_incident_limit),
            )
            recent_incidents = cur.fetchall()

    conversion_rate = (float(converted_leads) / float(total_leads)) if total_leads else 0.0
    return {
        "generated_at": now_utc().isoformat(),
        "window_days": safe_window_days,
        "tenant_summary": {
            "total_tenants": tenant_summary["total_tenants"] or 0,
            "active_tenants": tenant_summary["active_tenants"] or 0,
            "trialing_tenants": tenant_summary["trialing_tenants"] or 0,
            "past_due_tenants": tenant_summary["past_due_tenants"] or 0,
        },
        "incident_summary": {
            "total_incidents": incident_summary["total_incidents"] or 0,
            "open_incidents": incident_summary["open_incidents"] or 0,
            "critical_incidents": incident_summary["critical_incidents"] or 0,
            "high_incidents": incident_summary["high_incidents"] or 0,
            "mttd_seconds": float(response_metrics["mttd"] or 0),
            "mttr_seconds": float(response_metrics["mttr"] or 0),
        },
        "commercial_summary": {
            "total_leads": total_leads,
            "converted_signups": converted_leads,
            "conversion_rate": conversion_rate,
            "by_source": leads_by_source,
        },
        "webhook_summary_last_window": webhook_summary,
        "recent_incidents": [
            {
                "tenant_id": row["tenant_id"],
                "entity": row["entity"],
                "severity": row["severity"],
                "status": row["status"],
                "assigned_to": row.get("assigned_to"),
                "detected_at": row["detected_at"].isoformat() if row.get("detected_at") else None,
            }
            for row in recent_incidents
        ],
    }


@app.get("/admin/reports/board")
def get_board_report(window_days: int = 30, incident_limit: int = 10, _admin=Depends(require_internal_admin_token)):
    return build_board_report(window_days=window_days, incident_limit=incident_limit)


@app.get("/admin/reports/board.md")
def get_board_report_markdown(window_days: int = 30, incident_limit: int = 10, _admin=Depends(require_internal_admin_token)):
    report = build_board_report(window_days=window_days, incident_limit=incident_limit)
    return PlainTextResponse(
        content=render_board_report_markdown(report),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="board-report.md"'},
    )


@app.post("/admin/reports/schedules")
def create_report_schedule(body: ReportScheduleCreate, _admin=Depends(require_internal_admin_token)):
    """Create a new board report export schedule."""
    schedule = normalize_report_schedule_payload(body.model_dump())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO report_schedules 
                (name, description, format, frequency, day_of_week, day_of_month, hour_of_day, 
                 window_days, incident_limit, recipients, enabled, next_run, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                RETURNING id, name, description, format, frequency, day_of_week, day_of_month, hour_of_day,
                          window_days, incident_limit, recipients, enabled, last_run, next_run,
                          created_at, updated_at
                """,
                (
                    schedule["name"],
                    schedule.get("description"),
                    schedule["format"],
                    schedule["frequency"],
                    schedule.get("day_of_week"),
                    schedule.get("day_of_month"),
                    schedule["hour_of_day"],
                    schedule["window_days"],
                    schedule["incident_limit"],
                    schedule.get("recipients"),
                    schedule["enabled"],
                    schedule.get("next_run"),
                ),
            )
            row = cur.fetchone()
            conn.commit()
            return ReportScheduleResponse(**row)


@app.get("/admin/reports/schedules")
def list_report_schedules(_admin=Depends(require_internal_admin_token)):
    """List all board report export schedules."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, description, format, frequency, day_of_week, day_of_month, hour_of_day,
                       window_days, incident_limit, recipients, enabled, last_run, next_run,
                       created_at, updated_at
                FROM report_schedules
                ORDER BY created_at DESC
                """
            )
            rows = cur.fetchall()
            return [ReportScheduleResponse(**row) for row in rows]


@app.get("/admin/reports/schedules/due")
def list_due_report_schedules_ordered(_admin=Depends(require_internal_admin_token)):
    """List enabled schedules whose next_run is in the past (i.e. currently overdue)."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, frequency, next_run
                FROM report_schedules
                WHERE enabled = TRUE
                  AND next_run IS NOT NULL
                  AND next_run <= NOW()
                ORDER BY next_run ASC
                """
            )
            return cur.fetchall()


@app.get("/admin/reports/schedules/summary")
def get_report_schedule_summary(_admin=Depends(require_internal_admin_token)):
    """Return operational counters for report schedules."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE enabled = TRUE) AS enabled,
                    COUNT(*) FILTER (WHERE enabled = FALSE) AS paused,
                    COUNT(*) FILTER (
                        WHERE enabled = TRUE
                          AND next_run IS NOT NULL
                          AND next_run <= NOW()
                    ) AS due
                FROM report_schedules
                """
            )
            row = cur.fetchone() or {}
            return {
                "total": int(row.get("total") or 0),
                "enabled": int(row.get("enabled") or 0),
                "paused": int(row.get("paused") or 0),
                "due": int(row.get("due") or 0),
            }


@app.post("/admin/reports/schedules/run-due")
def run_due_report_schedules(_admin=Depends(require_internal_admin_token)):
    """Execute all currently due schedules immediately and return execution summary."""
    return execute_due_report_schedules()


@app.get("/admin/reports/schedules/{schedule_id}")
def get_report_schedule(schedule_id: int, _admin=Depends(require_internal_admin_token)):
    """Get a specific board report export schedule."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, description, format, frequency, day_of_week, day_of_month, hour_of_day,
                       window_days, incident_limit, recipients, enabled, last_run, next_run,
                       created_at, updated_at
                FROM report_schedules
                WHERE id = %s
                """,
                (schedule_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Schedule not found")
            return ReportScheduleResponse(**row)


@app.patch("/admin/reports/schedules/{schedule_id}")
def update_report_schedule(
    schedule_id: int,
    body: ReportScheduleUpdate,
    _admin=Depends(require_internal_admin_token),
):
    """Update a board report export schedule."""
    updates = body.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, description, format, frequency, day_of_week, day_of_month, hour_of_day,
                       window_days, incident_limit, recipients, enabled, last_run, next_run,
                       created_at, updated_at
                FROM report_schedules
                WHERE id = %s
                """,
                (schedule_id,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Schedule not found")

            normalized = normalize_report_schedule_payload(updates, existing=existing)
            cur.execute(
                """
                UPDATE report_schedules
                SET name = %s,
                    description = %s,
                    format = %s,
                    frequency = %s,
                    day_of_week = %s,
                    day_of_month = %s,
                    hour_of_day = %s,
                    window_days = %s,
                    incident_limit = %s,
                    recipients = %s,
                    enabled = %s,
                    next_run = %s,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id, name, description, format, frequency, day_of_week, day_of_month, hour_of_day,
                          window_days, incident_limit, recipients, enabled, last_run, next_run,
                          created_at, updated_at
                """,
                (
                    normalized["name"],
                    normalized.get("description"),
                    normalized["format"],
                    normalized["frequency"],
                    normalized.get("day_of_week"),
                    normalized.get("day_of_month"),
                    normalized["hour_of_day"],
                    normalized["window_days"],
                    normalized["incident_limit"],
                    normalized.get("recipients"),
                    normalized["enabled"],
                    normalized.get("next_run"),
                    schedule_id,
                ),
            )
            row = cur.fetchone()
            conn.commit()
            return ReportScheduleResponse(**row)


@app.delete("/admin/reports/schedules/{schedule_id}")
def delete_report_schedule(schedule_id: int, _admin=Depends(require_internal_admin_token)):
    """Delete a board report export schedule."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM report_schedules WHERE id = %s", (schedule_id,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Schedule not found")
            conn.commit()
            return {"success": True, "message": f"Schedule {schedule_id} deleted"}


@app.post("/admin/reports/schedules/{schedule_id}/run")
def run_report_schedule(schedule_id: int, _admin=Depends(require_internal_admin_token)):
    """Execute a configured board report schedule immediately and advance timestamps."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            result = run_report_schedule_export(cur, schedule_id)
            conn.commit()
            return result


@app.get("/admin/leads")
def get_leads(limit: int = 200, _admin=Depends(require_internal_admin_token)):
    safe_limit = max(1, min(limit, 2000))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, company, email, role, source, tenant_id, converted_to_signup, created_at FROM lead_captures ORDER BY id DESC LIMIT %s",
                (safe_limit,),
            )
            return cur.fetchall()


@app.get("/admin/leads.csv")
def get_leads_csv(limit: int = 500, _admin=Depends(require_internal_admin_token)):
    safe_limit = max(1, min(limit, 5000))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, company, email, role, source, tenant_id, converted_to_signup, created_at FROM lead_captures ORDER BY id DESC LIMIT %s",
                (safe_limit,),
            )
            rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "company", "email", "role", "source", "tenant_id", "converted_to_signup", "created_at"])
    for row in rows:
        writer.writerow([
            row["id"],
            row["company"],
            row["email"],
            row["role"],
            row["source"],
            row.get("tenant_id"),
            row.get("converted_to_signup"),
            row["created_at"].isoformat(),
        ])

    return PlainTextResponse(content=output.getvalue(), media_type="text/csv")


@app.get("/admin/analytics")
def get_analytics(limit: int = 500, _admin=Depends(require_internal_admin_token)):
    safe_limit = max(1, min(limit, 5000))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, event_name, page, visitor_ip, user_agent, meta, created_at FROM analytics_events ORDER BY id DESC LIMIT %s",
                (safe_limit,),
            )
            events = cur.fetchall()

            cur.execute(
                """
                SELECT event_name, COUNT(*) AS count
                FROM analytics_events
                WHERE created_at >= NOW() - INTERVAL '7 days'
                GROUP BY event_name
                ORDER BY count DESC
                """
            )
            summary = cur.fetchall()

    return {"events": events, "summary_last_7_days": summary}


@app.get("/admin/funnel")
def get_funnel(_admin=Depends(require_internal_admin_token)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS total FROM lead_captures")
            total_leads = cur.fetchone()["total"]

            cur.execute("SELECT COUNT(*) AS converted FROM lead_captures WHERE converted_to_signup=TRUE")
            converted = cur.fetchone()["converted"]

            cur.execute(
                """
                SELECT source, COUNT(*) AS count,
                       SUM(CASE WHEN converted_to_signup THEN 1 ELSE 0 END) AS converted
                FROM lead_captures
                GROUP BY source
                ORDER BY count DESC
                """
            )
            by_source = cur.fetchall()

            cur.execute(
                """
                SELECT t.plan, COUNT(*) AS count
                FROM lead_captures l
                JOIN tenants t ON t.id = l.tenant_id
                WHERE l.converted_to_signup = TRUE
                GROUP BY t.plan
                ORDER BY count DESC
                """
            )
            converted_plans = cur.fetchall()

    conversion_rate = (float(converted) / float(total_leads)) if total_leads else 0.0
    return {
        "total_leads": total_leads,
        "converted_signups": converted,
        "conversion_rate": conversion_rate,
        "by_source": by_source,
        "converted_plan_distribution": converted_plans,
    }


@app.get("/admin/funnel/tenants")
def get_funnel_by_tenant(limit: int = 200, _admin=Depends(require_internal_admin_token)):
    safe_limit = max(1, min(limit, 1000))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  t.id AS tenant_id,
                  t.name,
                  t.plan,
                  t.status,
                  COUNT(l.id) AS leads_attributed,
                  SUM(CASE WHEN l.converted_to_signup THEN 1 ELSE 0 END) AS converted_leads,
                  MIN(l.created_at) AS first_lead_at,
                  MAX(l.created_at) AS latest_lead_at
                FROM tenants t
                LEFT JOIN lead_captures l ON l.tenant_id = t.id
                GROUP BY t.id, t.name, t.plan, t.status
                ORDER BY leads_attributed DESC, converted_leads DESC
                LIMIT %s
                """,
                (safe_limit,),
            )
            rows = cur.fetchall()
    return rows


@app.get("/admin/webhooks/metrics")
def get_webhook_metrics(limit: int = 300, _admin=Depends(require_internal_admin_token)):
    safe_limit = max(1, min(limit, 5000))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, tenant_id, stripe_event_id, event_type, status, reason, created_at FROM webhook_metrics ORDER BY id DESC LIMIT %s",
                (safe_limit,),
            )
            events = cur.fetchall()

            cur.execute(
                """
                SELECT status, COALESCE(reason, '') AS reason, COUNT(*) AS count
                FROM webhook_metrics
                WHERE created_at >= NOW() - INTERVAL '7 days'
                GROUP BY status, reason
                ORDER BY count DESC
                """
            )
            summary = cur.fetchall()

    return {"events": events, "summary_last_7_days": summary}


@app.post("/admin/webhooks/cleanup")
def cleanup_webhooks(_admin=Depends(require_internal_admin_token)):
    removed = cleanup_webhook_replays()
    return {"removed_replay_fingerprints": removed}


@app.get("/dashboard/executive")
def executive_dashboard(tenant_id: str = Depends(get_tenant), _user=Depends(require_action("view_incidents"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS total FROM incidents WHERE tenant_id=%s", (tenant_id,))
            total_incidents = cur.fetchone()["total"]

            cur.execute(
                """
                SELECT AVG(EXTRACT(EPOCH FROM (a.detected_at - e.timestamp))) AS mttd
                FROM alerts a
                JOIN events e ON e.id = a.event_id
                WHERE a.tenant_id=%s
                """,
                (tenant_id,),
            )
            mttd = cur.fetchone()["mttd"]

            cur.execute(
                """
                SELECT AVG(EXTRACT(EPOCH FROM (i.responded_at - i.detected_at))) AS mttr
                FROM incidents i
                WHERE i.tenant_id=%s AND i.responded_at IS NOT NULL
                """,
                (tenant_id,),
            )
            mttr = cur.fetchone()["mttr"]

            cur.execute(
                """
                SELECT date_trunc('day', timestamp) AS day,
                       AVG(CASE severity
                           WHEN 'critical' THEN 95
                           WHEN 'high' THEN 75
                           WHEN 'medium' THEN 50
                           ELSE 20 END) AS risk_score
                FROM alerts
                WHERE tenant_id=%s AND timestamp >= NOW() - INTERVAL '14 days'
                GROUP BY day
                ORDER BY day ASC
                """,
                (tenant_id,),
            )
            trend = [{"day": row["day"].isoformat(), "risk_score": float(row["risk_score"])} for row in cur.fetchall()]

    return {
        "tenant_id": tenant_id,
        "total_incidents": total_incidents,
        "mttd_seconds": float(mttd or 0),
        "mttr_seconds": float(mttr or 0),
        "risk_score_trend": trend,
    }


@app.get("/analytics/ueba")
def analytics_ueba(
    window_days: int = 14,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    safe_window = max(1, min(window_days, 60))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, type, raw, timestamp
                FROM events
                WHERE tenant_id=%s AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY id DESC
                LIMIT 5000
                """,
                (tenant_id, safe_window),
            )
            events = cur.fetchall()

            cur.execute(
                """
                SELECT id, event_id, severity, rule_id, timestamp
                FROM alerts
                WHERE tenant_id=%s AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY id DESC
                LIMIT 5000
                """,
                (tenant_id, safe_window),
            )
            alerts = cur.fetchall()

    summary = compute_ueba_summary(events=events, alerts=alerts, top_n=15)
    return {
        "tenant_id": tenant_id,
        "window_days": safe_window,
        "ueba": summary,
    }


@app.get("/analytics/ml-anomalies")
def analytics_ml_anomalies(
    window_days: int = 14,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    safe_window = max(1, min(window_days, 60))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, type, raw, timestamp
                FROM events
                WHERE tenant_id=%s AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY id DESC
                LIMIT 5000
                """,
                (tenant_id, safe_window),
            )
            events = cur.fetchall()

    anomalies = detect_ml_anomalies(events=events)
    return {
        "tenant_id": tenant_id,
        "window_days": safe_window,
        "ml": anomalies,
    }


@app.get("/analytics/advanced")
def analytics_advanced(
    window_days: int = 14,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    safe_window = max(1, min(window_days, 60))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, type, raw, timestamp
                FROM events
                WHERE tenant_id=%s AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY id DESC
                LIMIT 5000
                """,
                (tenant_id, safe_window),
            )
            events = cur.fetchall()

            cur.execute(
                """
                SELECT id, event_id, severity, rule_id, timestamp
                FROM alerts
                WHERE tenant_id=%s AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY id DESC
                LIMIT 5000
                """,
                (tenant_id, safe_window),
            )
            alerts = cur.fetchall()

            cur.execute(
                """
                SELECT id, severity, status, entity, timestamp
                FROM incidents
                WHERE tenant_id=%s AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                ORDER BY id DESC
                LIMIT 2000
                """,
                (tenant_id, safe_window),
            )
            incidents = cur.fetchall()

    advanced = build_advanced_analytics(events=events, alerts=alerts, incidents=incidents)
    return {
        "tenant_id": tenant_id,
        "window_days": safe_window,
        "advanced": advanced,
    }


@app.get("/demo/bootstrap")
def demo_bootstrap():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT key FROM api_keys WHERE tenant_id=%s ORDER BY id DESC LIMIT 1", ("demo-corp",))
            key_row = cur.fetchone()
    return {
        "tenant_id": "demo-corp",
        "name": "Demo Corp",
        "preloaded_incidents": True,
        "owner": {"email": "owner@company.com", "password": "owner1234"},
        "analyst": {"email": "analyst@company.com", "password": "analyst123"},
        "viewer": {"email": "viewer@company.com", "password": "viewer123"},
        "api_key": key_row["key"] if key_row else None,
    }


@app.post("/admin/demo/reset")
def admin_demo_reset(body: DemoResetBody, _admin=Depends(require_internal_admin_token)):
    result = reset_demo_tenant_data(regenerate_api_key=body.regenerate_api_key)
    return {"status": "reset", **result}


@app.post("/admin/demo/run-showcase")
async def admin_demo_showcase(body: AdminDemoBody, _admin=Depends(require_internal_admin_token)):
    return await _run_demo_attack_flow("demo-corp", body)


@app.get("/demo/scenarios")
def demo_scenarios():
    return {
        "safe_lab": True,
        "scenarios": _scenario_catalog(),
    }


@app.post("/demo/seed-attack-data")
async def demo_seed_attack_data(
    body: DemoSeedBody,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("respond")),
):
    scenario_ids = _normalize_live_scenarios(None)
    generated = []
    for _ in range(body.rounds):
        for scenario in scenario_ids:
            result = await _run_demo_attack_flow(
                tenant_id,
                AdminDemoBody(
                    user_id="demo.user",
                    source_country="UK",
                    destination_country="US",
                    scenario=scenario,  # type: ignore[arg-type]
                    iterations=1,
                    include_noise=body.include_noise,
                    dry_run=False,
                ),
            )
            generated.append({"scenario": scenario, "event_count": result.get("event_count", 0)})

    return {
        "tenant_id": tenant_id,
        "status": "seeded",
        "rounds": body.rounds,
        "scenarios": generated,
        "total_events": sum(item["event_count"] for item in generated),
    }


@app.post("/demo/live/start")
async def demo_live_start(
    body: LiveSimulationBody,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("respond")),
):
    await _stop_live_simulation(tenant_id)
    state = {
        "running": True,
        "interval_seconds": body.interval_seconds,
        "include_noise": body.include_noise,
        "scenarios": _normalize_live_scenarios(body.scenarios),
        "started_at": now_utc().isoformat(),
        "last_emitted_at": None,
        "last_scenario": None,
        "last_error": None,
        "emitted_count": 0,
    }
    LIVE_SIMULATION_STATE[tenant_id] = state
    LIVE_SIMULATION_TASKS[tenant_id] = asyncio.create_task(_live_simulation_worker(tenant_id))
    return {"tenant_id": tenant_id, **state}


@app.post("/demo/live/stop")
async def demo_live_stop(
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("respond")),
):
    await _stop_live_simulation(tenant_id)
    state = LIVE_SIMULATION_STATE.get(tenant_id, {})
    state["running"] = False
    state["stopped_at"] = now_utc().isoformat()
    LIVE_SIMULATION_STATE[tenant_id] = state
    return {"tenant_id": tenant_id, **state}


@app.get("/demo/live/status")
def demo_live_status(
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    state = LIVE_SIMULATION_STATE.get(tenant_id, {})
    task = LIVE_SIMULATION_TASKS.get(tenant_id)
    return {
        "tenant_id": tenant_id,
        "running": bool(state.get("running") and task and not task.done()),
        "interval_seconds": state.get("interval_seconds"),
        "include_noise": state.get("include_noise"),
        "scenarios": state.get("scenarios") or [],
        "started_at": state.get("started_at"),
        "stopped_at": state.get("stopped_at"),
        "last_emitted_at": state.get("last_emitted_at"),
        "last_scenario": state.get("last_scenario"),
        "last_error": state.get("last_error"),
        "emitted_count": state.get("emitted_count", 0),
    }


@app.post("/demo/simulate-attack")
async def simulate_attack(
    body: DemoAttackBody,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("respond")),
):
    demo_body = AdminDemoBody(
        user_id=body.user_id,
        source_country=body.source_country,
        destination_country=body.destination_country,
        scenario=body.scenario,
        iterations=body.iterations,
        include_noise=body.include_noise,
        dry_run=body.dry_run,
    )
    return await _run_demo_attack_flow(tenant_id, demo_body)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    tenant_id = ws.query_params.get("tenant_id")
    token = ws.query_params.get("token")
    if not tenant_id or not token:
        await ws.close(code=1008)
        return
    try:
        claims = verify_token(token, token_type="access")
    except ValueError:
        await ws.close(code=1008)
        return

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT tenant_id FROM users WHERE id=%s", (claims.get("sub"),))
            user = cur.fetchone()
    if not user or user["tenant_id"] != tenant_id:
        await ws.close(code=1008)
        return

    await ws.accept()
    clients.append({"ws": ws, "tenant_id": tenant_id})
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        for item in list(clients):
            if item["ws"] == ws:
                clients.remove(item)


async def broadcast(tenant_id: str, alert: dict):
    stale = []
    for c in clients:
        if c["tenant_id"] != tenant_id:
            continue
        try:
            await c["ws"].send_json(alert)
        except Exception:
            stale.append(c)
    for c in stale:
        if c in clients:
            clients.remove(c)


def _run_response(tenant_id: str, action: str, target: str, incident_id: int):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incidents SET status=%s, responded_at=NOW() WHERE id=%s AND tenant_id=%s",
                ("contained", incident_id, tenant_id),
            )
            cur.execute(
                "UPDATE alerts SET responded_at=NOW() WHERE event_id IN (SELECT id FROM events WHERE tenant_id=%s)",
                (tenant_id,),
            )
        conn.commit()

    result = {
        "tenant_id": tenant_id,
        "incident_id": incident_id,
        "action": action,
        "target": target,
        "status": f"{target} handled via {action}",
        "timestamp": now_utc().isoformat(),
    }
    rdb.xadd(f"soc:{tenant_id}:responses", {"response": json.dumps(result)})
    return result
