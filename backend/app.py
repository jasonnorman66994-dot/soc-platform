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
AUTO_RESPONSE_RISK_THRESHOLD = int(os.getenv("AUTO_RESPONSE_RISK_THRESHOLD", "85"))


def _select_playbook_title(patterns: list[str], event_type: str | None) -> str:
    if "ACCOUNT_TAKEOVER" in patterns:
        return "account_takeover"
    if "IMPOSSIBLE_TRAVEL_CHAIN" in patterns:
        return "suspicious_ip"
    if event_type == "data_exfil":
        return "data_exfiltration"
    if event_type in {"email", "email_click"}:
        return "phishing"
    return "generic_alert"


def _should_auto_respond(incident_row: dict | None, risk_score: int, patterns: list[str]) -> bool:
    if not AUTO_RESPONSE_ENABLED or not incident_row:
        return False
    if (incident_row.get("status") or "").lower() in {"responded", "closed", "resolved"}:
        return False
    if incident_row.get("responded_at"):
        return False
    if risk_score >= AUTO_RESPONSE_RISK_THRESHOLD:
        return True
    return any(item in {"ACCOUNT_TAKEOVER", "IMPOSSIBLE_TRAVEL_CHAIN"} for item in patterns)


def _build_playbook_inputs(incident_row: dict, payload: dict, patterns: list[str], risk_score: int) -> tuple[dict, dict]:
    event_type = payload.get("event_type")
    incident_payload = {
        "id": incident_row.get("id"),
        "title": _select_playbook_title(patterns, event_type),
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

ROLE_ORDER = {"viewer": 1, "analyst": 2, "admin": 3, "owner": 4}
VALID_PLANS = {"free", "pro", "enterprise"}
VALID_LEAD_SOURCES = {"landing", "webinar", "partner", "unknown"}
VALID_REPORT_SCHEDULE_FORMATS = {"markdown", "json"}
VALID_REPORT_SCHEDULE_FREQUENCIES = {"daily", "weekly", "monthly"}
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


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


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

                ALTER TABLE lead_captures ADD COLUMN IF NOT EXISTS tenant_id TEXT;
                ALTER TABLE lead_captures ADD COLUMN IF NOT EXISTS converted_to_signup BOOLEAN NOT NULL DEFAULT FALSE;
                ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS day_of_month INTEGER;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_events_event_id ON billing_events (stripe_event_id) WHERE stripe_event_id IS NOT NULL;

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

    if context:
        patterns = _detect_behavior_patterns(context)
        user_alerts = [
            {"severity": item.get("severity"), "summary": item.get("summary")}
            for item in alert_rows
        ]
        risk_score = _calculate_context_risk(context, user_alerts, patterns)

        if _should_auto_respond(incident_row, risk_score, patterns):
            incident_payload, event_payload = _build_playbook_inputs(incident_row, payload, patterns, risk_score)
            playbook_result = execute_playbook_for_incident(incident_payload, event_payload)
            playbook_status = playbook_result.get("status", "unknown")

            if playbook_status == "success" and incident_row:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE incidents SET status='responded', responded_at=NOW() WHERE id=%s AND tenant_id=%s",
                            (incident_row["id"], tenant_id),
                        )
                    conn.commit()
                incident_row["status"] = "responded"
                incident_row["responded_at"] = now_utc().isoformat()

            if incident_row:
                log_response_action(
                    incident_row["id"],
                    "auto_playbook",
                    "success" if playbook_status == "success" else "error",
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
            },
        )

    log_action(tenant_id, None, "event.ingest", "events", {"event_id": saved_event["id"], "alerts": len(alert_rows)})

    return {
        "event": {"id": saved_event["id"], "timestamp": saved_event["timestamp"].isoformat(), **payload},
        "alerts": alert_rows,
        "incident": incident_row,
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
                "SELECT * FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
            incident_row = cur.fetchone()
    
    if not incident_row:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Get event associated with incident
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM events WHERE tenant_id=%s ORDER BY id DESC LIMIT 1",
                (tenant_id,),
            )
            event_row = cur.fetchone()
    
    if not event_row:
        return {"status": "warning", "message": "No events found for incident"}
    
    # Execute playbook
    result = execute_playbook_for_incident(incident_row, event_row)
    
    # Log the automation
    log_action(
        tenant_id,
        user["id"],
        "soar.playbook_executed",
        f"incidents/{incident_id}",
        {"playbook": result.get("playbook"), "actions": len(result.get("actions", []))},
    )
    
    # Mark incident as responded
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE incidents SET status=%s, responded_at=NOW() WHERE id=%s AND tenant_id=%s",
                ("responded", incident_id, tenant_id),
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


@app.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: int,
    tenant_id: str = Depends(get_tenant),
    _user=Depends(require_action("view_incidents")),
):
    """Get incident timeline events."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, status, severity, title, first_seen, last_seen FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
            incident = cur.fetchone()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {
        "incident_id": incident_id,
        "status": incident["status"],
        "timeline": [
            {
                "timestamp": incident["first_seen"].isoformat(),
                "action": "incident_created",
                "description": "Incident detected",
            },
            {
                "timestamp": incident["last_seen"].isoformat(),
                "action": "incident_updated",
                "description": "Last activity",
            },
        ],
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
