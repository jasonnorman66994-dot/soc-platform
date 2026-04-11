from datetime import datetime, timedelta, timezone
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


class DemoAttackBody(BaseModel):
    user_id: str = "demo.user"
    source_country: str = "UK"
    destination_country: str = "US"


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


def _build_attack_events(user_id: str, source_country: str, destination_country: str) -> list[dict]:
    return [
        {
            "user_id": user_id,
            "event_type": "email",
            "subject": "URGENT: Security policy update",
            "sender_domain": "comp-security-check.net",
            "raw": {"stage": "email_delivered"},
        },
        {
            "user_id": user_id,
            "event_type": "email_click",
            "subject": "Clicked suspicious link",
            "sender_domain": "comp-security-check.net",
            "raw": {"stage": "link_clicked"},
        },
        {
            "user_id": user_id,
            "event_type": "login_anomaly",
            "ip": "198.51.100.9",
            "raw": {"from": source_country, "to": destination_country, "geo_mismatch": True},
        },
        {
            "user_id": user_id,
            "event_type": "data_exfil",
            "ip": "198.51.100.9",
            "raw": {"stage": "file_download", "sensitive": True, "file": "finance_q3.xlsx"},
        },
    ]


async def _run_demo_attack_flow(tenant_id: str, body: AdminDemoBody) -> dict:
    outcomes = []
    for evt in _build_attack_events(body.user_id, body.source_country, body.destination_country):
        model = IngestEvent(**evt)
        result = await ingest(model, tenant_id=tenant_id, _key={"tenant_id": tenant_id})
        outcomes.append(result)

    return {
        "timeline": [
            "Email delivered",
            "Link clicked",
            f"Login anomaly {body.source_country} -> {body.destination_country}",
            "Sensitive file download",
        ],
        "outcomes": outcomes,
    }


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
                "SELECT id, user_id, type, timestamp FROM events WHERE tenant_id=%s ORDER BY id DESC LIMIT 30",
                (tenant_id,),
            )
            recent_events = [
                {
                    "id": e["id"],
                    "user_id": e["user_id"],
                    "event_type": e["type"],
                    "timestamp": e["timestamp"].isoformat(),
                }
                for e in cur.fetchall()
            ]

            incident = correlate(recent_events, alerts)
            incident_row = None
            if incident:
                cur.execute(
                    """
                    INSERT INTO incidents (tenant_id, entity, severity, status, story, assigned_to)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id, tenant_id, entity, severity, status, story, assigned_to, timestamp
                    """,
                    (tenant_id, incident["entity"], incident["severity"], incident["status"], json.dumps(incident["story"]), None),
                )
                incident_row = cur.fetchone()

        conn.commit()

    rdb.xadd(f"soc:{tenant_id}:events", {"event": json.dumps(payload)})
    for a in alerts:
        await broadcast(tenant_id, {"kind": "alert", **a})

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
