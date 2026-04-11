# SOC Platform (Enterprise SaaS)

## Architecture

Frontend (Next.js) -> Nginx -> API Gateway (FastAPI) -> Multi-Tenant Auth (JWT access+refresh + RBAC)
-> API-Key Ingestion -> Detection Marketplace -> Correlation + AI Analyst -> PostgreSQL + Redis -> WebSocket UI

## Services

- backend: FastAPI gateway with multi-tenant isolation, onboarding, billing scaffold, audit logs, executive metrics
- frontend: Next.js SOC command center
- redis: streaming cache and response/event stream channel
- db: PostgreSQL incident/event/alert store
- nginx: reverse proxy for UI + API + WebSocket

## Phase 22 Features Implemented

- Multi-tenant enforcement via `X-Tenant-ID` on all tenant-scoped APIs.
- Tenant-scoped persistence (`tenant_id`) across events, alerts, incidents, users, api_keys, and audit logs.
- RBAC matrix implemented:
  - `view_incidents`: owner/admin/analyst/viewer
  - `respond`: owner/admin/analyst
  - `manage_users`: owner/admin
- Onboarding API (`POST /api/signup`) that creates tenant, owner user, and ingestion API key.
- Billing scaffold on tenant model (`plan`, `status`, `stripe_customer_id`) with plan gating.
- SOC2-style audit logging for auth, ingestion, user management, and response actions.
- Detection marketplace rule packs under `backend/rules/` with `/api/rules` endpoint.
- Demo tenant bootstrap (`GET /api/demo/bootstrap`) with preloaded incidents.
- Executive dashboard endpoint (`GET /api/dashboard/executive`) with total incidents, MTTD, MTTR, risk trend.
- AI analyst response (`GET /api/ai/analyze/{incident_id}`) with summary, impact, timeline, and next steps.
- Security hardening: rate limiting, stricter Pydantic validation, JWT expiration + refresh, HTTPS enforcement toggle via env.
- Realistic attack simulation (`POST /api/demo/simulate-attack`) for full kill-chain demo.

## Quick Start

```bash
cd soc-platform
docker compose up --build
```

- SaaS landing page: <http://localhost>
- Live command center: <http://localhost/command-center>
- Frontend direct: <http://localhost:3000>
- Backend direct: <http://localhost:8000>

## Demo Bootstrap (Tenant + Credentials + API Key)

```bash
curl http://localhost/api/demo/bootstrap
```

Returns demo tenant id, seeded users, and API key.

## Command Center Modes

- `http://localhost/command-center` now supports:
  - `Demo Mode`: auto-connects `demo-corp` seeded tenant.
  - `Live Tenant Mode`: manual tenant/email/password/API key entry for customer demos.

## Auth (Tenant-Aware)

1. Login:

```bash
curl -X POST http://localhost/api/auth/login \
  -H "X-Tenant-ID: demo-corp" \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@company.com","password":"analyst123"}'
```

1. Refresh access token:

```bash
curl -X POST http://localhost/api/auth/refresh \
  -H "X-Tenant-ID: demo-corp" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

## API-Key Ingestion (Tenant-Isolated)

```bash
curl -X POST http://localhost/api/ingest \
  -H "X-Tenant-ID: demo-corp" \
  -H "X-API-Key: <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "demo.user",
    "event_type": "email",
    "subject": "URGENT: Verify my password",
    "sender_domain": "evil.com"
  }'
```

## Realistic Final Test Flow

```bash
curl -X POST http://localhost/api/demo/simulate-attack \
  -H "X-Tenant-ID: demo-corp" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"demo.user","source_country":"UK","destination_country":"US"}'
```

Expected behavior:

- Alerts are generated for phishing/login anomaly/data exfiltration stages.
- Incidents are correlated with attack timeline.
- Executive dashboard metrics update.
- AI analysis suggests response actions.

## Default Demo Users

- <owner@company.com> / owner1234 (owner)
- <admin@company.com> / admin123 (admin)
- <analyst@company.com> / analyst123 (analyst)
- <viewer@company.com> / viewer123 (viewer)

## Rule Marketplace Packs

- `backend/rules/microsoft/`
- `backend/rules/phishing/`
- `backend/rules/insider_threat/`

## Investor-Ready Extension Track (Optional)

- Add Stripe webhook + subscription lifecycle jobs.
- Add tenant self-service settings and branding.
- Add long-term data retention tiers and usage metering.
- Add downloadable board-ready incident and KPI reports.

## Commercial APIs

### Lead Capture

`POST /api/public/waitlist`

```json
{
  "company": "Northwind Security",
  "email": "ciso@northwind.example",
  "role": "CISO",
  "source": "landing"
}
```

### Stripe Webhook (Scaffold)

`POST /api/billing/stripe/webhook`

- Stores webhook payload in `billing_events`
- Maps Stripe customer to tenant via `stripe_customer_id`
- Updates tenant `plan` and `status` on subscription events
- Ignores duplicate webhook deliveries via `stripe_event_id` idempotency check
- Adds replay-fingerprint guard for re-sent signed payloads
- Enforces signature timestamp tolerance (`STRIPE_WEBHOOK_TOLERANCE_SECONDS`)
- Supports replay fingerprint cleanup via `/api/admin/webhooks/cleanup`

Supported transitions:

- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `checkout.session.completed`

### Subscription Access

- `GET /api/tenants/subscription` (owner/admin)
- `POST /api/tenants/subscription` (owner/admin manual override)

### Lead Attribution

- `POST /api/public/waitlist` leads can be auto-attributed during `POST /api/signup` by matching email
- Signup response now includes `lead_attributed`
- Lead records include `tenant_id` and `converted_to_signup`

## Billing and Security Environment Variables

- `JWT_SECRET`: signing key for access/refresh tokens
- `STRIPE_WEBHOOK_SECRET`: enables webhook signature validation
- `STRIPE_WEBHOOK_TOLERANCE_SECONDS`: webhook timestamp tolerance (default `300`)
- `WEBHOOK_REPLAY_TTL_DAYS`: replay fingerprint retention window before cleanup (default `7`)
- `INTERNAL_ADMIN_TOKEN`: access token for internal lead/analytics admin APIs
- `ENFORCE_HTTPS=true`: enforce HTTPS-only API behavior
- `ALLOW_INSECURE_HTTP=false`: block insecure HTTP when HTTPS enforcement is on
- `RATE_LIMIT_PER_MINUTE=120`: global per-route IP limiter

## Funnel Analytics APIs

- `POST /api/public/analytics`: capture anonymous product funnel events
- Landing page sends events like `landing_view`, `lead_submitted`, and CTA clicks

## Internal Admin APIs

Protected by header `X-Admin-Token: <INTERNAL_ADMIN_TOKEN>`:

- `GET /api/admin/leads`: JSON list of captured leads
- `GET /api/admin/leads.csv`: CSV export for CRM import
- `GET /api/admin/analytics`: raw analytics events + 7-day event summary
- `GET /api/admin/webhooks/metrics`: webhook observability counters and recent events

Optional signed admin sessions:

- `POST /api/admin/session` with `{ "admin_token": "<INTERNAL_ADMIN_TOKEN>" }`
- Use returned bearer token as `Authorization: Bearer <token>` for `/api/admin/*`
- Rotate session tokens: `POST /api/admin/session/refresh`
- Revoke session tokens: `POST /api/admin/session/revoke`
- Funnel conversion metrics: `GET /api/admin/funnel`
- Tenant conversion breakdown: `GET /api/admin/funnel/tenants`
- Replay fingerprint cleanup: `POST /api/admin/webhooks/cleanup`
- Board-ready KPI JSON: `GET /api/admin/reports/board`
- Downloadable board-ready Markdown report: `GET /api/admin/reports/board.md`

Board report query parameters:

- `window_days`: rolling lookback window for incident/webhook metrics (default `30`)
- `incident_limit`: number of recent incidents to include (default `10`)

### Board Report Export Scheduling

Admin-only endpoints for managing automated board report export schedules:

- **Create schedule**: `POST /api/admin/reports/schedules` — Accepts `name`, `description`, `format` (markdown/json), `frequency` (daily/weekly/monthly), `day_of_week`, `day_of_month`, `hour_of_day`, `window_days`, `incident_limit`, `recipients`, `enabled`.
- **List schedules**: `GET /api/admin/reports/schedules` — Returns array of all configured export schedules.
- **Get schedule**: `GET /api/admin/reports/schedules/{id}` — Returns single schedule by ID.
- **Update schedule**: `PATCH /api/admin/reports/schedules/{id}` — Partial update of schedule fields.
- **Run schedule now**: `POST /api/admin/reports/schedules/{id}/run` — Executes the configured export immediately, updates `last_run`/`next_run`, and returns the generated report payload.
- **Delete schedule**: `DELETE /api/admin/reports/schedules/{id}` — Removes schedule.

Schedule validation rules:

- `format` must be `markdown` or `json`
- `frequency` must be `daily`, `weekly`, or `monthly`
- Weekly schedules require `day_of_week` in the range `0-6`
- Monthly schedules require `day_of_month` in the range `1-28`
- Enabled schedules now return a computed `next_run` timestamp

Command Center support:

- **Admin Operations Panel** now includes Board Report Export Schedule section.
- Input fields for schedule name, frequency, day-of-week or day-of-month, hour, report format, and immediate CRUD controls.
- `Load Board Report` and `Download Board Report` use parameter inputs and clamp to safe ranges.
- Active schedules listed with run-now and delete controls plus computed next-run visibility.

## Founder Assets

- Pitch deck narrative: `founder/PITCH_DECK.md`
- Pricing strategy: `founder/PRICING_STRATEGY.md`
- Competitive positioning: `founder/COMPETITIVE_POSITIONING.md`
- Live demo runbook: `founder/DEMO_SCRIPT.md`
