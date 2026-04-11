# SOC Platform v2.0.0 - Complete System Architecture

## System Overview

```
┌─ ATTACKERS
│
├─→ [Event Sources]
│   ├─ Email servers (phishing detection)
│   ├─ Identity providers (login anomalies)
│   ├─ Cloud platforms (network activity)
│   ├─ Endpoint sensors (host activity)
│   └─ Application logs (suspicious behavior)
│
├─→ [SOC Platform Data Flow]
│   │
│   ├─ INGESTION LAYER
│   │   └─→ POST /api/ingest
│   │       └─→ Kafka Topic: logs
│   │           └─→ Event Storage (PostgreSQL)
│   │               └─→ Redis Stream
│   │
│   ├─ DETECTION LAYER
│   │   ├─→ Kafka Consumer (Worker)
│   │   │   ├─ Baseline Detection Rules
│   │   │   │   └─ Rule Engine (pattern matching)
│   │   │   ├─ Correlation Engine
│   │   │   │   └─ Timeline Analysis (10-min window)
│   │   │   ├─ Pattern Detection
│   │   │   │   ├─ Account Takeover
│   │   │   │   ├─ Impossible Travel
│   │   │   │   └─ Post-Compromise Privilege Escalation
│   │   │   └─ MITRE ATT&CK Mapping
│   │   │
│   │   └─→ Alerts → PostgreSQL
│   │
│   ├─ CORRELATION LAYER
│   │   ├─→ Event × Alerts → Incident Fingerprinting
│   │   ├─→ Deduplication & Aggregation
│   │   └─→ Incidents → PostgreSQL
│   │
│   ├─ AI ANALYSIS LAYER
│   │   ├─→ GET /api/ai/analyze/{incident_id}
│   │   ├─→ Risk Scoring (0-100)
│   │   ├─→ Attack Narrative Generation
│   │   ├─→ Impact Assessment (business/operational)
│   │   ├─→ Root Cause Analysis
│   │   ├─→ MITRE Technique Mapping
│   │   ├─→ Affected Assets Identification
│   │   └─→ Prioritized Recommendations
│   │
│   ├─ SOAR AUTOMATION LAYER
│   │   ├─→ POST /api/automate/incident/{id}
│   │   ├─→ Intelligent Playbook Selection
│   │   │   ├─ Account Takeover Playbook
│   │   │   │   └─→ disable_user()
│   │   │   │   └─→ revoke_sessions()
│   │   │   │   └─→ force_password_reset()
│   │   │   │   └─→ enable_mfa()
│   │   │   │   └─→ notify_all_channels()
│   │   │   │
│   │   │   ├─ Suspicious IP Playbook
│   │   │   │   └─→ block_ip()
│   │   │   │   └─→ isolate_subnet() [if critical]
│   │   │   │   └─→ notify_all_channels()
│   │   │   │
│   │   │   ├─ Phishing Playbook
│   │   │   │   └─→ block_domain()
│   │   │   │   └─→ notify_all_channels()
│   │   │   │
│   │   │   └─ Data Exfiltration Playbook
│   │   │       └─→ block_ip()
│   │   │       └─→ disable_user()
│   │   │       └─→ isolate_subnet()
│   │   │       └─→ escalate_notify()
│   │   │
│   │   └─→ INTEGRATIONS
│   │       ├─ Identity Provider (Okta, Azure AD)
│   │       ├─ Network Provider (Cloudflare, AWS WAF)
│   │       └─ Messaging (Slack, Teams, Email, SIEM)
│   │
│   ├─ INCIDENT MANAGEMENT LAYER
│   │   ├─→ PUT /api/incidents/{id}/status
│   │   ├─→ Timeline Tracking (all actions)
│   │   ├─→ Analyst Notes (with tags)
│   │   ├─→ Response Action Logging
│   │   ├─→ Incident Aggregation (same user/IP/domain)
│   │   └─→ Incident Closure (with resolution)
│   │
│   └─ REAL-TIME STREAMING
│       ├─→ GET /ws/alerts
│       ├─→ Redis Pubsub (soc-core:alerts channel)
│       ├─→ Connected WebSocket clients
│       └─→ Frontend real-time dashboard updates
│
├─→ [API GATEWAY]
│   └─ FastAPI (8000)
│       ├─ Multi-tenant isolation (X-Tenant-ID)
│       ├─ RBAC enforcement (JWT + role matrix)
│       ├─ Rate limiting by endpoint
│       ├─ Audit logging
│       └─ Health endpoints (/health, /ready)
│
├─→ [NGINX REVERSE PROXY]
│   └─ soc.example.com:443
│       ├─ HTTPS/TLS termination
│       ├─ Rate limiting (API, login, WebSocket)
│       ├─ Response caching (10m)
│       ├─ Gzip compression
│       ├─ Security headers (HSTS, CSP, etc.)
│       └─ Load balancing (3+ API replicas)
│
├─→ [FRONTEND]
│   ├─ Next.js Dashboard
│   │   ├─ SOC Command Center (/soc-dashboard)
│   │   │   ├─ Alert Feed (live stream)
│   │   │   ├─ Attack Timeline (with replay)
│   │   │   ├─ Incident Graph (IP/user/event relationships)
│   │   │   └─ Metrics Cards (top KPIs)
│   │   │
│   │   ├─ Focused Views
│   │   │   ├─ /alerts (live feed only)
│   │   │   ├─ /timeline (historical events)
│   │   │   └─ /graph (investigation view)
│   │   │
│   │   └─ WebSocket Connection
│   │       └─→ ws://soc.example.com/ws/alerts
│   │           └─ Real-time alert streaming
│   │
│   └─ Browser Clients
│       └─ Connected via WebSocket for live updates
│
├─→ [DATA PERSISTENCE]
│   ├─ PostgreSQL (Primary DB)
│   │   ├─ Events (raw ingested log entries)
│   │   ├─ Alerts (detection engine output)
│   │   ├─ Incidents (correlated incidents with fingerprints)
│   │   ├─ Users (multi-tenant user accounts)
│   │   ├─ Audit Logs (all actions + actors)
│   │   └─ Report Schedules (recurring reports)
│   │
│   └─ Redis (Cache + Streaming)
│       ├─ event:stream (real-time event stream)
│       ├─ soc-core:alerts (WebSocket alert pubsub)
│       ├─ response:stream (SOAR action log)
│       └─ session:* (user session cache)
│
├─→ [MESSAGE QUEUE]
│   └─ Kafka
│       ├─ Topic: logs (raw events from ingestion)
│       ├─ Topic: alerts (detected alerts)
│       └─ Topic: incidents (correlated incidents)
│
└─→ [KUBERNETES ORCHESTRATION]
    ├─ Deployment: soc-api (3-10 replicas)
    ├─ Service: soc-api (ClusterIP)
    ├─ Ingress: soc.example.com (HTTPS via Let's Encrypt)
    ├─ StatefulSet: PostgreSQL (with PVC)
    ├─ StatefulSet: Redis (with PVC)
    ├─ StatefulSet: Kafka (with PVC)
    ├─ HorizontalPodAutoscaler (CPU/Memory based)
    ├─ PodDisruptionBudget (HA guarantee)
    ├─ NetworkPolicy (pod isolation)
    └─ ConfigMap: soc-logging-config
```

---

## Component Interaction Matrix

| From | To | Protocol | Purpose |
|------|----|---------|----|
| Event Source | API Ingestion | HTTPS | Send events |
| API | Kafka | TCP | Queue events |
| Worker | Kafka | TCP | Consume events |
| Worker | PostgreSQL | TCP | Store events/alerts/incidents |
| Worker | Redis | TCP | Publish real-time stream |
| API | Redis Pubsub | TCP | Subscribe for WebSocket relay |
| API | PostgreSQL | TCP | Query incidents/events |
| Frontend | API | HTTPS | REST API calls |
| Frontend | API | WSS | WebSocket alerts |
| SOAR | Identity Provider | HTTPS | Account control |
| SOAR | Network Provider | HTTPS | IP/domain blocking |
| SOAR | Messaging | HTTPS/SMTP | Send alerts |
| NGINX | API | HTTP | Proxy requests |
| Client | NGINX | HTTPS | Browse dashboard |

---

## Deployment Topology

### Single-Region HA (Production)

```
┌─────────────────────────────────────────────────────────┐
│ Kubernetes Cluster (e.g., GKE, EKS, AKS)              │
│                                                         │
│ ┌───────────────────────────────────────────────────┐  │
│ │ Ingress with Let's Encrypt                        │  │
│ │ soc.example.com → NGINX LB                        │  │
│ └───────────────────────────────────────────────────┘  │
│                    ↓                                    │
│ ┌────────────────────────────────────────────────────┐ │
│ │ NGINX Reverse Proxy (rate limit, cache, TLS)      │ │
│ └────────────────────────────────────────────────────┘ │
│   ↓                    ↓                     ↓         │
│ ┌──────────┐      ┌──────────┐      ┌──────────┐     │
│ │ soc-api  │      │ soc-api  │      │ soc-api  │     │
│ │ replica  │      │ replica  │      │ replica  │     │
│ │ :8000    │      │ :8000    │      │ :8000    │     │
│ └──────────┘      └──────────┘      └──────────┘     │
│
│ Data Layer (separate pod or cluster):
│ ┌──────────┐  ┌─────────┐  ┌────────────┐            │
│ │PostgreSQL│  │ Redis   │  │   Kafka    │            │
│ │(primary) │  │(pubsub) │  │ (broker)   │            │
│ └──────────┘  └─────────┘  └────────────┘            │
│
│ Auto-scaling:
│ HPA watching CPU/Memory → scale 3-10 replicas
│
│ Resilience:
│ - Rolling updates (maxSurge: 1, maxUnavailable: 0)
│ - Pod Affinity spread across nodes
│ - PDB ensures 1 pod always available
└─────────────────────────────────────────────────────────┘
```

---

## Request Flow Example: Account Takeover Incident

```
1. USER LOGIN FROM NEW COUNTRY
   ├─→ POST /api/ingest
   ├─→ JSON: {user: "alice", event_type: "login", ip: "203.0.113.45", location: "CN"}
   └─→ Kafka Topic: logs

2. WORKER PROCESSING
   ├─→ Kafka Consumer reads event
   ├─→ Baseline Detection: "login_from_unusual_location" ALERT
   ├─→ Correlation Engine: 
   │   └─ Checks alice's login timeline (last 10 minutes)
   │   └─ No previous logins from China → ANOMALY
   ├─→ Pattern Detection: "impossible_travel" ALERT (unlikely distance in short time)
   ├─→ Generate Incident Fingerprint: hash(alice|203.0.113.45|login)
   ├─→ Insert/Update Incident in PostgreSQL
   ├─→ Upsert Alerts (baseline + correlated)
   └─→ Redis Publish to "soc-core:alerts" channel

3. REAL-TIME NOTIFICATION
   ├─→ Connected WebSocket clients receive alert
   ├─→ Frontend updates AlertFeed component
   ├─→ Dashboard shows new incident in card & feed
   └─→ Analyst sees "Login from China" incident

4. AI ANALYSIS
   ├─→ Analyst clicks "Analyze" button
   ├─→ GET /api/ai/analyze/incident_id
   ├─→ AIAnalyzer returns:
   │   ├─ summary: "Possible account takeover via credential compromise"
   │   ├─ risk_score: 82 (HIGH)
   │   ├─ mitre_techniques: ["T1078.004", "T1110.003"]
   │   └─ recommendations: [
   │       "Disable user immediately",
   │       "Revoke all active sessions",
   │       "Force password reset on re-enable",
   │       "Enable MFA enforcement"
   │   ]
   └─→ Frontend displays analysis to analyst

5. SOAR AUTOMATION
   ├─→ Analyst clicks "Automate Response"
   ├─→ POST /api/automate/incident/{id}
   ├─→ PlaybookExecutor detects "account_takeover" pattern
   ├─→ Sequential execution:
   │   ├─ disable_user("alice")
   │   │  └─→ POST to Okta API: deactivate user
   │   │  └─→ Response: {status: "disabled", timestamp: "..."}
   │   │
   │   ├─ revoke_sessions("alice")
   │   │  └─→ POST to Okta API: revoke sessions
   │   │  └─→ Forces all Alice's active browser sessions to re-auth
   │   │
   │   ├─ force_password_reset("alice")
   │   │  └─→ POST to Okta API: reset_password
   │   │  └─→ Sends email to alice@company.com with reset link
   │   │
   │   ├─ enable_mfa("alice")
   │   │  └─→ POST to Okta API: enforce_mfa
   │   │  └─→ Alice must register MFA (TOTP or hardware key)
   │   │
   │   └─ notify_all_channels()
   │      ├─→ POST to Slack: #security channel
   │      │  └─ "🚨 Account takeover response: alice disabled, sessions revoked"
   │      ├─→ POST to Teams: SOC team channel
   │      │  └─ Same notification
   │      ├─→ POST to email: security-team@company.com
   │      │  └─ Email with incident details
   │      └─→ POST to Splunk: forward event
   │         └─ Log response action for audit
   │
   ├─→ All actions logged in SOAR execution history
   ├─→ Response status updated in incident:
   │   ├─ Incident status: "responded"
   │   ├─ Timeline events added for each action
   │   ├─ Response summary shows 5 actions executed
   │   └─ Completed at: 2026-04-10T12:34:56Z
   │
   └─→ Total response time: ~30 seconds (automated)

6. INCIDENT MANAGEMENT
   ├─→ Analyst adds note: "Confirmed: attacker used credential stuffing"
   ├─→ Analyst tags: ["CONFIRMED", "EXTERNAL_ATTACKER"]
   ├─→ Analyst checks related incidents: 3 other logins from China in 24h
   ├─→ Links as siblings (related user/IP group)
   ├─→ When investigation complete:
   │   ├─ POST /api/incidents/{id}/close
   │   ├─ Resolution: "Password reset completed, MFA enabled, no data accessed"
   │   ├─ Incident status: "closed"
   │   └─ Closed at: 2026-04-10T13:15:00Z

7. METRICS & REPORTING
   ├─→ Login detection: 12:34:00
   ├─→ Alert generated: 12:34:05 (MTTD: 5 seconds)
   ├─→ Response executed: 12:34:35 (MTTR: 35 seconds)
   ├─→ Incident closed: 13:15:00 (Total: 41 minutes)
   ├─→ KPIs updated in dashboard:
   │   ├─ Total incidents: +1
   │   ├─ Closed incidents: +1
   │   ├─ Auto-remediated: +1 (with SOAR assistance)
   │   └─ Average response time: improving
   └─→ Compliance audit log record created

Timeline: Event → Detection → Analysis → Remediation = ~2-5 minutes
```

---

## Security Architecture

### Network Security Layers

```
Level 1: Perimeter (Cloudflare/AWS WAF)
├─ DDoS protection
├─ Rate limiting at edge
├─ Geography-based blocking
└─ Bot detection

Level 2: Reverse Proxy (NGINX)
├─ HTTPS/TLS 1.2+
├─ Rate limiting (API endpoints)
├─ Request validation
├─ Security headers
└─ Connection limits

Level 3: Application (FastAPI)
├─ JWT token validation
├─ RBAC enforcement
├─ Input sanitization
├─ Audit logging
└─ Multi-tenant isolation

Level 4: Pod Network (Kubernetes NetworkPolicy)
├─ Ingress: only from LB
├─ Egress: only to required services
├─ DNS restricted
└─ Inter-pod communication rules

Level 5: Data Security
├─ PostgreSQL encryption at rest
├─ Redis encryption in transit
├─ Secrets in Kubernetes Secrets (→ Vault in prod)
└─ Audit log immutability
```

---

## Monitoring & Observability

### Prometheus Metrics

```
API Level:
- http_requests_total (with labels: endpoint, method, status)
- http_request_duration_seconds (histogram)
- soar_playbook_executions_total
- incident_status_transitions_total

Business Level:
- incidents_open_count
- incidents_closed_count
- playbook_automation_success_rate
- mttd_seconds_summary (quantiles: p50, p99)
- mttr_seconds_summary (quantiles: p50, p99)

Infrastructure Level:
- kubernetes_pod_cpu_usage
- kubernetes_pod_memory_usage
- postgres_connection_pool_usage
- redis_memory_usage
- kafka_consumer_lag
```

### Log Aggregation

```
Sources:
- API application logs (stdout → stdout collector)
- NGINX access logs (combined format)
- PostgreSQL slow query logs
- Redis replication logs (errors only)
- Kubernetes events

Destinations:
- Elasticsearch (indexed)
- Datadog (SaaS)
- Stackdriver (GCP)
- CloudWatch (AWS)
- Splunk (on-prem)
```

---

## Summary: From Attack to Resolution

```
┌──────────────────────────────────────────────────────────────┐
│ ATTACK DETECTION TO RESOLUTION PIPELINE                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ Attack Event          →  Ingestion API  →  Kafka Queue      │
│ (login from China)       (1 second)          (async)         │
│     ↓                         ↓                  ↓            │
│                                                               │
│ Detection Engine      →  Correlation   →  Incident DB       │
│ (anomaly rules)          (timeline)        (fingerprint)     │
│ (2-5 seconds)            (5-10 sec)        (MTTD achieved)  │
│     ↓                         ↓                  ↓            │
│                                                               │
│ WebSocket Stream      →  Frontend       →  Analyst Views    │
│ (real-time alert)        Updates            (Sees incident)  │
│ (1-2 seconds)            (reactive)         (Seconds)        │
│     ↓                         ↓                  ↓            │
│                                                               │
│ AI Analysis          →  Recommendations →  Analyst Reviews  │
│ (risk scoring)         (ranked actions)    (Reads summary)  │
│ (2-3 seconds)          (automated)         (Few minutes)    │
│     ↓                         ↓                  ↓            │
│                                                               │
│ SOAR Orchestration   →  External APIs    →  Remediation    │
│ (intelligent routing)    (identity, net)     (Executed)     │
│ (playbook select)        (messaging)         (1-5 minutes)  │
│     ↓                         ↓                  ↓            │
│                                                               │
│ Incident Management  →  Closure Logger  →  Audit Trail     │
│ (timeline track)        (resolution doc)   (Compliance OK)  │
│ (ongoing)               (permanent)         (Ready to report)│
│                                                               │
│ Total MTTD: 5-10 seconds  │  Total MTTR: 2-5 minutes       │
│ Total Incident Lifecycle: 15-60 minutes                       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

**Result**: Enterprise-grade SOC platform ready for production deployment.
