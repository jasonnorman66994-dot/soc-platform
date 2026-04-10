# Demo Script (High-Impact, 8-10 Minutes)

## Goal
Show that Nexus SOC detects, correlates, explains, and responds to a realistic attack sequence in minutes.

## Setup (Before Call)
- Open product site: `http://localhost`
- Open command center: `/command-center`
- Ensure demo tenant bootstrap endpoint responds

## Script

### 1. Frame the Problem (1 minute)
"Security teams do not need more alerts; they need fast, accountable response."

### 2. Show Multi-Tenant Foundation (1 minute)
- Point out tenant-aware auth and role context in command center.
- Mention API-key ingestion isolation by tenant.

### 3. Launch Realistic Attack Simulation (2 minutes)
- Trigger `POST /demo/simulate-attack` from UI.
- Explain attack chain:
  - phishing email delivered
  - malicious link clicked
  - UK -> US login anomaly
  - sensitive file download

### 4. Show Detection + Correlation (2 minutes)
- Highlight generated alerts and severity progression.
- Open incidents list and show correlated storyline.

### 5. Show AI Analyst + Response (2 minutes)
- Open AI incident analysis with summary and next steps.
- Trigger a response action (`block-ip`) and show status update.

### 6. Show Executive Outcomes (1 minute)
- Read KPI widgets: total incidents, MTTD, MTTR trend movement.
- Connect to board-level reporting and security ROI.

## Close (30 sec)
"In one platform, we turned telemetry into action and executive clarity. That's what we deploy as SaaS for modern security teams."
