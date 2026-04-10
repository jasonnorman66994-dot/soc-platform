# Handoff Notes

## What Was Added

- Security posture checks and optional strict security enforcement.
- Password hashing migration-on-login path plus hashed writes on create/signup.
- Admin session lifecycle APIs (create, refresh, revoke).
- Stripe webhook replay fingerprinting + idempotency and metrics endpoints.
- Funnel analytics endpoints (global + tenant-level).
- Demo automation APIs (`/admin/demo/reset`, `/admin/demo/run-showcase`).
- Command Center admin operations panel for sessions and metrics.
- Docker Compose environment parameterization for sensitive/runtime values.

## Environment

- Start from `.env.example` and set production secrets.
- Recommended production settings:
  - `STRICT_SECURITY_MODE=true`
  - `STRIPE_WEBHOOK_TOLERANCE_SECONDS=300`
  - `WEBHOOK_REPLAY_TTL_DAYS=7`

## Demo Day Runbook

1. Start services with fresh build.
2. Run `scripts/demo-day.ps1`.
3. Present timeline + outcomes from showcase response.
4. Show funnel and webhook KPI snapshot from script output.

## Release Validation and Rollback

- Verify release readiness in one command:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\release-verify.ps1`
- CI-friendly pass/fail summary command:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\release-verify-ci.ps1`
- Full preflight chain (checkpoint + verify + demo):
  - `powershell -ExecutionPolicy Bypass -File .\scripts\preflight-release.ps1`
- v1 dry-run sequence:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\release-v1-dry-run.ps1 -Version v1.0.0`
- Post-release confidence check:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\post-release-check.ps1`
- Create rollback snapshot before deployment:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\rollback.ps1 -Action checkpoint`
- Restore latest snapshot if needed:
  - `powershell -ExecutionPolicy Bypass -File .\scripts\rollback.ps1 -Action rollback`
- Operator runbook:
  - `RELEASE_OPERATOR_RUNBOOK.md`

## CI Automation

- GitHub Actions workflow added:
  - `.github/workflows/release-verify.yml`
- On `main` pushes affecting platform code, it builds stack, waits for health, runs `release-verify-ci.ps1`, and tears down.
- GitHub Actions PR quick-check workflow added:
  - `.github/workflows/pr-quick-check.yml`
- On pull requests it runs `scripts/quick-check.ps1` (file presence, PowerShell syntax parse, and `docker compose config`).
- GitHub Actions nightly resilience workflow added:
  - `.github/workflows/nightly-resilience.yml`
- Nightly workflow runs quick checks, release verify, full preflight, and uploads diagnostics artifacts.
- GitHub Actions release-tag workflow added:
  - `.github/workflows/release-tag.yml`
- Manual release-tag workflow creates a version tag and generated GitHub release notes.
- Branch governance playbook added:
  - `.github/BRANCH_PROTECTION.md`
- Secrets and environment hardening guide added:
  - `.github/SECRETS_ENVIRONMENTS.md`

## Risk Notes

- Existing legacy plaintext passwords are migrated only when users successfully log in.
- Ensure admin token distribution process is controlled and auditable.
- Webhook replay store requires Redis durability strategy aligned with retention goals.
