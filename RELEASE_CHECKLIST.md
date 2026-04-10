# Release Checklist

## Security

- [ ] Rotate `JWT_SECRET`, `ADMIN_SESSION_SECRET`, and `INTERNAL_ADMIN_TOKEN` in production.
- [ ] Set `STRICT_SECURITY_MODE=true` after migration checks pass.
- [ ] Confirm no plaintext passwords remain in `users.password`.
- [ ] Confirm Stripe webhook secret is set and endpoint is TLS-protected.

## Infrastructure

- [ ] Copy `.env.example` to `.env` and fill all required values.
- [ ] Run `docker compose up -d --build`.
- [ ] Verify backend health endpoint returns no critical warnings.
- [ ] Verify database migrations/init path succeeded in logs.

## Product Ops

- [ ] Validate admin session create/refresh/revoke flows.
- [ ] Validate funnel metrics endpoint and tenant breakdown endpoint.
- [ ] Validate webhook metrics and replay cleanup endpoint.
- [ ] Run demo-day script and verify timeline/outcome counts.
- [ ] Run `powershell -ExecutionPolicy Bypass -File .\scripts\release-verify.ps1` and confirm all checks pass.
- [ ] CI gate command: `powershell -ExecutionPolicy Bypass -File .\scripts\release-verify-ci.ps1`
- [ ] One-command preflight: `powershell -ExecutionPolicy Bypass -File .\scripts\preflight-release.ps1`
- [ ] Fast local validation: `powershell -ExecutionPolicy Bypass -File .\scripts\quick-check.ps1`
- [ ] Dry-run release cut: `powershell -ExecutionPolicy Bypass -File .\scripts\release-v1-dry-run.ps1 -Version v1.0.0`
- [ ] Review sequence in `RELEASE_OPERATOR_RUNBOOK.md`

## Go-Live

- [ ] Capture KPI baseline (funnel + webhook summary).
- [ ] Freeze release tag and changelog.
- [ ] Run release-tag workflow: `.github/workflows/release-tag.yml` with target version.
- [ ] Run post-release verification: `powershell -ExecutionPolicy Bypass -File .\scripts\post-release-check.ps1`
- [ ] Create rollback snapshot: `powershell -ExecutionPolicy Bypass -File .\scripts\rollback.ps1 -Action checkpoint`
- [ ] Confirm restore path: `powershell -ExecutionPolicy Bypass -File .\scripts\rollback.ps1 -Action rollback`
- [ ] Enable branch protection required checks per `.github/BRANCH_PROTECTION.md`.
- [ ] Configure scheduled monitoring via `.github/workflows/nightly-resilience.yml`.
- [ ] Apply GitHub environment protections per `.github/SECRETS_ENVIRONMENTS.md`.
