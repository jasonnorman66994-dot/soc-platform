# Release Cut Checklist - v2.0.0

## Scope

Enterprise rollout covering:
- Phase 7: SOAR integrations and orchestration
- Phase 8: Incident management workflow
- Phase 9: AI analyst enhancement
- Phase 10: Deployment hardening (K8s + NGINX)

## Pre-Release Validation

- [x] Python compile checks pass for new backend modules
- [x] Backend container rebuild succeeds
- [x] Backend startup healthy (`/health` returns 200)
- [x] Quick checks script passes (`scripts/quick-check.ps1`)
- [x] Markdown lint issues resolved in touched docs
- [x] Kubernetes manifests parse as valid YAML

## Runtime Smoke Test (Executed)

Environment: local Docker Compose via project-scoped command.

- [x] `GET /api/health` -> `ok`
- [x] `GET /api/demo/bootstrap` -> tenant bootstrap available
- [x] `POST /api/auth/login` with demo analyst -> access token issued
- [x] `GET /api/incidents` -> incident list returned
- [x] `GET /api/ai/analyze/{incident_id}` -> risk fields returned
- [x] `POST /api/automate/incident/{incident_id}` -> playbook execution path returns
- [x] `GET /api/soar/executions/{incident_id}` -> history endpoint reachable

## Release Notes Inputs

- [x] Changelog updated for v2.0.0
- [x] README updated with enterprise features and deployment notes
- [x] Deployment guide added
- [x] Architecture and implementation summaries added

## Operational Readiness

- [ ] Populate real integration credentials in deployment secrets
- [ ] Set production domain in ingress/nginx manifests
- [ ] Configure cert-manager issuer email/domain values
- [ ] Verify tenant auth strategy for websocket in production
- [ ] Run security scan on dependencies and container images

## Git/Release Actions

- [ ] Create release branch (optional)
- [ ] Open PR to main (if not committing directly)
- [ ] Tag release: `v2.0.0`
- [ ] Publish GitHub release notes
- [ ] Attach deployment guide and rollout notes

## Rollback Plan

- Revert to last stable tag (v1.3.0)
- Redeploy previous backend and frontend images
- Keep database schema backward-compatible paths only
- Validate health checks and login flow before traffic restore

## Post-Release Verification

- [ ] Health endpoints stable for 15+ minutes
- [ ] Login/ingestion/incident/AI endpoints return expected responses
- [ ] SOAR automation logs are generated and auditable
- [ ] Dashboard websocket feed receives alerts
- [ ] Error rate and latency within baseline
