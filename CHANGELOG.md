# Changelog

## Unreleased

### Added

- Admin session APIs for create, refresh, and revoke operations.
- Funnel analytics API for platform and tenant-level conversion visibility.
- Webhook observability APIs for daily summary and recent event traces.
- Demo automation endpoints for tenant reset and showcase attack sequence.
- Command Center admin operations panel for session and KPI workflows.
- Demo-day script for repeatable presentation setup and KPI capture.
- Board-ready admin report endpoints for KPI JSON and downloadable Markdown summaries.

### Changed

- User password handling now writes hashes on create/signup and migrates plaintext on successful login.
- Health checks now include security posture warnings.
- Docker compose backend environment now supports secret and hardening parameterization.

### Security

- Added webhook replay fingerprint deduplication and retention cleanup control.
- Added strict security mode gate for production startup policy enforcement.
