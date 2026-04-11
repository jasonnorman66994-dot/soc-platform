# Changelog

## v1.3.0 (Board Report Export Scheduling)

### Highlights

- Board report export scheduling with admin CRUD endpoints: POST, GET, PATCH, DELETE `/admin/reports/schedules`
- Report schedule database model with frequency (daily/weekly/monthly), time, format, recipients, and enabled flag
- Command Center UI section for managing scheduled report exports with real-time schedule list display

## Unreleased

### Added

- Board report schedules now validate cadence fields and compute `next_run` for daily, weekly, and monthly exports.
- Monthly board report schedules now support `day_of_month` in the admin API and Command Center.
- Board report schedules can now be executed manually through `POST /api/admin/reports/schedules/{id}/run` and the Command Center `Run Now` control.
- Report schedules can now be paused or resumed via `PATCH /api/admin/reports/schedules/{id}` (`enabled` field) and the Command Center `Pause`/`Resume` toggle buttons.
- Background auto-executor: the backend now runs a 1-minute APScheduler job that fires all enabled schedules whose `next_run <= NOW()` automatically.
- New endpoint `GET /api/admin/reports/schedules/due` lists all currently overdue enabled schedules for operational visibility.
- Command Center now supports schedule editing: load a schedule into the form, update via `PATCH /api/admin/reports/schedules/{id}`, or cancel edit.
- New endpoint `POST /api/admin/reports/schedules/run-due` executes all currently due schedules immediately and returns execution summary counts.
- Command Center adds a `Run Due Now` control to trigger due-schedule execution on demand and display summary results.
- New endpoint `GET /api/admin/reports/schedules/summary` returns operational counters for schedule state (`total`, `enabled`, `paused`, `due`).
- Command Center schedule panel now shows live summary counters for total, enabled, paused, and due-now schedules.
- Added modular SOC scaffold directories for ingestion, detection, correlation, workers, frontend dashboard components, and infrastructure layers.
- Added a runnable ingestion service prototype at `backend/ingestion/server.py` with `POST /ingest` and `GET /events`, wired to simple detection rules in `backend/detection/rules.py`.
- Added production SOC core components: Kafka producer (`backend/ingestion/producer.py`), stream worker (`backend/workers/consumer.py`), and SQLAlchemy storage layer (`backend/storage/*`).
- Added production-ready API service at `backend/api/server.py` with event queue ingest and persisted events/alerts query endpoints.
- Added dedicated phase-2 orchestration stack at `infrastructure/docker/docker-compose.yml` (API, worker, Kafka, Zookeeper, PostgreSQL, Redis).

### Changed

### Security
