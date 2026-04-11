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

### Changed

### Security
