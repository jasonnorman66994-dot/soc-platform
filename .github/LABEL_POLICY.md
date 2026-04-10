# PR Label Policy

This repository uses PR labels to improve release notes quality and version hinting.

## Required Labels

Each pull request must include:

1. At least one change area label:
- security
- hardening
- ci
- github-actions
- backend
- api
- frontend
- ui
- infra
- ops
- docs

2. At least one release hint label:
- major
- minor
- patch
- fix
- chore

## Why This Exists

- Release Drafter uses labels to group changelog entries.
- Version hint labels provide consistent release intent.
- Label checks keep release notes and semver decisions predictable.

## Suggested Defaults

- Most PRs should include `patch`.
- Use `minor` for new backward-compatible features.
- Use `major` only for breaking changes.
- Add `skip-changelog` only for changes that should not appear in release notes.
