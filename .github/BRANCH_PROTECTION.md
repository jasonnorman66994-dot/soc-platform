# Branch Protection Setup

This document defines recommended repository protection settings for `main`.

## Required Status Checks

Enable "Require status checks to pass before merging" and add these checks:

- `quick-check`
- `label-policy`

If your repository UI shows workflow-prefixed names, use:

- `PR Quick Check / quick-check`
- `PR Label Policy / label-policy`

`verify` remains a post-merge release gate on `main` and should stay enabled in Actions, but it is not a pre-merge PR status check.

## Recommended Main Branch Rules

1. Require a pull request before merging.
2. Require approvals: at least 1.
3. Dismiss stale pull request approvals when new commits are pushed.
4. Require conversation resolution before merging.
5. Require status checks to pass before merging.
6. Require branches to be up to date before merging.
7. Do not allow force pushes.
8. Do not allow deletions.

## Optional Hardening

- Restrict who can push to `main`.
- Require signed commits.
- Require linear history.
- Enable merge queue.

## Validation Procedure

1. Open a test pull request that touches `scripts/quick-check.ps1`.
2. Confirm the PR check `quick-check` runs and passes.
3. Confirm the PR check `label-policy` runs and passes.
4. Merge to `main`.
5. Confirm `verify` runs on `main` and passes.
6. Confirm branch settings block merges when checks fail.
7. Trigger `.github/workflows/release-tag.yml` via manual dispatch and verify release creation.
8. Confirm `.github/workflows/nightly-resilience.yml` is enabled and scheduled.
9. For smoke tests, add `docs` and `patch` labels to the PR so `label-policy` can pass.
