# Release Operator Runbook

This runbook describes the sequence from merge-ready code to published GitHub release.

## Step 1: Verify Merge Gate

Run fast checks locally:

- `powershell -ExecutionPolicy Bypass -File .\scripts\quick-check.ps1`

Confirm pull request checks in GitHub:

- `PR Quick Check / quick-check`

## Step 2: Validate Release Readiness

Run full preflight:

- `powershell -ExecutionPolicy Bypass -File .\scripts\preflight-release.ps1`

Expected outcomes:

- rollback checkpoint created
- release verify gate passes
- demo-day scenario passes

## Step 3: Optional Local Dry-Run for Target Version

Simulate release cut for target version:

- `powershell -ExecutionPolicy Bypass -File .\scripts\release-v1-dry-run.ps1 -Version v1.0.0`

## Step 4: Enforce Governance

Confirm these are enabled for `main`:

- Required checks: `quick-check`, `verify`
- Required pull request reviews
- Conversation resolution required
- Force pushes disabled

Reference:

- `.github/BRANCH_PROTECTION.md`

## Step 5: Cut Release Tag

Run manual GitHub workflow:

- `.github/workflows/release-tag.yml`

Inputs:

- `version`: `v1.0.0` (or target version)
- `prerelease`: `false` for stable releases

Expected outcomes:

- git tag created and pushed
- GitHub release published with generated notes

## Step 6: Post-Release Confidence

Verify `main` release workflow completed:

- `Release Verify / verify`

Run post-release local verification:

- `powershell -ExecutionPolicy Bypass -File .\scripts\post-release-check.ps1`

Then check nightly resilience status and artifacts:

- `.github/workflows/nightly-resilience.yml`

## Incident Rollback Procedure

1. Restore most recent snapshot with `powershell -ExecutionPolicy Bypass -File .\scripts\rollback.ps1 -Action rollback`.

1. Re-run release verifier with `powershell -ExecutionPolicy Bypass -File .\scripts\release-verify-ci.ps1`.

1. Capture incident notes and update changelog.

## SOC Agent Tuning Rollback

If distributed telemetry volume spikes or ingest retries become noisy after release, roll agent tuning back to defaults:

1. Set these environment values where agents run:
	`SOC_AGENT_BATCH_SIZE=100`, `SOC_AGENT_MAX_RETRIES=2`, `SOC_AGENT_RETRY_BASE_DELAY=1.0`, `SOC_AGENT_RETRY_MAX_DELAY=8.0`.

1. Restart agent processes.

1. Confirm stabilization by checking reduced retry warnings and expected ingest throughput.
