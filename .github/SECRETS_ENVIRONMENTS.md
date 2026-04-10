# Secrets and Environments Hardening

Use GitHub Environments to control secret access and require reviewer approval before production actions.

## Recommended Environments

- `staging`
- `production`

## Required Repository Secrets

Set these as GitHub secrets (or environment-scoped secrets where possible):

- `JWT_SECRET`
- `ADMIN_SESSION_SECRET`
- `INTERNAL_ADMIN_TOKEN`
- `STRIPE_WEBHOOK_SECRET`
- `DATABASE_URL`
- `REDIS_URL`

## Recommended Environment Variables

These may be managed as non-secret variables:

- `STRIPE_WEBHOOK_TOLERANCE_SECONDS` (default `300`)
- `WEBHOOK_REPLAY_TTL_DAYS` (default `7`)
- `STRICT_SECURITY_MODE` (`true` in production)
- `ENFORCE_HTTPS` (`true` in production)
- `ALLOW_INSECURE_HTTP` (`false` in production)

## Production Environment Protection Rules

1. Required reviewers: at least 1 maintainer.
2. Wait timer: 5 minutes (optional but recommended).
3. Deployment branches: `main` only.
4. Prevent self-review for environment approval.

## Secure Workflow Practices

1. Never print secrets in workflow logs.
2. Pass secrets through environment variables only in steps that need them.
3. Keep `permissions` minimal (`contents: read` unless write is necessary).
4. Use environment-scoped secrets for release/deploy workflows.
5. Rotate production secrets quarterly or after any incident.

## Verification Checklist

1. Confirm no secrets are committed to `.env.example`.
2. Confirm protected `production` environment exists in GitHub settings.
3. Confirm release/deploy workflows reference the correct environment.
4. Confirm branch protection requires CI checks before merge.
