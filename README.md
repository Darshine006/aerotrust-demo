# AeroTrust

**AeroTrust is a Cloudflare Worker that evaluates real GitHub pull-request webhook events using contribution-source and changed-file risk signals, then writes an auditable decision to Cloudflare D1.**

This repository contains the live webhook path. There is no simulation endpoint in this version.

## What it does

1. Receives GitHub `pull_request` webhook deliveries (`opened`, `reopened`, `synchronize`, `ready_for_review`).
2. Verifies the raw request body with GitHub's `X-Hub-Signature-256` HMAC-SHA256 signature before trusting the payload.
3. Fetches the actual changed-file list from the GitHub Pull Requests API.
4. Evaluates the contribution against explicit policy rules:
   - **BLOCK** — an external fork changes GitHub Actions workflows or reusable/local actions.
   - **REVIEW** — an external fork changes deployment, infrastructure, Kubernetes, Helm, or Docker configuration; also fail-closed when changed-file evidence cannot be retrieved.
   - **ALLOW** — no configured high-risk path is detected. This is not an automatic merge or deployment approval.
5. Persists the decision, evidence paths, event metadata, and GitHub delivery ID in D1. The unique delivery ID makes webhook retries idempotent.
6. Optionally posts the policy result as a comment on the real pull request when `GITHUB_TOKEN` is configured.

## Zero Trust controls

- **Verify explicitly:** webhook authenticity is checked with HMAC-SHA256; dashboard and audit API requests require a valid Cloudflare Access JWT.
- **Least privilege:** the webhook endpoint is public only because GitHub must reach it, and it accepts only correctly signed requests. Dashboard and audit endpoints are protected separately.
- **Fail closed:** missing Access configuration, invalid JWTs, missing file evidence, and GitHub API errors do not produce an ALLOW decision.
- **Minimize trust:** external contributions are evaluated from their source repository and actual changed paths; the Worker never merges a PR or grants deployment credentials.
- **Auditability:** every processed delivery is stored in D1 with its delivery ID and decision.

## Required Cloudflare configuration

### 1. Preserve the existing D1 database

In `wrangler.toml`, replace `REPLACE_WITH_YOUR_EXISTING_D1_DATABASE_ID` with the ID of the already-existing `aerotrust-db`. Do not create a second database if the current Worker already uses one.

### 2. Configure Worker secrets

```bash
npx wrangler secret put GITHUB_WEBHOOK_SECRET
npx wrangler secret put ACCESS_TEAM_DOMAIN
npx wrangler secret put ACCESS_AUD
```

`ACCESS_TEAM_DOMAIN` is the team domain only, for example `example.cloudflareaccess.com`.
`ACCESS_AUD` is the Audience (AUD) tag shown in the Cloudflare Access application's overview.

For real PR comments, also configure a fine-grained GitHub token with **Pull requests: Read** and **Issues: Read and write** for this repository:

```bash
npx wrangler secret put GITHUB_TOKEN
```

The token is optional for public-repository file retrieval. Without it, AeroTrust still evaluates and logs real events, but it cannot post a PR comment.

### 3. Apply the D1 migration

The existing `0001_init.sql` schema is retained. Apply the additive migration that adds webhook delivery IDs and indexes:

```bash
npx wrangler d1 migrations apply aerotrust-db --remote
```

Do this against the existing database before enabling the new webhook code.

### 4. Create the Cloudflare Access application

In Cloudflare Zero Trust:

1. Go to **Access → Applications → Add an application → Self-hosted**.
2. Protect the exact Worker hostname used for the dashboard (for example `aerotrust.iamdarshine.workers.dev`) with an allow policy for your own email or approved research team identities.
3. Copy the application's **Audience (AUD) tag** into `ACCESS_AUD`.
4. Set `ACCESS_TEAM_DOMAIN` to your Zero Trust team domain.
5. Keep `/webhook/github` reachable by GitHub. The Worker validates GitHub HMAC itself; do not put an interactive Access login challenge in front of this webhook path. If the Access application is configured with path exclusions, exclude only `/webhook/github` and keep `/` and `/api/*` protected.

The Worker independently verifies the `CF-Access-Jwt-Assertion` signature, issuer, audience, and expiry for dashboard/API requests. If the Access values are missing or invalid, those routes deny access.

### 5. Deploy

```bash
npm install
npx wrangler deploy
```

If a custom route or Worker hostname is already in use, retain it. Do not change or delete the existing D1 database, webhook secret, or Worker service while deploying.

## GitHub webhook configuration

In `Darshine006/aerotrust-demo` → **Settings → Webhooks**:

- Payload URL: `https://YOUR-WORKER-HOSTNAME/webhook/github`
- Content type: `application/json`
- Secret: exactly the same value configured as `GITHUB_WEBHOOK_SECRET`
- Events: **Pull requests**

The Worker supports `opened`, `reopened`, `synchronize`, and `ready_for_review`. GitHub retries with the same delivery ID are not double-counted.

## Endpoints

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/health` | Public | Non-sensitive service health |
| POST | `/webhook/github` | Public + GitHub HMAC | Real GitHub webhook receiver |
| GET | `/` | Cloudflare Access JWT | Protected audit dashboard |
| GET | `/api/decisions` | Cloudflare Access JWT | Protected audit records |

## Demo flow for a research review

1. Open a real pull request in this repository from a separate fork or branch.
2. Add or modify an ordinary source file: expect **ALLOW** for an external fork.
3. Open another PR from a fork that changes a file under `.github/workflows/`: expect **BLOCK**.
4. Open another PR from a fork that changes `terraform/main.tf` or `kubernetes/deployment.yaml`: expect **REVIEW**.
5. Show the actual GitHub webhook delivery response and the matching D1 audit row in the Access-protected dashboard.

These are real GitHub pull requests and webhook deliveries, not calls to a demo/simulation endpoint. Use a test fork or disposable branches; do not merge risky test changes.

## Scope and limitations

AeroTrust is a research prototype for contribution-risk evaluation and auditability. It does not replace GitHub branch protection, required reviews, CI security hardening, secret isolation, or deployment authorization. An ALLOW result is a policy classification only. Production use would need stronger policy configuration, tests, rate limiting, alerting, and integration with required GitHub checks or deployment gates.
