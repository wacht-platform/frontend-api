<h1 align="center">
  <a href="https://wacht.dev" style="text-decoration:none;">Wacht Frontend API</a>
</h1>

<p align="center">
  <strong>The public runtime API that powers Wacht-embedded applications.</strong>
</p>

<p align="center">
  <a href="https://github.com/wacht-platform/frontend-api/blob/main/LICENSE.md">
    <img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" />
  </a>
  <img alt="Status" src="https://img.shields.io/badge/status-public%20beta-blue?style=flat-square" />
  <img alt="Built with Go" src="https://img.shields.io/badge/built%20with-go-00ADD8?style=flat-square" />
</p>

<p align="center">
  <a href="https://wacht.dev">Website</a> ·
  <a href="https://wacht.dev/docs">Docs</a> ·
  <a href="https://github.com/wacht-platform/frontend-api/issues">Issues</a>
</p>

---

## Overview

Wacht Frontend API is the public-facing runtime that browsers and the
[Wacht React SDK](https://github.com/wacht-platform/react-sdk) talk to. It handles every
in-app interaction an end-user has with a Wacht-built product — sign-in, sessions, profile,
B2B switching, agent invocations, consent, notifications, and more.

Behavior is driven by per-deployment configuration authored in the Wacht console, so a single
Frontend API instance serves many tenants with their own policies, identity providers,
branding, and feature flags.

If you are looking for the operator/control-plane surface (deployment configuration, billing
operations, agent orchestration internals), see
[`platform-api`](https://github.com/wacht-platform/platform-api).

## What It Serves

The Frontend API is structured around the surfaces an end-user-facing application needs:

- **Authentication.** Sign-up, sign-in, sessions, social logins, OAuth2, MFA/TOTP, password
  reset, and email verification. JWT issuance with rotating session tokens.
- **User.** Profile, preferences, attached identities, devices, and personal activity.
- **Sessions.** Active session listing, revocation, and impersonation flows.
- **Organizations and workspaces.** Membership, invitations, switching, and per-tenant role
  and permission resolution.
- **API auth apps.** End-user-managed API keys and OAuth client credentials.
- **OAuth consent.** Authorization-code consent screens for third-party clients integrating
  with a deployment.
- **External connections.** End-user OAuth connections to external providers (Google, Slack,
  etc.) used by AI agents and integrations.
- **AI / agents.** Runtime endpoints for invoking agents, streaming responses, and managing
  conversational state from the user's session.
- **Notifications.** In-app and webhook-driven user notifications.
- **Webhook apps.** Customer-managed webhook subscriptions.
- **SCIM.** SCIM 2.0 endpoints for enterprise directory provisioning.
- **Waitlist.** Public waitlist capture for gated deployments.

## Architecture

Frontend API is the customer-plane counterpart to the rest of the Wacht stack:

- **`platform-api`** — control plane, operator surface, agent execution engine.
- **`frontend-api`** (this repository) — public runtime serving deployment end-users.
- **`react-sdk`** — official client libraries that embed the Frontend API into web apps.

## Tech Stack

- Go 1.23 with [Fiber v2](https://gofiber.io/)
- PostgreSQL via GORM
- Redis for sessions and caching
- JWT via [`lestrrat-go/jwx`](https://github.com/lestrrat-go/jwx)
- Argon2 password hashing
- AWS SDK for cloud-managed resources

## Quickstart

```bash
git clone https://github.com/wacht-platform/frontend-api.git
cd frontend-api
go mod download
```

Create a `.env`:

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=wacht_db

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h

# OAuth2
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Application
PORT=3000
ENVIRONMENT=development
```

Run it:

```bash
# Development
go run main.go

# Production
go build -o wacht-frontend-api
./wacht-frontend-api
```

The API listens on `http://localhost:3000`.

## Testing

```bash
go test ./...
go test -cover ./...
go test ./handler -v
```

## Status

Frontend API is in **public beta**. The HTTP surface and data model are stabilizing; breaking
changes are documented in the changelog.

## Contributing

We're not accepting pull requests yet — the contribution process isn't set up. Forks,
self-hosting, and any other use the AGPL-3.0 allows are welcome. Self-hosting documentation
is still in progress.

## Support

- Product and integration docs: [wacht.dev/docs](https://wacht.dev/docs).
- Direct assistance: [engineering@intellinesia.com](mailto:engineering@intellinesia.com).

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).
See [LICENSE.md](./LICENSE.md) for the full text.
