# Verza Backend Monorepo Audit (Current State)
Last updated: 2026-01-24

## Executive Summary
- The repository is a Turborepo-based Node.js + TypeScript monorepo with three Node services (`main-api`, `identity-gateway`, `identity-orchestrator`) and one Python service (`inference`).
- Core platform foundations are present (config parsing, HTTP middleware, error envelope, logging, Postgres migrations, JWT + API-key auth, crypto utilities).
- `main-api` implements auth, “me”, notifications, credentials storage/shares, and partial fiat-payments flows; many required product endpoints are currently stubbed.
- Identity subsystem is wired end-to-end at a minimal level (gateway proxy + S3 presign + orchestrator persistence + inference calls), but is missing auth semantics, state-machine completeness, and real async execution.

## Repo Layout (What Exists)
- `apps/main-api/` — Verza API (Express). Entry: [index.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/index.ts), server: [server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/server.ts)
- `apps/identity-gateway/` — Edge API (Express) proxy + S3 presign. Entry: [index.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-gateway/src/index.ts), server: [server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-gateway/src/server.ts)
- `apps/identity-orchestrator/` — Internal API + inference calls (Express). Entry: [index.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-orchestrator/src/index.ts), server: [server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-orchestrator/src/server.ts)
- `apps/inference/` — Python FastAPI placeholder for inference endpoints: [app.py](file:///c:/Users/User/Desktop/verzabackendnode/apps/inference/app.py)
- `packages/*` — Shared libraries:
  - Config/env parsing: [config/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/config/src/index.ts)
  - HTTP middleware + error envelope: [http/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/http/src/index.ts)
  - Auth (JWT, RBAC, institution API keys, TOTP): [auth/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/auth/src/index.ts)
  - Crypto (HKDF + AES-GCM, receipt signing, DID-signed request verify): [crypto/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/crypto/src/index.ts)
  - DB pool + migration runner: [db/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/src/index.ts), CLI: [db/cli.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/src/cli.ts)
  - Logging (pino): [observability/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/observability/src/index.ts)
  - Shared types (partial): [types/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/types/src/index.ts)

## Current Implementations (Completed)

### Shared Platform Packages
- **Config parsing (Zod)**: service configs are validated and normalized in [config/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/config/src/index.ts).
- **HTTP baseline middleware**:
  - Request ID propagation (`x-request-id`)
  - Structured HTTP logs via `pino-http`
  - CORS with allowlist support
  - Basic rate limit (120 req/min, bypasses `/health*` and `/healthz`)
  - JSON body limit (1mb) + raw body capture (for signature verification)
  - Unified error envelope and 404 handler  
  Implemented in [http/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/http/src/index.ts).
- **Auth & RBAC**:
  - HS256 JWT access tokens + verification, `requireUser`, `requireAdmin`
  - Institution API key validation backed by Postgres (`institution_api_keys` + `institutions`)
  - TOTP (RFC6238-like) verification + backup codes verification  
  Implemented in [auth/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/auth/src/index.ts).
- **Crypto primitives**:
  - AES-256-GCM encryption for JSON blobs; per-ciphertext HKDF-derived key (salted)
  - Canonical JSON stable stringify
  - Ed25519 receipt signing (KID derived from pubkey hash)
  - DID-signed request verification (Ed25519; supports `did:jwk:` and `did:key:z...`)  
  Implemented in [crypto/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/crypto/src/index.ts).
- **Database**:
  - Postgres pool helper
  - Migration runner using `schema_migrations` bookkeeping
  - Migrations exist for both `main` and `identity` databases  
  Implemented in [db/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/src/index.ts).

### apps/main-api (Implemented Routes)
Server wiring (middlewares + health + docs placeholders + route registration): [main-api/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/server.ts)

#### Health + Docs (Public)
- `GET /health` — returns `{status:"ok"}`
- `GET /health/db` — runs `select 1`
- `GET /health/redis` — placeholder returns `{status:"ok"}`
- `GET /openapi.json`, `GET /swagger.json`, `GET /openapi.yaml`, `GET /swagger.yaml` — placeholder empty specs

#### Auth (Public + User)
Implemented in [auth.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/auth.ts):
- `POST /api/v1/auth/signup` — creates user + session, returns access/refresh tokens
- `POST /api/v1/auth/login` — checks password + optional 2FA, creates session, returns tokens
- `POST /api/v1/auth/refresh` — rotates refresh token for matching session hash, returns new tokens
- `POST /api/v1/auth/forgot-password` — stores reset token (does not deliver it)
- `POST /api/v1/auth/reset-password` — validates token hash and updates password
- `POST /api/v1/auth/logout` — revokes current session (requires JWT)

#### “Me” (User)
Implemented in [me.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/me.ts):
- `GET /api/v1/me` — returns profile fields
- `PATCH /api/v1/me` — updates profile fields
- `POST /api/v1/me/change-password`
- `GET /api/v1/me/sessions`
- `POST /api/v1/me/sessions/revoke`
- `POST /api/v1/me/2fa/setup` — sets secret + returns secret/backup codes
- `POST /api/v1/me/2fa/verify` — enables 2FA and returns backup codes
- `POST /api/v1/me/2fa/disable`

#### Notifications (User)
Implemented in [notifications.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/notifications.ts):
- `GET /api/v1/notifications`
- `POST /api/v1/notifications/read-all`
- `POST /api/v1/notifications/:id/read`
- `POST /api/v1/notifications/seed` — gated from production

#### Credentials (User) + Public Shares
Implemented in [credentials.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/credentials.ts):
- `POST /api/v1/credentials/store` — encrypts `data` with AES-GCM and stores
- `GET /api/v1/credentials` — list credentials (non-decrypted)
- `GET /api/v1/credentials/:credentialId` — decrypts and returns `data`
- `PATCH /api/v1/credentials/:credentialId` — updates status/notes
- `GET /api/v1/credentials/:credentialId/shares` — list shares
- `POST /api/v1/credentials/share` — create share token
- `POST /api/v1/credentials/:credentialId/shares/:shareId/revoke`
- `GET /api/v1/shares/:token` — public read of shared credential data (decrypts and returns)

#### Fiat Payments (Partial)
Implemented in [fiatPayments.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/fiatPayments.ts):
- `POST /api/v1/fiat/payments/initiate` — requires DID-signed request headers; stores session
- `GET /api/v1/fiat/payments/:id/status`
- `GET /api/v1/fiat/payments/:id/receipt` — returns Ed25519-signed receipt payload

#### Institution API (API key)
Mounted at `/api/v1/institution/*` with `requireInstitutionApiKey` in [routes.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routes.ts). Implemented in [institution.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/institution.ts):
- `GET /api/v1/institution/me`
- `POST /api/v1/institution/api-keys/rotate`
- `GET /api/v1/institution/consents`
- `GET /api/v1/institution/consents/:consent_id`
- `GET /api/v1/institution/consents/:consent_id/audit`
- `GET /api/v1/institution/consents/:consent_id/credential`
- `GET /api/v1/institution/consents/:consent_id/identity`
- `GET /api/v1/institution/identity/verifications`
- `GET /api/v1/institution/identity/verifications/:verification_id`

### apps/identity-gateway (Completed Minimal Behavior)
Implemented in [identity-gateway/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-gateway/src/server.ts):
- `GET /healthz`
- `POST /v1/sessions` — proxies to orchestrator `/internal/v1/sessions`
- `POST /v1/media/presign` — S3-compatible presigned PUT URL (AWS SDK v3)
- `POST /v1/verifications` — proxies to orchestrator `/internal/v1/verifications`
- `ALL /v1/verifications/:id/*` — dynamic proxy to orchestrator
- Passes through `x-request-id`, `traceparent`, and `authorization` headers

### apps/identity-orchestrator (Completed Minimal Internal API)
Implemented in [identity-orchestrator/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-orchestrator/src/server.ts):
- `GET /healthz`
- `POST /internal/v1/sessions` — inserts into `identity_sessions`
- `POST /internal/v1/verifications` — inserts into `identity_verifications_v2`
- `GET /internal/v1/verifications/:id`
- `GET /internal/v1/verifications/:id/audit`
- `POST /internal/v1/verifications/:id/media` — stores media metadata + audit event
- `POST /internal/v1/verifications/:id/run` — sync run triggers inference; async returns `202` and stores idempotency row
- `POST /internal/v1/verifications/:id/idempotency` — checks if key exists

### apps/inference (Completed Placeholder Endpoints)
Implemented in [inference/app.py](file:///c:/Users/User/Desktop/verzabackendnode/apps/inference/app.py):
- `POST /v1/liveness/extract_best_frame`
- `POST /v1/document/extract_portrait`

## Current Implementations (Incomplete / Stubbed)

### main-api route groups are stubbed
The following route groups currently route to a stub handler returning `{status:"ok"}` via [stubs.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/stubs.ts), as wired in [routes.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routes.ts):
- `/api/v1/proofs/*` and `/api/v1/proofs`
- `/api/v1/verifiers`
- `/api/v1/escrow`
- `/api/v1/governance`
- `/api/v1/verifications`
- `/api/v1/identity/verifications`
- `/api/v1/search`
- `/admin/bridge`
- `/admin/institutions`

### main-api endpoints that exist but are placeholders
- `GET /api/v1/credentials/:credentialId/proof` — returns `{status:"ok"}` (no proof generation)
- Docs endpoints (`/openapi*`, `/swagger*`) return empty specs in [main-api/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/server.ts)
- `POST /api/v1/fiat/payments/reconcile` — returns `{status:"ok"}` (no Stripe reconciliation logic)
- `POST /api/v1/institution/identity/attestations` — returns `{status:"ok"}` (no persistence / validation)
- `GET /health/redis` — always ok (no Redis check)

### identity-orchestrator “async run” is not implemented
- `POST /internal/v1/verifications/:id/run?async=true` returns `202` and stores idempotency, but no worker/queue processes jobs (no Redis queue usage despite `REDIS_URL` config).

### “metrics” is configured but not implemented
`docker-compose.yml` sets `METRICS_ENABLED`, but none of the Node services expose `/metrics`.

## What Must Be Added To Make The Project “Complete”
This section is anchored to the required scope described in [NODE_MONOREPO_IMPLEMENTATION_PROMPT.md](file:///c:/Users/User/Desktop/verzabackendnode/NODE_MONOREPO_IMPLEMENTATION_PROMPT.md). The current codebase implements only a subset of that API surface and business logic.

### 1) Main API: implement missing routers/endpoints
High-level missing domains (currently stubbed or absent):
- **Proofs**: real proof generation and verification workflows (replaces `/api/v1/proofs*` stubs).
- **Verifiers**: CRUD/search, stats, and any role-based restrictions.
- **Escrow**: create/release/dispute/status with correct state transitions.
- **Governance**: proposals + voting + listing, admin controls.
- **Verifications & Identity Verifications**: request/complete/status, audit trail, institutional attestations, listing/getting.
- **Search**: implement whatever search behavior is required (likely credentials/verifiers/identity records).
- **Admin surface**: `/admin/bridge`, `/admin/institutions` (institution management, API keys, members).

Practical implementation steps:
- Replace [stubs.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/stubs.ts) usage with real routers per domain.
- Back each domain with:
  - Zod request validation
  - Postgres persistence (tables exist for several areas already; others may need schema additions if not present)
  - Auth enforcement (`requireUser`, `requireAdmin`, `requireInstitutionApiKey`) consistent with the prompt’s actor model
  - Consistent error envelope (already implemented in `@verza/http`)

### 2) Main API: finish partial flows
- **Password reset delivery**: `forgot-password` currently stores a token hash but never delivers a reset link/token to a user (email/SMS integration missing).
- **2FA backup codes lifecycle**: backup codes are checked but not consumed/invalidated when used.
- **Credential proofs**: implement `GET /api/v1/credentials/:credentialId/proof` and the `/api/v1/proofs*` domain.
- **Fiat payments**: Stripe integration, reconciliation, and webhook/polling as required by your spec.
- **OpenAPI/Swagger**: generate/serve real specs instead of placeholders.
- **Redis health**: implement actual Redis connectivity checks if Redis is a real dependency.

### 3) Identity subsystem: complete orchestrator semantics
The orchestrator currently persists a verification record, logs media uploads, and calls inference endpoints, but is missing key production capabilities:
- **Auth & request validation semantics**: orchestrator internal endpoints currently have no auth; gateway just passes through headers but nothing enforces them.
- **State machine**: statuses exist as strings; there’s no enforced transition model, failure states, retries, or decision artifacts.
- **Async execution**: `?async=true` needs a real job queue (Redis) plus a worker process to run inference, update status, and append audit events idempotently.
- **Inference outputs**: inference responses are not stored in DB; you likely need persisted “signals/scores/reasons” equivalents for identity decisions.
- **Object storage integration**: orchestrator currently stores S3 keys only; it does not fetch or validate object presence/metadata.

### 4) Tests
There are workspace scripts for `lint`, `typecheck`, and `test` (see [package.json](file:///c:/Users/User/Desktop/verzabackendnode/package.json)), but critical workflow tests are not present in the code reviewed:
- Add unit tests for crypto/auth primitives (JWT verification, TOTP, DID signature verification).
- Add integration tests for auth + session lifecycle, credentials encryption roundtrip, and institution API-key enforcement.
- Add integration tests for identity gateway/orchestrator happy paths (session -> verification -> media -> run).

## Security & Compliance Assessment (Current vs Needed)

### Implemented security controls (present today)
- **Centralized error envelope** with request IDs: [http/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/http/src/index.ts)
- **Request correlation** (`x-request-id`) and structured logs (pino/pino-http)
- **Input validation**: Zod is consistently used in route handlers
- **Rate limiting**: global request rate limit middleware (coarse)
- **CORS allowlist**: configurable allowlist in `packages/http`
- **Credential data at rest**: AES-GCM encryption via HKDF-derived keys for stored JSON payloads (credentials)
- **Password storage**: bcrypt hashing (signup/login/change-password/reset-password)
- **Session handling**: refresh token stored as SHA-256 hash; logout revokes session
- **JWT verification**: HMAC SHA-256 with timing-safe signature comparison
- **Institution access**: API keys hashed and checked against DB + institution status checks
- **DID request verification (partial)**: used by fiat payment initiation endpoint

### High-risk gaps (should be addressed before production)
- **Orchestrator internal endpoints lack authentication/authorization** (gateway passthrough does not enforce anything).
- **Password reset flow has no delivery channel** (tokens can be created but users cannot complete flow in practice).
- **Backup codes are not consumed** when used; a stolen code remains reusable until rotated/reset.
- **No standard security headers** (e.g., `helmet`) and no explicit TLS termination guidance inside the apps (assumed external).
- **Docs/spec endpoints are placeholders**, increasing mismatch risk between clients and server behavior.
- **Async identity run is a stub**: idempotency table exists but no worker executes queued jobs.

### Compliance-readiness notes (what exists vs what auditors usually expect)
- **SOC2-style controls**: logging exists, but you likely need audit logging for admin actions, access events, and key lifecycle events; plus retention policies and access controls.
- **OWASP API Security**: authentication exists for main-api user/admin flows; however, identity internal surfaces need protection, and per-route rate limiting and abuse prevention should be tightened.
- **Secrets management**: secrets are environment-driven (good baseline) but there is no explicit rotation policy or secret scanning in repo scope.

## Database Coverage (What’s Already Modeled)
- Core user/session/auth tables exist in [0002_app_core.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/main/0002_app_core.sql)
- Institutions, API keys, consents, and audit events exist in [0005_institutions_consents.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/main/0005_institutions_consents.sql)
- Identity verification tables exist in [0003_identity_verifications.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/main/0003_identity_verifications.sql)
- Identity platform (v2) minimal schema exists in [0001_identity_platform.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/identity/0001_identity_platform.sql)

## How To Run (Current State)
- Top-level scripts are defined in [package.json](file:///c:/Users/User/Desktop/verzabackendnode/package.json): `lint`, `typecheck`, `test`, `build`, and DB migrate commands.
- Local stack can be started via [docker-compose.yml](file:///c:/Users/User/Desktop/verzabackendnode/docker-compose.yml) (Postgres + identity Postgres + Redis + MinIO + inference + identity services + main-api).
