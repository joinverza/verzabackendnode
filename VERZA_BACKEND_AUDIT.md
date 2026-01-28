# Verza Backend Monorepo Audit (Current State)
Last updated: 2026-01-27

## Executive Summary
- The repository is a Turborepo-based Node.js + TypeScript monorepo with three Node services (`main-api`, `identity-gateway`, `identity-orchestrator`) and one Python service (`inference`).
- Core platform foundations are present (config parsing, HTTP middleware, error envelope, logging, Postgres migrations, JWT + API-key auth, crypto utilities).
- `main-api` implements auth, “me”, notifications, credentials storage/shares, fiat-payments (partial), plus functional enterprise surfaces for **consents**, **verifiers**, **identity verifications**, **proofs**, **escrow**, **governance**, **verifications**, **search**, and the **admin surface** (`/admin/bridge`, `/admin/institutions`).
- Identity subsystem now enforces auth on internal endpoints and supports async execution via Redis-backed queue processing, while persisting inference outputs/decisions and validating S3/MinIO media objects when configured.

## Recent Updates (2026-01-27)
- Implemented admin routers in `main-api`:
  - `/admin/bridge/*` via [adminBridge.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/adminBridge.ts)
  - `/admin/institutions/*` via [adminInstitutions.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/adminInstitutions.ts)
  - Mounted in [routes.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routes.ts)
- Identity orchestrator quality fixes and semantics hardening:
  - Redis client typing fixes + `exactOptionalPropertyTypes` fixes in [server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-orchestrator/src/server.ts)
  - Workspace verification: `npm run lint`, `npm run typecheck`, `npm test` passed
- Completed auth + payments + ops hardening in `main-api`:
  - Password reset delivery attempts (SMTP first, then Twilio SMS fallback) in [auth.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/auth.ts)
  - 2FA backup codes are now consumed (one-time use) on successful login in [auth.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/auth.ts) using [auth/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/auth/src/index.ts)
  - Stripe webhook handling + admin reconciliation endpoint in [fiatPayments.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/fiatPayments.ts)
  - Real Redis connectivity check in [main-api/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/server.ts)
  - `/metrics` endpoints (gated by `METRICS_ENABLED=true`) in all Node services:
    - [main-api/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/server.ts)
    - [identity-gateway/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-gateway/src/server.ts)
    - [identity-orchestrator/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-orchestrator/src/server.ts)
  - Fixed Windows-native `bcrypt` binding test failures by switching `main-api` to `bcryptjs`:
    - [main-api/package.json](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/package.json)
    - [auth.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/auth.ts), [me.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/me.ts)

## Next Tasks (Recommended Order)
1. Add integration tests for auth/identity flows and admin surfaces.
2. Generate OpenAPI from code to reduce spec drift (beyond path discovery).
3. Harden fiat payments (Stripe event idempotency, refunds/chargebacks, richer reconciliation).

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
Server wiring (middlewares + health + OpenAPI + Swagger UI + route registration): [main-api/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/server.ts)

#### Health + Docs (Public)
- `GET /health` — returns `{status:"ok"}`
- `GET /health/db` — runs `select 1`
- `GET /health/redis` — connects and `PING`s Redis (or returns `not_configured`)
- `GET /metrics` — Prometheus metrics (only when `METRICS_ENABLED=true`)
- `GET /openapi.json`, `GET /swagger.json` — OpenAPI 3.0.3 JSON (hybrid: hand-authored base + runtime route discovery)
- `GET /docs` — Swagger UI
- `GET /swaggerdocs` — redirects to `/docs`

#### Auth (Public + User)
Implemented in [auth.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/auth.ts):
- `POST /api/v1/auth/signup` — creates user + session, returns access/refresh tokens
- `POST /api/v1/auth/login` — checks password + optional 2FA, creates session, returns tokens
- `POST /api/v1/auth/refresh` — rotates refresh token for matching session hash, returns new tokens
- `POST /api/v1/auth/forgot-password` — stores reset token and attempts delivery (email/SMS) when configured
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

#### Proofs (User)
Implemented in [proofs.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/proofs.ts):
- `POST /api/v1/proofs/generate` — generates (or reuses) a proof envelope for a credential
- `POST /api/v1/proofs/verify` — verifies receipt signature envelope
- `GET /api/v1/proofs/:id` — returns stored proof envelope for the requesting user
Credential shortcut endpoint implemented in [credentials.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/credentials.ts):
- `GET /api/v1/credentials/:credentialId/proof` — returns generated proof envelope for a credential

#### Institution API (API key)
Mounted at `/api/v1/institution/*` with `requireInstitutionApiKey` in [routes.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routes.ts). Implemented in [institution.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/institution.ts):
- `GET /api/v1/institution/me`
- `POST /api/v1/institution/api-keys/rotate`
- `GET /api/v1/institution/consents`
- `GET /api/v1/institution/consents/:consent_id`
- `GET /api/v1/institution/consents/:consent_id/audit`
- `GET /api/v1/institution/consents/:consent_id/credential` — enforces consent active/not-expired; returns field-minimized credential (never returns `encrypted_data`)
- `GET /api/v1/institution/consents/:consent_id/identity`
- `POST /api/v1/institution/identity/attestations` — completes verification as institution (requires active consent; writes audit event)
- `GET /api/v1/institution/identity/verifications`
- `GET /api/v1/institution/identity/verifications/:verification_id`

#### Consents (User)
Implemented in [consents.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/consents.ts):
- `GET /api/v1/consents`
- `POST /api/v1/consents` — validates credential ownership + institution active; validates `expires_at` is future; writes consent audit
- `GET /api/v1/consents/:consentId`
- `POST /api/v1/consents/:consentId/revoke` — idempotent revoke; writes consent audit
- `GET /api/v1/consents/:consentId/audit` — requires user owns consent (prevents audit leakage)

#### Verifiers (User)
Implemented in [verifiers.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/verifiers.ts):
- `POST /api/v1/verifiers` — creates verifier owned by current user
- `GET /api/v1/verifiers` — lists owned verifiers; supports `?q=` search over active verifiers
- `GET /api/v1/verifiers/:id` — owner can view; non-owner can view only if `status=active`
- `PATCH /api/v1/verifiers/:id` — owner-only update (403 on non-owner)

#### Identity Verifications (User + Admin)
Implemented in [identityVerifications.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/identityVerifications.ts):
- `POST /api/v1/identity/verifications/request` — creates a `pending` verification + audit event
- `GET /api/v1/identity/verifications`
- `GET /api/v1/identity/verifications/:id` — user can view own; admin can view any
- `GET /api/v1/identity/verifications/:id/audit` — user can view own; admin can view any
- `POST /api/v1/identity/verifications/:id/status` — user can view own; admin can view any
- `POST /api/v1/identity/verifications/:id/cancel` — user can cancel pending
- `POST /api/v1/identity/verifications/:id/complete` — **admin-only**, only completes `pending`; persists decision fields and writes audit event

#### Escrow (User)
Implemented in [escrow.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/escrow.ts):
- `POST /api/v1/escrow/create`
- `POST /api/v1/escrow/release`
- `POST /api/v1/escrow/dispute`
- `GET /api/v1/escrow/:id/status`

#### Governance (User + Admin)
Implemented in [governance.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/governance.ts):
- `POST /api/v1/governance/propose` — admin-only
- `POST /api/v1/governance/vote`
- `GET /api/v1/governance/proposals`

#### Verifications (User)
Implemented in [verifications.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/verifications.ts):
- `POST /api/v1/verifications/request`
- `POST /api/v1/verifications/complete`
- `GET /api/v1/verifications/:id/status`

#### Search (User)
Implemented in [search.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/search.ts):
- `GET /api/v1/search?q=...` — searches across supported domains

#### Admin Surface (Admin)
Mounted at `/admin/*` in [routes.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routes.ts):
- `GET /admin/bridge/transactions`
- `GET /admin/bridge/transactions/:id`
- `POST /admin/bridge/transactions/:id/status`
- `POST /admin/bridge/transactions/:id/retry`
- `GET /admin/bridge/credential-metadata/:credential_id`
- `POST /admin/bridge/credential-metadata/upsert`
- `GET /admin/institutions`
- `POST /admin/institutions`
- `GET /admin/institutions/:institutionId`
- `POST /admin/institutions/:institutionId/status`
- `GET /admin/institutions/:institutionId/api-keys`
- `POST /admin/institutions/:institutionId/api-keys`
- `POST /admin/institutions/:institutionId/api-keys/:apiKeyId/revoke`
- `GET /admin/institutions/:institutionId/members`
- `POST /admin/institutions/:institutionId/members`
- `POST /admin/institutions/:institutionId/members/:memberId`

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
- `POST /internal/v1/verifications/:id/run` — sync run triggers inference; async enqueues job in Redis and stores idempotency row
- `POST /internal/v1/verifications/:id/idempotency` — checks if key exists
Additional behavior in [identity-orchestrator/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/identity-orchestrator/src/server.ts):
- Internal routes are protected by JWT auth (`requireUser`)
- Async worker consumes Redis queue and processes inference jobs
- Media objects are validated via `HeadObject` when S3/MinIO is configured
- Inference outputs and decisions are persisted (v2 tables/migration)

### apps/inference (Completed Placeholder Endpoints)
Implemented in [inference/app.py](file:///c:/Users/User/Desktop/verzabackendnode/apps/inference/app.py):
- `POST /v1/liveness/extract_best_frame`
- `POST /v1/document/extract_portrait`

## Current Implementations (Incomplete / Stubbed)

### main-api endpoints that exist but are placeholders
- None identified in the previously stubbed set; remaining gaps are primarily scope/completeness and production hardening.

### OpenAPI is hybrid (partially hand-authored)
- `main-api` serves OpenAPI and Swagger UI, but the spec is still partly hand-authored, and route discovery mainly reduces drift on route presence rather than request/response schema completeness.

## What Must Be Added To Make The Project “Complete”
This section is anchored to the required scope described in [NODE_MONOREPO_IMPLEMENTATION_PROMPT.md](file:///c:/Users/User/Desktop/verzabackendnode/NODE_MONOREPO_IMPLEMENTATION_PROMPT.md). The current codebase implements only a subset of that API surface and business logic.

### 1) Main API: implement missing routers/endpoints
High-level missing domains (currently stubbed or absent):
- **Proofs**: implemented.
- **Verifiers**: basic CRUD/search is implemented; remaining scope includes stats, institution/admin controls, and any approval/reputation semantics.
- **Escrow**: implemented.
- **Governance**: implemented.
- **Verifications**: implemented.
- **Identity Verifications**: user/admin/institution flows are implemented; remaining scope includes integration with identity gateway/orchestrator, async processing, and stronger state-machine semantics.
- **Search**: implemented.
- **Admin surface**: implemented (`/admin/bridge`, `/admin/institutions`).

Practical implementation steps:
- `stubs.ts` is no longer mounted in `main-api`; remaining work should follow the same patterns as the implemented routers.
- Back each domain with:
  - Zod request validation
  - Postgres persistence (tables exist for several areas already; others may need schema additions if not present)
  - Auth enforcement (`requireUser`, `requireAdmin`, `requireInstitutionApiKey`) consistent with the prompt’s actor model
  - Consistent error envelope (already implemented in `@verza/http`)

### 2) Main API: finish partial flows
- **Password reset delivery**: implemented (email/SMS delivery attempts) in [auth.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/auth.ts); remaining scope is production hardening (rate limits, templating, deliverability monitoring).
- **2FA backup codes lifecycle**: implemented (one-time consumption on successful login) in [auth.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/auth.ts) + [auth/index.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/auth/src/index.ts).
- **Fiat payments**: implemented Stripe webhook + admin reconcile endpoint in [fiatPayments.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/fiatPayments.ts); remaining scope is broader coverage (refunds/chargebacks, event idempotency, reconciliation depth).
- **OpenAPI/Swagger**: implemented as a hybrid spec (hand-authored base + runtime route discovery); remaining scope is to generate richer schemas from code to reduce drift further.
- **Redis health**: implemented as a real connectivity check in [main-api/server.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/server.ts).
- **Metrics**: implemented behind `METRICS_ENABLED=true` in all Node services.

### 3) Identity subsystem: complete orchestrator semantics
The orchestrator now supports production-critical capabilities:
- **Auth & request validation semantics**: implemented (JWT auth on `/internal/v1/*`).
- **State machine**: implemented at the API/DB-update level via controlled status transitions in route handlers and worker.
- **Async execution**: implemented via Redis queue + worker.
- **Inference outputs**: persisted (v2 outputs/decisions tables).
- **Object storage integration**: implemented via `HeadObject` validation when S3/MinIO is configured.

### 4) Tests
There are workspace scripts for `lint`, `typecheck`, and `test` (see [package.json](file:///c:/Users/User/Desktop/verzabackendnode/package.json)), but critical workflow tests are not present in the code reviewed:
- Unit tests exist for 2FA backup code verification in [twofa.test.ts](file:///c:/Users/User/Desktop/verzabackendnode/packages/auth/src/twofa.test.ts).
- Minimal auth route test exists for forgot-password behavior in [auth.test.ts](file:///c:/Users/User/Desktop/verzabackendnode/apps/main-api/src/v1/routers/auth.test.ts).
- Remaining gaps:
  - Add unit tests for crypto/auth primitives (JWT verification, DID signature verification).
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
- **Password storage**: bcrypt hashing (implemented via `bcryptjs`) for signup/login/change-password/reset-password
- **Session handling**: refresh token stored as SHA-256 hash; logout revokes session
- **JWT verification**: HMAC SHA-256 with timing-safe signature comparison
- **Institution access**: API keys hashed and checked against DB + institution status checks
- **DID request verification (partial)**: used by fiat payment initiation endpoint
- **Baseline security headers (main-api)**: `x-content-type-options`, `x-frame-options`, `referrer-policy`, `permissions-policy`, conditional HSTS (behind HTTPS), and `x-powered-by` disabled
- **Data minimization for institution reads**: institution consent-credential endpoint never returns encrypted credential payloads and is gated on active consent
- **Privileged completion of identity decisions**: user cannot self-complete identity verification; completion is admin-only and attestation is institution-only with consent

### High-risk gaps (should be addressed before production)
- **TLS termination + edge headers are assumed external**: the apps do not enforce HTTPS themselves (expected at load balancer/ingress).
- **Fiat payments need deeper payment-event coverage**: refund/chargeback paths, stronger event idempotency, and reconciliation completeness should be added.
- **OpenAPI generation is not fully code-driven**: drift risk is reduced but not eliminated (spec schema completeness still depends on manual work).

### Compliance-readiness notes (what exists vs what auditors usually expect)
- **SOC2-style controls**: logging exists, but you likely need audit logging for admin actions, access events, and key lifecycle events; plus retention policies and access controls.
- **OWASP API Security**: authentication exists for main-api user/admin flows; however, identity internal surfaces need protection, and per-route rate limiting and abuse prevention should be tightened.
- **Secrets management**: secrets are environment-driven (good baseline) but there is no explicit rotation policy or secret scanning in repo scope.

## Database Coverage (What’s Already Modeled)
- Core user/session/auth tables exist in [0002_app_core.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/main/0002_app_core.sql)
- Institutions, API keys, consents, and audit events exist in [0005_institutions_consents.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/main/0005_institutions_consents.sql)
- Identity verification tables exist in [0003_identity_verifications.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/main/0003_identity_verifications.sql)
- Enterprise domains (verifiers/proofs/escrow/governance) exist in [0007_enterprise_domains.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/main/0007_enterprise_domains.sql)
- Identity platform (v2) minimal schema exists in [0001_identity_platform.sql](file:///c:/Users/User/Desktop/verzabackendnode/packages/db/migrations/identity/0001_identity_platform.sql)

## How To Run (Current State)
- Top-level scripts are defined in [package.json](file:///c:/Users/User/Desktop/verzabackendnode/package.json): `lint`, `typecheck`, `test`, `build`, and DB migrate commands.
- Local stack can be started via [docker-compose.yml](file:///c:/Users/User/Desktop/verzabackendnode/docker-compose.yml) (Postgres + identity Postgres + Redis + MinIO + inference + identity services + main-api).
