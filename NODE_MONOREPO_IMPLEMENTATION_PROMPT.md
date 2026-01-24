# Verza Node.js Monorepo Implementation Prompt (Enterprise-Grade, Self-Contained)

You are a senior engineer responsible for building the Verza backend as a **professional Node.js + TypeScript monorepo**.

This prompt is self-contained: it includes the required API shapes, auth wire formats, and Postgres schema needed to implement the backend in a new repository without relying on the current codebase.

## 1) Scope and Non-Negotiables

- Implement the full HTTP API surface listed in Section 7 with correct auth requirements and JSON shapes.
- Implement auth and DID flows exactly as specified in Section 8.1 and Appendix C.
- Use Postgres schema exactly as provided in Appendix B.
- Use the error envelope exactly as provided in Appendix A.

## 2) Objective and Definition of Done

Deliver a Node.js + TypeScript monorepo that:

- Implements **100%** of the main API endpoints listed in Section 7, with matching status codes, auth requirements, and JSON shapes described in this document.
- Implements the identity-platform services as separate Node apps:
  - `identity-gateway` (public edge)
  - `identity-orchestrator` (internal API + job runner)
  - Keep `inference` service as-is (Python FastAPI) unless explicitly requested to port it.
- Uses Postgres with the same tables and constraints as the current SQL migrations; includes a migration runner.
- Preserves security semantics: JWT, refresh sessions, bcrypt, TOTP, DID session tokens, institution API keys, admin RBAC.
- Preserves crypto semantics: AES-GCM encryption derived via HKDF; Ed25519 receipt signatures and KID derivation.
- Includes production-grade middleware: request-id, structured logs, exception safety, CORS, rate limiting, input validation.
- Includes tests (unit + integration) for critical workflows and security primitives.
- Can be run locally via docker compose (Postgres + optional Redis + optional MinIO + optional inference + identity services).
- Provides CI-ready scripts: `lint`, `typecheck`, `test`, `build`, and Docker image builds for each service.

## 3) Monorepo Layout (required)

Choose one: `pnpm workspaces`, `Nx`, or `Turborepo`. Keep it simple, reproducible, and CI-friendly.

**Required top-level folders**
- `apps/`
  - `main-api/` (Verza API, port 8090)
  - `identity-gateway/` (port 8088)
  - `identity-orchestrator/` (port 8089)
  - `inference/` (Python service; can be vendored or referenced; keep docker-compose parity)
- `packages/`
  - `db/` (SQL migration runner + DB access helpers)
  - `config/` (typed env parsing shared across services)
  - `http/` (shared middleware: request id, CORS, rate limit, error envelope, logging)
  - `auth/` (JWT, session validation helpers, API key auth helpers, RBAC helpers)
  - `crypto/` (HKDF + AES-GCM utilities, canonical JSON helpers, Ed25519 signing helpers)
  - `types/` (shared TS types aligned to OpenAPI + DB models; generated types allowed)
  - `observability/` (structured logger, metrics wrapper, trace propagation)

**Hard constraints**
- TypeScript strict mode.
- Centralized error handling and consistent API error envelope (Appendix A).
- No business logic in route files beyond validation + mapping to service calls.
- No raw stringly env usage outside `packages/config`.

## 4) Actors, Roles, and Access Model (must match current semantics)

Implement these “actors” and enforce their access:

- **Public**: no auth (docs endpoints, health, public share links, some payments endpoints).
- **User**: Bearer JWT access token (`Authorization: Bearer <jwt>`).
- **Admin**: User JWT where `role=admin` (RBAC enforced per endpoint).
- **Verifier**: Implemented as a user role and/or verifier entity. Enforce any role-based restrictions as required by the endpoints.
- **Enterprise / Institution**: authenticated via API key:
  - `X-Institution-API-Key: <key>` (also accept `X-API-Key` as fallback)
  - institution must be active; key must not be revoked

Also implement DID-related flows:
- **DID Session Token**: `X-DID-Session-Token` (HS256 token with its own TTL semantics).
- **DID Signed Requests**: implement Appendix C.

## 5) Services to Implement (apps)

### 5.1) apps/main-api (Verza API)

**Port and health**
- Default `:8090` (respect `VERZA_ADDR` / `PORT`)
- Health endpoints: `/health`, `/health/db`, `/health/redis`

**Must implement these features**
- Auth lifecycle: signup/login/refresh/logout, forgot/reset password, sessions, session revocation.
- 2FA: TOTP setup/verify/disable + backup codes.
- Credentials: store/list/get/update, generate proofs, share management, public share tokens.
- Consents: granting, listing, revoking, audit events.
- Verifiers: register/search/update, stats lookup.
- Escrow: create/release/dispute, status.
- Governance: propose/vote/list proposals.
- Verifications: request/complete/status (cross-chain verification flow).
- Identity verifications: request/complete/list/get/status + audit trail + institutional attestations.
- Fiat payments: Stripe flow initiation, status, signed receipts, reconciliation/reporting.
- Admin: bridge health/tx list, institution management (CRUD-ish), members, API keys.
- Enterprise (institution) API: read “me”, rotate keys, list consents, pull credential/identity artifacts, list identity verifications, submit attestations.

### 5.2) apps/identity-gateway (Identity Platform Edge API)

Implement the public-ish gateway service described in the identity subsystem. It:
- Handles HTTP ingress, auth, observability, rate limit, metrics.
- Issues pre-signed upload URLs for object storage.
- Proxies session + verification flows to the orchestrator.

Routes (must match existing gateway behavior):
- `GET /healthz`
- `GET /metrics` (if enabled)
- `POST /v1/sessions`
- `POST /v1/media/presign`
- `POST /v1/verifications`
- `GET|POST|... /v1/verifications/:id/*` (dynamic proxy to orchestrator internal endpoints)

No other documents are required beyond this prompt.

### 5.3) apps/identity-orchestrator (Identity Platform Internal API + Jobs)

Implement orchestrator service described in the identity subsystem. It:
- Owns the verification state machine and persistence layer.
- Stores media metadata, triggers inference calls, produces explainable decisions.
- Supports synchronous run and async run via job queue with idempotency keys.

Routes (must match existing orchestrator behavior):
- `GET /healthz`
- `GET /metrics` (if enabled)
- `POST /internal/v1/sessions`
- `POST /internal/v1/verifications`
- `GET /internal/v1/verifications/:id`
- `GET /internal/v1/verifications/:id/audit`
- `POST /internal/v1/verifications/:id/media`
- `POST /internal/v1/verifications/:id/run` (supports `?async=true|1` and `Idempotency-Key`)
- `POST /internal/v1/verifications/:id/idempotency`

No other documents are required beyond this prompt.

### 5.4) apps/inference (Keep Python; integrate cleanly)

Keep inference as a separate internal service (Python FastAPI). The Node orchestrator calls it via HTTP JSON according to the identity platform design:
- `/v1/liveness/extract_best_frame`
- `/v1/document/extract_portrait`

Inference HTTP endpoints expected by the orchestrator:
- `POST /v1/liveness/extract_best_frame`
- `POST /v1/document/extract_portrait`

## 6) Data Stores and Integrations (required)

### 6.1) Postgres
Apply the SQL migrations provided in Appendix B in numeric order. Do not modify table/column names.

Identity platform can use a separate database if implemented; its schema is out of scope for Appendix B.

### 6.2) Redis
- Main API: used for `/health/redis` only in current setup; keep optional.
- Identity orchestrator: use Redis for job queue if implementing async jobs (recommended).

### 6.3) Object storage (S3-compatible)
Identity gateway must generate pre-signed PUT URLs; orchestrator must read the objects.
Support MinIO in dev and AWS S3 in prod.

### 6.4) Stripe
Fiat payment workflows are Stripe-backed. Implement Stripe client integration, webhook/polling behavior as defined by the existing endpoints/spec.

### 6.5) Optional chain/zk integrations
Main API reads optional URLs/config:
- EVM RPC (`EVM_RPC_URL`) to enable EVM client behaviors.
- ZK verifier URL (`ZK_VERIFIER_URL`) for proof verification workflows.

## 7) Main API Endpoints (list to implement)

The list below is the complete path surface; implement **every path** with correct methods and auth.

### Docs + Health (Public)
- `GET /swagger.yaml`
- `GET /openapi.yaml`
- `GET /openapi.json`
- `GET /swagger.json`
- `GET /health`
- `GET /health/db`
- `GET /health/redis`

### Auth (Public + User)
- `POST /api/v1/auth/signup`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/forgot-password`
- `POST /api/v1/auth/reset-password`
- `POST /api/v1/auth/logout` (User)

### User (“Me”) (User)
- `GET|PATCH /api/v1/me`
- `POST /api/v1/me/change-password`
- `GET /api/v1/me/sessions`
- `POST /api/v1/me/sessions/revoke`
- `POST /api/v1/me/2fa/setup`
- `POST /api/v1/me/2fa/verify`
- `POST /api/v1/me/2fa/disable`

### Notifications (User)
- `GET /api/v1/notifications`
- `POST /api/v1/notifications/read-all`
- `POST /api/v1/notifications/{id}/read`
- `POST /api/v1/notifications/seed` (dev/test utility; enforce environment gating)

### Search (User)
- `GET /api/v1/search`

### Credentials + Proofs + Shares (User + Public)
- `POST /api/v1/credentials/store`
- `POST /api/v1/credentials/share`
- `POST /api/v1/proofs/generate`
- `GET /api/v1/credentials`
- `GET|PATCH /api/v1/credentials/{credentialId}`
- `GET /api/v1/credentials/{credentialId}/proof`
- `GET /api/v1/credentials/{credentialId}/shares`
- `POST /api/v1/credentials/{credentialId}/shares/{shareId}/revoke`
- `GET /api/v1/shares/{token}` (Public)

### Verifiers (User; some endpoints may require verifier/admin per spec)
- `POST /api/v1/verifiers/register`
- `GET /api/v1/verifiers/search`
- `POST /api/v1/verifiers/update`
- `GET /api/v1/verifiers/{did}/stats`

### Escrow (User)
- `POST /api/v1/escrow/create`
- `POST /api/v1/escrow/release`
- `POST /api/v1/escrow/dispute`
- `GET /api/v1/escrow/{id}/status`

### Governance (User; propose requires Admin)
- `POST /api/v1/governance/propose` (Admin)
- `POST /api/v1/governance/vote`
- `GET /api/v1/governance/proposals`

### Cross-chain Verifications (User)
- `POST /api/v1/verifications/request`
- `POST /api/v1/verifications/complete`
- `GET /api/v1/verifications/{id}/status`

### Identity Verifications (User)
- `POST /api/v1/identity/verifications/request`
- `POST /api/v1/identity/verifications/complete`
- `GET /api/v1/identity/verifications`
- `GET /api/v1/identity/verifications/{id}`
- `GET /api/v1/identity/verifications/{id}/status`

### Fiat Payments (Public + Admin)
- `POST /api/v1/fiat/payments/initiate` (Public)
- `POST /api/v1/fiat/payments/reconcile` (Admin)
- `GET /api/v1/fiat/payments/{id}/status` (Public)
- `GET /api/v1/fiat/payments/{id}/receipt` (Public; supports format query)

### Admin (Admin)
- `GET /admin/bridge/health`
- `GET /admin/bridge/txs`
- `GET|POST /admin/institutions`
- `GET|PATCH /admin/institutions/{institution_id}`
- `GET|POST /admin/institutions/{institution_id}/members`
- `DELETE /admin/institutions/{institution_id}/members/{user_id}`
- `GET|POST /admin/institutions/{institution_id}/api-keys`
- `POST /admin/institutions/{institution_id}/api-keys/{api_key_id}/revoke`

### Enterprise / Institution API (Institution API Key)
- `GET /api/v1/institution/me`
- `POST /api/v1/institution/api-keys/rotate`
- `GET /api/v1/institution/consents`
- `GET /api/v1/institution/consents/{consent_id}`
- `GET /api/v1/institution/consents/{consent_id}/audit`
- `GET /api/v1/institution/consents/{consent_id}/credential`
- `GET /api/v1/institution/consents/{consent_id}/identity`
- `POST /api/v1/institution/identity/attestations`
- `GET /api/v1/institution/identity/verifications`
- `GET /api/v1/institution/identity/verifications/{verification_id}`

## 8) Security Requirements (must match existing behavior)

### 8.1) Auth primitives
Implement these exact semantics:

- Error envelope: use Appendix A ErrorResponse for all errors.
- JWT access token:
  - Header JSON: `{"alg":"HS256","typ":"JWT"}` then base64url (no padding).
  - Claims JSON:
    - `iss` (string)
    - `sub` (string user_id UUID)
    - `email` (string)
    - `role` (string, e.g. `user` or `admin`)
    - `sid` (string session_id UUID)
    - `iat` (int unix seconds)
    - `exp` (int unix seconds)
  - Signature: HMAC-SHA256 over `<b64url(header)>.<b64url(payload)>` with `JWT_SECRET`.
  - Validation: reject if signature invalid; reject if `exp` missing/expired; if `JWT_ISSUER` is non-empty, reject if `iss != JWT_ISSUER`.
- Refresh token sessions:
  - On successful signup/login, create a new `sessions` row with a UUID `id` and `refresh_token_hash = sha256_hex(refresh_token)`.
  - Refresh tokens are random url-safe base64 strings (48 random bytes encoded base64url without padding).
  - On refresh, rotate refresh token: update the `sessions.refresh_token_hash` to the new hash and extend session expiry to now + `REFRESH_TOKEN_TTL_SECONDS`.
  - Session revocation is enforced by checking `sessions.revoked_at IS NULL` and `now < sessions.expires_at`.
- Password hashing: bcrypt with default cost.
- 2FA (TOTP + backup codes):
  - Secret: 20 random bytes, base32 encoded, no padding.
  - Code: 6 digits, time step = 30s, HMAC-SHA1, allow window steps `-1, 0, +1`.
  - Setup response returns `secret` and `backup_codes` (10 strings). Each backup code is a UUID with `-` removed, first 10 characters.
  - Backup codes are stored as `sha256_hex(code)` array.
  - Disable 2FA requires valid password plus either a valid TOTP code or a valid backup code.
- Institution API key auth:
  - Accept API key from `X-Institution-API-Key`, fallback to `X-API-Key`, fallback to `Authorization: ApiKey <key>`.
  - Lookup by `sha256_hex(key)` in `institution_api_keys.key_hash`.
  - Reject if API key revoked or institution status != `active`.
- DID Session Token and DID-signed requests: implement Appendix C exactly.

### 8.1.1) Auth request/response JSON
Implement these JSON bodies exactly (also shown in Appendix A):

- Signup: `POST /api/v1/auth/signup` body `{ "email": string, "password": string, "name": string }` => AuthResponse
- Login: `POST /api/v1/auth/login` body `{ "email": string, "password": string, "twofa_code"?: string, "backup_code"?: string }` => AuthResponse
- Refresh: `POST /api/v1/auth/refresh` body `{ "refresh_token": string }` => AuthResponse
- Forgot password: `POST /api/v1/auth/forgot-password` body `{ "email": string }` => `{ "status": "ok" }`
- Reset password: `POST /api/v1/auth/reset-password` body `{ "token": string, "new_password": string }` => `{ "status": "ok" }`

### 8.2) Crypto primitives
Preserve behavior exactly:
- Encryption at rest: per-transaction key derived via HKDF; AES-GCM encryption with random nonce.
- Canonical JSON hashing for audit-style chains.
- Receipt signing: Ed25519 signature; KID derived from public key hash prefix; signature input includes issued-at timestamp.

## 9) Observability and Operational Requirements

Implement across all Node services:
- Request IDs: accept/propagate `X-Request-Id`, generate if missing.
- Structured JSON logs, include request_id, method, route, status, duration_ms.
- Safe exception handling: never crash on request; return consistent error envelope.
- CORS: compatible with existing `CORS_ALLOWED_ORIGINS` behavior.
- Rate limiting: IP-based; exempt health endpoints; keep semantics close to Go defaults.
- Metrics endpoint for identity services (`/metrics`) with Prometheus-friendly output or equivalent.
- Trace propagation: accept/emit `traceparent` for identity services and proxy calls.

## 10) Required Work Breakdown (tasks to execute)

Deliver this in phases with working software each phase.

### Phase A — Monorepo foundation
- Choose workspace tool (pnpm/Nx/Turbo) and implement folder layout.
- Implement `packages/config` with typed env parsing for each service (main API + identity services).
- Implement `packages/http` middleware stack shared by services (request id, logs, error envelope, CORS, rate limit, body size limits).
- Implement `packages/db` migration runner that can run both main DB migrations and identity DB migrations.
- Implement `packages/observability` logger + metrics helpers.

### Phase B — Main API skeleton
- Implement server bootstrap for `apps/main-api` with route structure aligned to Section 7.
- Implement consistent response envelope and error handling per spec.
- Implement DB connection pooling and repo layer scaffolding.

### Phase C — Auth + sessions + Me
- Implement users, sessions, refresh workflow, logout revoke, forgot/reset password.
- Implement JWT mint/verify and RBAC for admin endpoints.
- Implement 2FA flows (setup/verify/disable) and backup codes.
- Integration tests for auth and sessions using Postgres.

### Phase D — Core user features
- Notifications endpoints + dynamic read endpoints.
- Search endpoint behavior per spec.
- Credentials CRUD, share tokens, public share retrieval, proof generation endpoint behavior.
- Consent system (user side) per spec.
- Tests for credential + share flows.

### Phase E — Verifiers, escrow, governance, verifications
- Verifier registry endpoints and stats.
- Escrow create/release/dispute/status.
- Governance propose/vote/list; enforce admin on propose.
- Cross-chain verification request/complete/status.
- Tests covering permission boundaries and status transitions.

### Phase F — Identity verifications + enterprise hooks
- Identity verification request/complete/list/get/status, audit events.
- Enterprise endpoints to list identity verifications, fetch consent-bound artifacts, submit attestations.
- Tests around consent enforcement and institution auth.

### Phase G — Fiat payments
- Stripe-backed initiation, status, receipt issuance (signed), reconciliation flow (admin).
- Implement audit-chain style payment events per schema.
- Tests for receipt signing determinism and signature verification.

### Phase H — Admin + enterprise management
- Admin institution management endpoints, member management, API key issuance and revocation.
- Institution key rotation endpoint.
- Tests for admin permissions and key revocation.

### Phase I — Identity platform services (Node)
- Implement `apps/identity-gateway` and `apps/identity-orchestrator` matching Go behavior:
  - auth model, presigned uploads, proxying, state transitions
  - sync run and async run via job queue with idempotency key support
- Integrate with S3/MinIO and inference service HTTP APIs.
- Provide docker compose to run: postgres + redis + minio + inference + orchestrator + gateway.

## 11) Local Dev + CI Expectations

### Local dev
- One command to start the full stack in docker compose (main API + db; identity stack separately or combined).
- Provide seed/dev mode behaviors equivalent to the current repo (e.g., notification seeding gated to non-prod).

### CI
Provide scripts and ensure they pass:
- `lint`
- `typecheck`
- `test` (unit + integration; integration uses ephemeral Postgres container)
- `build`
- Docker image builds for `main-api`, `identity-gateway`, `identity-orchestrator`

## 12) Acceptance Criteria Checklist

You are done only when:
- All paths listed above are implemented and validated against this document.
- All DB migrations apply cleanly and the service runs against a fresh database.
- Auth and permission boundaries are enforced (user/admin/institution).
- Crypto primitives match Go outputs for test vectors (HKDF/AES-GCM + receipt signature KID derivation).
- Identity gateway and orchestrator run end-to-end with MinIO + inference stubs.
- Tests cover the critical flows and pass in CI.

## Appendix A — Error Envelope and Auth Schemas

### ErrorResponse

```json
{
  "error": {
    "code": "string",
    "message": "string",
    "details": { "any": "object" },
    "request_id": "string"
  }
}
```

### OkStatusResponse

```json
{ "status": "ok" }
```

### User

```json
{
  "id": "string",
  "email": "string",
  "name": "string",
  "phone": "string",
  "bio": "string",
  "avatar_url": "string",
  "did": "string",
  "role": "string",
  "status": "string",
  "created_at": "date-time",
  "updated_at": "date-time"
}
```

### Session

```json
{
  "id": "string",
  "user_id": "string",
  "created_at": "date-time",
  "expires_at": "date-time",
  "revoked_at": "date-time|null",
  "user_agent": "string",
  "ip": "string"
}
```

### AuthResponse

```json
{
  "user": { "id": "string" },
  "access_token": "string",
  "refresh_token": "string"
}
```

## Appendix B — Postgres Migrations

Apply the following SQL in numeric order.

### 0001_cross_chain.sql

```sql
CREATE TABLE IF NOT EXISTS cross_chain_transactions (
    id UUID PRIMARY KEY,
    midnight_tx_hash VARCHAR(66),
    cardano_tx_hash VARCHAR(66),
    operation_type VARCHAR(50),
    status VARCHAR(20),
    retry_count INT DEFAULT 0,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credential_metadata (
    credential_id VARCHAR(66) PRIMARY KEY,
    midnight_address VARCHAR(100),
    cardano_escrow_id VARCHAR(66),
    verifier_did VARCHAR(100),
    status VARCHAR(20),
    created_at TIMESTAMP
);
```

### 0002_app_core.sql

```sql
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    did TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'active',
    password_hash TEXT NOT NULL,
    twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    twofa_secret TEXT NOT NULL DEFAULT '',
    backup_codes_sha TEXT NOT NULL DEFAULT '',
    last_login_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    user_agent TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_hash ON sessions(refresh_token_hash);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    read_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);

CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    owner_did TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    issuer_name TEXT NOT NULL DEFAULT '',
    document_number TEXT NOT NULL DEFAULT '',
    issue_date TIMESTAMP,
    expiry_date TIMESTAMP,
    issuing_authority TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    encrypted_data TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credentials_owner_user_id ON credentials(owner_user_id);

CREATE TABLE IF NOT EXISTS credential_shares (
    id UUID PRIMARY KEY,
    credential_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_did TEXT NOT NULL DEFAULT '',
    recipient TEXT NOT NULL DEFAULT '',
    permission TEXT NOT NULL DEFAULT 'view',
    purpose TEXT NOT NULL DEFAULT '',
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credential_shares_credential_id ON credential_shares(credential_id);
```

### 0003_identity_verifications.sql

```sql
CREATE TABLE IF NOT EXISTS identity_verifications (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id UUID REFERENCES credentials(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    provider TEXT NOT NULL DEFAULT 'internal',
    document_type TEXT NOT NULL DEFAULT '',
    confidence_threshold REAL NOT NULL DEFAULT 0.98,
    scores_json TEXT NOT NULL DEFAULT '{}',
    reasons_json TEXT NOT NULL DEFAULT '[]',
    signals_json TEXT NOT NULL DEFAULT '{}',
    locale TEXT NOT NULL DEFAULT '',
    client_timestamp TIMESTAMP,
    geo_lat REAL NOT NULL DEFAULT 0,
    geo_lon REAL NOT NULL DEFAULT 0,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    server_received_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_identity_verifications_user_id ON identity_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_identity_verifications_credential_id ON identity_verifications(credential_id);
CREATE INDEX IF NOT EXISTS idx_identity_verifications_status ON identity_verifications(status);

CREATE TABLE IF NOT EXISTS identity_verification_audit_events (
    id UUID PRIMARY KEY,
    verification_id UUID NOT NULL REFERENCES identity_verifications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_verification_audit_verification_id ON identity_verification_audit_events(verification_id);
CREATE INDEX IF NOT EXISTS idx_identity_verification_audit_user_id ON identity_verification_audit_events(user_id);
```

### 0004_fiat_payments.sql

```sql
CREATE TABLE IF NOT EXISTS did_revocations (
    did_hash TEXT PRIMARY KEY,
    revoked_at TIMESTAMP NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS did_sessions (
    id UUID PRIMARY KEY,
    did_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_did_sessions_did_hash ON did_sessions(did_hash);

CREATE TABLE IF NOT EXISTS fiat_payment_sessions (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    did_hash TEXT NOT NULL,
    did_enc TEXT NOT NULL DEFAULT '',
    did_nonce_b64 TEXT NOT NULL DEFAULT '',
    amount_minor BIGINT NOT NULL,
    currency TEXT NOT NULL,
    preferred_currency TEXT NOT NULL DEFAULT '',
    stripe_payment_intent_id TEXT NOT NULL DEFAULT '',
    stripe_client_secret TEXT NOT NULL DEFAULT '',
    stripe_status TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'initiated',
    fx_rate REAL NOT NULL DEFAULT 0,
    fx_source_currency TEXT NOT NULL DEFAULT '',
    fx_target_currency TEXT NOT NULL DEFAULT '',
    fx_locked_until TIMESTAMP,
    zk_token_hash TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fiat_payment_sessions_user_id ON fiat_payment_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_fiat_payment_sessions_did_hash ON fiat_payment_sessions(did_hash);
CREATE INDEX IF NOT EXISTS idx_fiat_payment_sessions_stripe_id ON fiat_payment_sessions(stripe_payment_intent_id);
CREATE INDEX IF NOT EXISTS idx_fiat_payment_sessions_status ON fiat_payment_sessions(status);

CREATE TABLE IF NOT EXISTS payment_audit_events (
    id UUID PRIMARY KEY,
    payment_id UUID NOT NULL REFERENCES fiat_payment_sessions(id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    type TEXT NOT NULL,
    at TIMESTAMP NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    prev_hash_hex TEXT NOT NULL DEFAULT '',
    hash_hex TEXT NOT NULL,
    sig_kid TEXT NOT NULL DEFAULT '',
    sig_b64 TEXT NOT NULL DEFAULT '',
    UNIQUE (payment_id, seq),
    UNIQUE (hash_hex)
);

CREATE INDEX IF NOT EXISTS idx_payment_audit_payment ON payment_audit_events(payment_id);

CREATE TABLE IF NOT EXISTS payment_receipts (
    id UUID PRIMARY KEY,
    payment_id UUID NOT NULL REFERENCES fiat_payment_sessions(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    receipt_json TEXT NOT NULL DEFAULT '{}',
    receipt_hash_hex TEXT NOT NULL,
    sig_kid TEXT NOT NULL DEFAULT '',
    sig_b64 TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_payment_receipts_payment ON payment_receipts(payment_id);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id UUID PRIMARY KEY,
    payment_id UUID NOT NULL REFERENCES fiat_payment_sessions(id) ON DELETE CASCADE,
    amount_minor BIGINT NOT NULL,
    currency TEXT NOT NULL,
    stripe_payment_intent_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_entries_payment ON ledger_entries(payment_id);

CREATE TABLE IF NOT EXISTS reconciliation_reports (
    id UUID PRIMARY KEY,
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    report_json TEXT NOT NULL DEFAULT '{}',
    zk_proof_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);
```

### 0005_institutions_consents.sql

```sql
CREATE TABLE IF NOT EXISTS institutions (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS institution_members (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL,
    UNIQUE(institution_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_institution_members_user_id ON institution_members(user_id);
CREATE INDEX IF NOT EXISTS idx_institution_members_institution_id ON institution_members(institution_id);

CREATE TABLE IF NOT EXISTS institution_api_keys (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    key_hash TEXT UNIQUE NOT NULL,
    last4 TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_institution_api_keys_institution_id ON institution_api_keys(institution_id);

CREATE TABLE IF NOT EXISTS consents (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    credential_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    allowed_fields_json TEXT NOT NULL DEFAULT '[]',
    purpose TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_consents_user_id ON consents(user_id);
CREATE INDEX IF NOT EXISTS idx_consents_institution_id ON consents(institution_id);
CREATE INDEX IF NOT EXISTS idx_consents_credential_id ON consents(credential_id);
CREATE INDEX IF NOT EXISTS idx_consents_status ON consents(status);

CREATE TABLE IF NOT EXISTS consent_audit_events (
    id UUID PRIMARY KEY,
    consent_id UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL DEFAULT '',
    actor_type TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_consent_audit_events_consent_id ON consent_audit_events(consent_id);
```

### 0006_identity_verification_attestations.sql

```sql
ALTER TABLE identity_verifications
    ADD COLUMN IF NOT EXISTS verifier_institution_id UUID REFERENCES institutions(id) ON DELETE SET NULL;

ALTER TABLE identity_verifications
    ADD COLUMN IF NOT EXISTS standard TEXT NOT NULL DEFAULT '';

ALTER TABLE identity_verifications
    ADD COLUMN IF NOT EXISTS verifier_reference TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_identity_verifications_verifier_institution_id ON identity_verifications(verifier_institution_id);
```

## Appendix C — DID Signed Requests and DID Session Tokens

### DID signed requests (Ed25519)

Used by `POST /api/v1/fiat/payments/initiate`.

Required headers:
- `X-DID: <did>`
- `X-DID-Timestamp: <RFC3339Nano>`
- `X-DID-Nonce: <string>`
- `X-DID-Signature: <base64url(signature)>` (also accept standard base64)

Canonical string to sign (exactly):

```
UPPERCASE(METHOD) + "\n" +
PATH + "\n" +
TIMESTAMP + "\n" +
NONCE + "\n" +
HEX(SHA256(raw_request_body_bytes))
```

Timestamp validation window: reject if timestamp is more than 30 seconds in the future or more than 5 minutes in the past.

Supported DID methods:
- `did:jwk:<base64url(jwk_json)>` where `jwk_json` is `{"kty":"OKP","crv":"Ed25519","x":"<base64url(pubkey_bytes)>"}`
- `did:key:z...` Ed25519 multicodec, multibase base58btc:
  - Decode base58btc (strip leading `z`)
  - Parse unsigned varint `0xed` then `0x01`
  - Remaining bytes must be 32-byte Ed25519 public key

### DID session token (HS256)

Header JSON: `{"alg":"HS256","typ":"DID"}` then base64url (no padding).

Claims JSON:
- `did_hash`: `sha256_hex(did_string)`
- `sid`: session UUID
- `iat`: unix seconds
- `exp`: unix seconds

Signature: HMAC-SHA256 over `<b64url(header)>.<b64url(payload)>` with `DID_SESSION_SECRET` (must be at least 16 bytes). Default `DID_SESSION_SECRET = JWT_SECRET` if not provided.

Validation:
- Reject if signature invalid.
- Reject if `exp` missing/expired.
- Check the referenced `did_sessions` row exists, `revoked_at IS NULL`, `now < expires_at`, and `did_hash` matches.
- Reject if `did_hash` exists in `did_revocations`.
