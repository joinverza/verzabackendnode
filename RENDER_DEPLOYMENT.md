# Render Deployment Guide

## Overview

This repo ships a Render Blueprint in [render.yaml](file:///c:/Users/User/Desktop/verzabackendnode/render.yaml) that deploys:

- verza-main-api (public)
- identity-gateway (public)
- identity-orchestrator (private)
- inference (private)
- verza-main-db (managed Postgres)
- verza-identity-db (managed Postgres)

The main API and identity orchestrator run DB migrations on startup, so the managed databases must be reachable and writable at boot.

## Deploy Steps (Blueprint)

1. In Render, choose New → Blueprint.
2. Point it to this repository and confirm render.yaml is detected.
3. Pick a region and create resources.
4. After resources are created, open each service and set the required environment variables listed below.
5. Deploy all services.

## Deploy Steps (Manual, No Blueprint)

This is the most reliable way to get running on Render when Blueprint validation keeps failing.

### 1) Create the databases

Create two managed PostgreSQL databases:

- verza-main-db
- verza-identity-db

After creation, keep each database’s Internal Database URL handy (Render shows it on the database page).

### 2) Create services (Docker)

Create each service from the Render Dashboard:

#### verza-main-api (public web service)

- New → Web Service
- Connect this repo
- Runtime: Docker
- Dockerfile path: apps/main-api/Dockerfile

Set the environment variables listed in the verza-main-api section below, including:

- DATABASE_URL: use verza-main-db’s connection string
- PGSSLMODE: require
- IDENTITY_GATEWAY_URL: use the identity-gateway internal URL (or its public URL)

Health check path:

- /health

#### identity-gateway (public web service)

- New → Web Service
- Connect this repo
- Runtime: Docker
- Dockerfile path: apps/identity-gateway/Dockerfile

Set the environment variables listed in the identity-gateway section below.

Health check path:

- /healthz

#### identity-orchestrator (private service)

- New → Private Service
- Connect this repo
- Runtime: Docker
- Dockerfile path: apps/identity-orchestrator/Dockerfile

Set the environment variables listed in the identity-orchestrator section below, including:

- IDENTITY_DATABASE_URL: use verza-identity-db’s connection string
- PGSSLMODE: require
- INFERENCE_URL: use inference’s internal URL

Health check path:

- /healthz

#### inference (private service)

- New → Private Service
- Connect this repo
- Runtime: Docker
- Dockerfile path: apps/inference/Dockerfile

If you want a minimum viable deployment, you can skip inference and set identity-orchestrator’s INFERENCE_URL to a reachable service you control.

### 3) Deploy order

1. Deploy verza-main-db and verza-identity-db first (databases must be ready).
2. Deploy inference (if used).
3. Deploy identity-orchestrator (it runs migrations for the identity DB on boot).
4. Deploy identity-gateway.
5. Deploy verza-main-api (it runs migrations for the main DB on boot).

## Environment Variables

Render will inject database connection strings for the two managed databases. Secrets marked as secret should be configured in Render as synced secrets.

### Generating secret values

If you’re setting these manually in the Render Dashboard, you can generate safe values like this:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

Use the output as the value for:

- JWT_SECRET
- ENCRYPTION_MASTER_KEY_B64
- RECEIPT_ED25519_SEED_B64

### verza-main-api (public)

Required:

- PORT: 8090
- DATABASE_URL: from verza-main-db
- PGSSLMODE: require
- JWT_SECRET: secret, at least 16 chars
- JWT_ISSUER: verza
- JWT_AUDIENCE: verza
- ENCRYPTION_MASTER_KEY_B64: secret, base64
- RECEIPT_ED25519_SEED_B64: secret, base64
- IDENTITY_GATEWAY_URL: http://identity-gateway:8088

Recommended:

- ACCESS_TOKEN_TTL_SECONDS: 900
- REFRESH_TOKEN_TTL_SECONDS: 2592000
- IDENTITY_RETENTION_DAYS: 0
- CORS_ALLOWED_ORIGINS: comma-separated list, or empty for allow-all
- LOG_LEVEL: info
- METRICS_ENABLED: 0

Optional:

- REDIS_URL: enables Redis-backed features if used later

### identity-gateway (public)

Required:

- PORT: 8088
- HOST: 0.0.0.0
- ORCHESTRATOR_URL: http://identity-orchestrator:8089
- JWT_SECRET: secret, at least 16 chars
- JWT_ISSUER: verza
- JWT_AUDIENCE: verza

Optional (required for /v1/media/presign):

- S3_ENDPOINT: S3-compatible endpoint
- S3_ACCESS_KEY_ID
- S3_SECRET_ACCESS_KEY
- S3_BUCKET
- S3_REGION

Recommended:

- S3_FORCE_PATH_STYLE: 0 (set to 1 for MinIO or path-style S3)
- CORS_ALLOWED_ORIGINS: comma-separated list, or empty for allow-all
- LOG_LEVEL: info
- METRICS_ENABLED: 1

### identity-orchestrator (private)

Required:

- PORT: 8089
- IDENTITY_DATABASE_URL: from verza-identity-db
- PGSSLMODE: require
- INFERENCE_URL: http://inference:8087
- JWT_SECRET: secret, at least 16 chars
- JWT_ISSUER: verza
- JWT_AUDIENCE: verza

Recommended:

- IDENTITY_RETENTION_DAYS: 0
- CORS_ALLOWED_ORIGINS: comma-separated list, or empty for allow-all
- LOG_LEVEL: info
- METRICS_ENABLED: 1

Optional:

- REDIS_URL: required for async verification runs
- S3_ENDPOINT
- S3_ACCESS_KEY_ID
- S3_SECRET_ACCESS_KEY
- S3_BUCKET
- S3_REGION
- S3_FORCE_PATH_STYLE
- TLS_KEY_PATH
- TLS_CERT_PATH
- TLS_CA_PATH
- TLS_REQUIRE_CLIENT_CERT

### inference (private)

Required:

- PORT: 8087

## Post-Deploy Checks

Use the public service URLs Render assigns.

Health checks:

- verza-main-api: GET /health
- identity-gateway: GET /healthz
- identity-orchestrator: GET /healthz (private network only)

Inference smoke test (private network only):

- POST /v1/liveness/extract_best_frame
- POST /v1/document/extract_portrait

Example payload:

```json
{ "key": "sample-key" }
```

## Notes

- identity-gateway is public for direct testing; its downstream calls to identity-orchestrator remain private inside Render’s network.
- If REDIS_URL is not set in identity-orchestrator, async verification runs are disabled and sync runs still work.
- If S3 values are not set for identity-orchestrator, media existence checks are skipped.
