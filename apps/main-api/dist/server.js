import http from "node:http";
import crypto from "node:crypto";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { createMainApiConfig } from "@verza/config";
import { canonicalJson, sha256Hex, signReceipt } from "@verza/crypto";
import { createPgPool, migrateDatabase } from "@verza/db";
import { createHttpApp, errorHandler, notFoundHandler } from "@verza/http";
import { createLogger, initTelemetry } from "@verza/observability";
import promClient from "prom-client";
import { createClient } from "redis";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { registerMainApiRoutes } from "./v1/routes.js";
import { appendAuditEvent } from "./v1/routers/auditLog.js";
import { authTokensResponseSchema, forgotPasswordSchema, loginSchema, okResponseSchema, refreshSchema, resetPasswordSchema, signupSchema } from "./v1/routers/auth.js";
import { shareResponseSchema, shareSchema, storeResponseSchema, storeSchema } from "./v1/routers/credentials.js";
import { idSchema as fiatPaymentIdParamsSchema, initiateResponseSchema, initiateSchema as fiatInitiateSchema, notConfiguredResponseSchema, paymentStatusResponseSchema, receiptQuerySchema, receiptResponseSchema, reconcileResponseSchema } from "./v1/routers/fiatPayments.js";
export async function createMainApiServer() {
    const config = createMainApiConfig(process.env);
    const logger = createLogger({ service: "main-api", level: config.LOG_LEVEL });
    const telemetry = await initTelemetry({ serviceName: "main-api" });
    const pool = createPgPool(config.DATABASE_URL);
    await migrateDatabase({
        db: "main",
        databaseUrl: config.DATABASE_URL,
        logger
    });
    if (config.IDENTITY_RETENTION_DAYS && config.IDENTITY_RETENTION_DAYS > 0) {
        await purgeMainIdentityRetention({ pool, days: config.IDENTITY_RETENTION_DAYS, logger });
    }
    const app = createHttpApp({ logger, corsAllowedOrigins: config.CORS_ALLOWED_ORIGINS });
    app.disable("x-powered-by");
    app.use((req, res, next) => {
        res.setHeader("x-content-type-options", "nosniff");
        res.setHeader("x-frame-options", "DENY");
        res.setHeader("referrer-policy", "no-referrer");
        res.setHeader("permissions-policy", "geolocation=(), microphone=(), camera=()");
        const xfProto = (req.header("x-forwarded-proto") ?? "").toLowerCase();
        if (req.secure || xfProto === "https") {
            res.setHeader("strict-transport-security", "max-age=15552000; includeSubDomains");
        }
        next();
    });
    app.get("/health", (_req, res) => res.json({ status: "ok" }));
    app.get("/health/db", async (_req, res, next) => {
        try {
            await pool.query("select 1 as ok");
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    const redisUrlTrimmed = String(config.REDIS_URL ?? "").trim();
    const redisUrl = redisUrlTrimmed.length ? redisUrlTrimmed : null;
    const createRedisClient = createClient;
    const redis = redisUrl ? createRedisClient({ url: redisUrl }) : null;
    app.get("/health/redis", async (_req, res, next) => {
        try {
            if (!redis)
                return res.json({ status: "ok", redis: "not_configured" });
            if (!redis.isOpen)
                await redis.connect();
            const pong = await redis.ping();
            res.json({ status: "ok", redis: pong });
        }
        catch (err) {
            next(err);
        }
    });
    if (config.METRICS_ENABLED) {
        const register = new promClient.Registry();
        register.setDefaultLabels({ service: "main-api" });
        promClient.collectDefaultMetrics({ register });
        app.get("/metrics", async (_req, res, next) => {
            try {
                res.setHeader("content-type", register.contentType);
                res.send(await register.metrics());
            }
            catch (err) {
                next(err);
            }
        });
    }
    registerMainApiRoutes(app, { config, logger, pool });
    const openapi = buildOpenApiSpec({
        title: "Verza Main API",
        version: "1.0.0",
        serverUrl: `http://localhost:${config.PORT}`
    });
    openapi.paths = mergeOpenApiPaths(discoverExpressPaths(app), openapi.paths ?? {});
    enhanceOpenApiFromZod(openapi);
    app.get("/openapi.json", (_req, res) => {
        res.setHeader("cache-control", "no-store");
        res.setHeader("x-robots-tag", "noindex, nofollow");
        res.json(openapi);
    });
    app.get("/swagger.json", (_req, res) => {
        res.setHeader("cache-control", "no-store");
        res.setHeader("x-robots-tag", "noindex, nofollow");
        res.json(openapi);
    });
    app.get("/swaggerdocs", (_req, res) => res.redirect(302, "/docs"));
    app.get("/docs", (_req, res) => {
        res.setHeader("cache-control", "no-store");
        res.setHeader("x-robots-tag", "noindex, nofollow");
        res.type("text/html").send(getSwaggerUiHtml({ specUrl: "/openapi.json", title: "Verza API Docs" }));
    });
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = http.createServer(app);
    let stopAuditAnchorJob = null;
    let stopRetentionJob = null;
    return {
        start: async () => {
            await new Promise((resolve) => {
                server.listen(config.PORT, config.HOST, resolve);
            });
            const addr = server.address();
            logger.info({ addr }, "main-api listening");
            if (!stopAuditAnchorJob)
                stopAuditAnchorJob = startAuditAnchorJob({ pool, config, logger });
            if (!stopRetentionJob)
                stopRetentionJob = startRetentionJob({ pool, config, logger });
        },
        stop: async () => {
            if (stopAuditAnchorJob)
                stopAuditAnchorJob();
            if (stopRetentionJob)
                stopRetentionJob();
            await new Promise((resolve, reject) => {
                server.close((err) => (err ? reject(err) : resolve()));
            });
            if (redis?.isOpen)
                await redis.quit();
            await pool.end();
            await telemetry.shutdown();
        }
    };
}
async function purgeMainIdentityRetention(opts) {
    try {
        const days = Math.max(0, Math.floor(opts.days));
        if (!days)
            return;
        await opts.pool.query("delete from identity_verifications where server_received_at < now() - ($1::int * interval '1 day') and status <> 'pending'", [days]);
    }
    catch (err) {
        opts.logger.error({ err }, "identity retention purge failed");
    }
}
function unrefTimer(timer) {
    if (typeof timer !== "object" || !timer)
        return;
    const maybe = timer;
    if (typeof maybe.unref !== "function")
        return;
    timer.unref();
}
function startAuditAnchorJob(opts) {
    const intervalSecondsRaw = Number(opts.config.AUDIT_ANCHOR_INTERVAL_SECONDS ?? 0);
    const intervalSeconds = Number.isFinite(intervalSecondsRaw) ? Math.max(0, Math.floor(intervalSecondsRaw)) : 0;
    if (!intervalSeconds)
        return () => void 0;
    let running = false;
    const tick = async () => {
        if (running)
            return;
        running = true;
        try {
            await runAuditAnchorJobOnce(opts);
        }
        catch (err) {
            opts.logger.error({ err }, "audit anchor job failed");
        }
        finally {
            running = false;
        }
    };
    void tick();
    const timer = setInterval(() => void tick(), intervalSeconds * 1000);
    unrefTimer(timer);
    return () => clearInterval(timer);
}
async function runAuditAnchorJobOnce(opts) {
    const anchorUrl = String(opts.config.AUDIT_ANCHOR_URL ?? "").trim();
    const anchorSecret = String(opts.config.AUDIT_ANCHOR_SECRET ?? "").trim();
    const storeToWorm = opts.config.COMPLIANCE_WORM_ENFORCE ? true : Boolean(createComplianceS3ClientIfConfigured(opts.config));
    const s3 = storeToWorm ? createComplianceS3ClientIfConfigured(opts.config) : null;
    if (storeToWorm && !s3)
        throw new Error("WORM storage not configured");
    const chains = await opts.pool.query("select tenant_id,stream,head_hash,next_seq,updated_at from audit_chains");
    for (const chain of chains.rows) {
        const anchoredAt = new Date();
        const stream = (chain.stream ?? "tenant").trim() || "tenant";
        const payload = {
            type: "audit_chain_anchor",
            tenant_id: chain.tenant_id,
            stream,
            head_hash: chain.head_hash ?? "",
            next_seq: Number(chain.next_seq ?? 1),
            chain_updated_at: chain.updated_at?.toISOString?.() ?? null,
            anchored_at: anchoredAt.toISOString()
        };
        const payloadJson = canonicalJson(payload);
        const payloadSha = sha256Hex(payloadJson);
        const signed = signReceipt({ seedB64: opts.config.RECEIPT_ED25519_SEED_B64, receipt: payload });
        const anchorId = crypto.randomUUID();
        await opts.pool.query("insert into audit_chain_anchors (id,tenant_id,stream,head_hash,next_seq,anchored_at,payload_json,sig_kid,sig_b64,anchor_target) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", [anchorId, chain.tenant_id, stream, payload.head_hash, payload.next_seq, anchoredAt, payloadJson, signed.sig_kid, signed.sig_b64, anchorUrl]);
        let evidence = null;
        if (s3) {
            const now = new Date();
            const retainUntil = new Date(now.getTime() + opts.config.COMPLIANCE_S3_OBJECT_LOCK_DAYS * 24 * 60 * 60 * 1000);
            const key = buildWormKey({
                prefix: "audit_anchors",
                tenantId: chain.tenant_id,
                stream,
                createdAtMs: now.getTime(),
                sha256: payloadSha,
                suffix: "json"
            });
            const bodyBuf = Buffer.from(payloadJson, "utf8");
            const bodySha = sha256Hex(bodyBuf);
            await s3.client.send(new PutObjectCommand({
                Bucket: s3.bucket,
                Key: key,
                Body: bodyBuf,
                ContentType: "application/json",
                ObjectLockMode: "COMPLIANCE",
                ObjectLockRetainUntilDate: retainUntil,
                Metadata: { tenant_id: chain.tenant_id, stream, payload_sha256: payloadSha, object_sha256: bodySha }
            }));
            const evidenceId = crypto.randomUUID();
            await opts.pool.query("insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", [
                evidenceId,
                chain.tenant_id,
                null,
                "audit_anchor",
                anchorId,
                "application/json",
                bodySha,
                "external",
                Buffer.from(JSON.stringify({ provider: "s3", bucket: s3.bucket, key, payload_sha256: payloadSha, retain_until: retainUntil.toISOString() }), "utf8").toString("base64"),
                now,
                now.getTime()
            ]);
            evidence = { evidence_id: evidenceId, bucket: s3.bucket, key, retain_until: retainUntil.toISOString(), object_sha256: bodySha };
        }
        if (anchorUrl) {
            try {
                await fetch(anchorUrl, {
                    method: "POST",
                    headers: {
                        "content-type": "application/json",
                        ...(anchorSecret ? { "x-anchor-secret": anchorSecret } : {})
                    },
                    body: JSON.stringify({ ...payload, ...signed, payload_sha256: payloadSha })
                });
            }
            catch {
                void 0;
            }
        }
        await appendAuditEvent(opts.pool, {
            tenantId: chain.tenant_id,
            eventType: "audit_anchor_job_created",
            actorType: "system",
            actorId: "audit_anchor_job",
            subjectType: "audit_chain_anchor",
            subjectId: anchorId,
            data: { stream, head_hash: payload.head_hash, next_seq: payload.next_seq, payload_sha256: payloadSha, evidence }
        });
    }
}
function startRetentionJob(opts) {
    const enabled = Boolean(opts.config.RETENTION_JOB_ENABLED);
    if (!enabled)
        return () => void 0;
    const intervalSecondsRaw = Number(opts.config.RETENTION_JOB_INTERVAL_SECONDS ?? 0);
    const intervalSeconds = Number.isFinite(intervalSecondsRaw) ? Math.max(1, Math.floor(intervalSecondsRaw)) : 0;
    if (!intervalSeconds)
        return () => void 0;
    let running = false;
    const tick = async () => {
        if (running)
            return;
        running = true;
        try {
            await runRetentionJobOnce(opts);
        }
        catch (err) {
            opts.logger.error({ err }, "retention job failed");
        }
        finally {
            running = false;
        }
    };
    void tick();
    const timer = setInterval(() => void tick(), intervalSeconds * 1000);
    unrefTimer(timer);
    return () => clearInterval(timer);
}
async function runRetentionJobOnce(opts) {
    const storeToWorm = opts.config.COMPLIANCE_WORM_ENFORCE ? true : Boolean(createComplianceS3ClientIfConfigured(opts.config));
    const s3 = storeToWorm ? createComplianceS3ClientIfConfigured(opts.config) : null;
    if (storeToWorm && !s3)
        throw new Error("WORM storage not configured");
    const tenants = await opts.pool.query("select distinct tenant_id from retention_policies");
    for (const t of tenants.rows) {
        try {
            const policies = await opts.pool.query("select resource_type,retention_days,action from retention_policies where tenant_id=$1", [t.tenant_id]);
            const results = [];
            for (const p of policies.rows) {
                if (!p.retention_days || p.retention_days <= 0)
                    continue;
                const cutoff = new Date(Date.now() - p.retention_days * 24 * 60 * 60 * 1000);
                if (p.resource_type === "identity_verifications" && p.action === "delete") {
                    const del = await opts.pool.query("delete from identity_verifications where tenant_id=$1 and server_received_at < $2", [t.tenant_id, cutoff]);
                    results.push({ tenant_id: t.tenant_id, resource_type: p.resource_type, action: p.action, cutoff: cutoff.toISOString(), deleted: del.rowCount ?? 0 });
                }
            }
            const ranAt = new Date();
            const report = {
                type: "retention_run_report",
                tenant_id: t.tenant_id,
                ran_at: ranAt.toISOString(),
                results: results.map((r) => ({ ...r, deleted: Number(r.deleted ?? 0) }))
            };
            const reportJson = canonicalJson(report);
            const reportSha = sha256Hex(reportJson);
            const signed = signReceipt({ seedB64: opts.config.RECEIPT_ED25519_SEED_B64, receipt: report });
            const envelopeJson = canonicalJson({ report, report_sha256: reportSha, ...signed });
            const envelopeSha = sha256Hex(envelopeJson);
            const retentionRunId = crypto.randomUUID();
            const evidenceId = crypto.randomUUID();
            const createdAtMs = ranAt.getTime();
            let evidence = null;
            if (s3) {
                const retainUntil = new Date(ranAt.getTime() + opts.config.COMPLIANCE_S3_OBJECT_LOCK_DAYS * 24 * 60 * 60 * 1000);
                const key = buildWormKey({
                    prefix: "retention_runs",
                    tenantId: t.tenant_id,
                    stream: "retention",
                    createdAtMs,
                    sha256: reportSha,
                    suffix: "json"
                });
                const bodyBuf = Buffer.from(envelopeJson, "utf8");
                const bodySha = sha256Hex(bodyBuf);
                await s3.client.send(new PutObjectCommand({
                    Bucket: s3.bucket,
                    Key: key,
                    Body: bodyBuf,
                    ContentType: "application/json",
                    ObjectLockMode: "COMPLIANCE",
                    ObjectLockRetainUntilDate: retainUntil,
                    Metadata: { tenant_id: t.tenant_id, report_sha256: reportSha, object_sha256: bodySha, sig_kid: signed.sig_kid }
                }));
                await opts.pool.query("insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", [
                    evidenceId,
                    t.tenant_id,
                    null,
                    "retention_run_report",
                    retentionRunId,
                    "application/json",
                    bodySha,
                    "external",
                    Buffer.from(JSON.stringify({ provider: "s3", bucket: s3.bucket, key, report_sha256: reportSha, sig_kid: signed.sig_kid, sig_b64: signed.sig_b64, retain_until: retainUntil.toISOString() }), "utf8").toString("base64"),
                    ranAt,
                    createdAtMs
                ]);
                evidence = { evidence_id: evidenceId, bucket: s3.bucket, key, retain_until: retainUntil.toISOString(), object_sha256: bodySha };
            }
            else {
                await opts.pool.query("insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", [
                    evidenceId,
                    t.tenant_id,
                    null,
                    "retention_run_report",
                    retentionRunId,
                    "application/json",
                    envelopeSha,
                    "inline",
                    Buffer.from(envelopeJson, "utf8").toString("base64"),
                    ranAt,
                    createdAtMs
                ]);
                evidence = { evidence_id: evidenceId, object_sha256: envelopeSha };
            }
            await opts.pool.query("insert into retention_runs (id,tenant_id,ran_at,report_sha256,evidence_id) values ($1,$2,$3,$4,$5)", [
                retentionRunId,
                t.tenant_id,
                ranAt,
                reportSha,
                evidenceId
            ]);
            await appendAuditEvent(opts.pool, {
                tenantId: t.tenant_id,
                eventType: "retention_job_run",
                actorType: "system",
                actorId: "retention_job",
                subjectType: "retention_run",
                subjectId: retentionRunId,
                data: { report_sha256: reportSha, evidence, results: results.map((r) => ({ ...r, deleted: Number(r.deleted ?? 0) })) }
            });
        }
        catch (err) {
            opts.logger.error({ err, tenant_id: t.tenant_id }, "retention job tenant run failed");
        }
    }
}
function createComplianceS3ClientIfConfigured(config) {
    const endpoint = String(config.COMPLIANCE_S3_ENDPOINT ?? "").trim();
    const accessKeyId = String(config.COMPLIANCE_S3_ACCESS_KEY_ID ?? "").trim();
    const secretAccessKey = String(config.COMPLIANCE_S3_SECRET_ACCESS_KEY ?? "").trim();
    const bucket = String(config.COMPLIANCE_S3_BUCKET ?? "").trim();
    const region = String(config.COMPLIANCE_S3_REGION ?? "").trim();
    if (!endpoint || !accessKeyId || !secretAccessKey || !bucket || !region)
        return null;
    return {
        bucket,
        client: new S3Client({
            region,
            endpoint,
            forcePathStyle: config.COMPLIANCE_S3_FORCE_PATH_STYLE ?? false,
            credentials: { accessKeyId, secretAccessKey }
        })
    };
}
function buildWormKey(opts) {
    const safeStream = opts.stream.replaceAll(/[^a-zA-Z0-9._-]/g, "_").slice(0, 64) || "tenant";
    return `compliance/${opts.prefix}/tenant=${opts.tenantId}/stream=${safeStream}/at_ms=${opts.createdAtMs}/${opts.sha256}.${opts.suffix}`;
}
function buildOpenApiSpec(input) {
    return {
        openapi: "3.0.3",
        info: {
            title: input.title,
            version: input.version
        },
        servers: [{ url: input.serverUrl }],
        tags: [
            { name: "Health" },
            { name: "Auth" },
            { name: "Me" },
            { name: "Credentials" },
            { name: "Consents" },
            { name: "Identity Verifications" },
            { name: "Verifiers" }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT"
                },
                institutionApiKey: {
                    type: "apiKey",
                    in: "header",
                    name: "x-institution-api-key"
                }
            },
            schemas: {
                ErrorResponse: {
                    type: "object",
                    properties: {
                        error: { type: "string" },
                        message: { type: "string" }
                    }
                },
                Consent: {
                    type: "object",
                    properties: {
                        id: { type: "string", format: "uuid" },
                        user_id: { type: "string", format: "uuid" },
                        institution_id: { type: "string", format: "uuid" },
                        credential_id: { type: "string", format: "uuid" },
                        allowed_fields: { type: "array", items: { type: "string" } },
                        purpose: { type: "string" },
                        status: { type: "string" },
                        expires_at: { type: "string", format: "date-time", nullable: true },
                        revoked_at: { type: "string", format: "date-time", nullable: true },
                        created_at: { type: "string", format: "date-time" }
                    }
                },
                IdentityVerification: {
                    type: "object",
                    properties: {
                        id: { type: "string", format: "uuid" },
                        user_id: { type: "string", format: "uuid" },
                        credential_id: { type: "string", format: "uuid", nullable: true },
                        status: { type: "string" },
                        provider: { type: "string" },
                        document_type: { type: "string" },
                        confidence_threshold: { type: "number" },
                        scores: { type: "object", additionalProperties: { type: "number" } },
                        reasons: { type: "array", items: { type: "string" } },
                        signals: { type: "object", additionalProperties: true },
                        locale: { type: "string" },
                        server_received_at: { type: "string", format: "date-time" },
                        completed_at: { type: "string", format: "date-time", nullable: true }
                    }
                },
                Verifier: {
                    type: "object",
                    properties: {
                        id: { type: "string", format: "uuid" },
                        owner_user_id: { type: "string", format: "uuid" },
                        name: { type: "string" },
                        did: { type: "string" },
                        status: { type: "string" },
                        website_url: { type: "string" },
                        description: { type: "string" },
                        metadata: { type: "object", additionalProperties: true },
                        created_at: { type: "string", format: "date-time" },
                        updated_at: { type: "string", format: "date-time" }
                    }
                }
            }
        },
        paths: {
            "/health": {
                get: {
                    tags: ["Health"],
                    summary: "Health check",
                    responses: {
                        200: {
                            description: "OK",
                            content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } }
                        }
                    }
                }
            },
            "/api/v1/consents": {
                get: {
                    tags: ["Consents"],
                    summary: "List user consents",
                    security: [{ bearerAuth: [] }],
                    responses: {
                        200: {
                            description: "Consents",
                            content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Consent" } } } }
                        }
                    }
                },
                post: {
                    tags: ["Consents"],
                    summary: "Create consent",
                    security: [{ bearerAuth: [] }],
                    requestBody: {
                        required: true,
                        content: {
                            "application/json": {
                                schema: {
                                    type: "object",
                                    required: ["institution_id", "credential_id"],
                                    properties: {
                                        institution_id: { type: "string", format: "uuid" },
                                        credential_id: { type: "string", format: "uuid" },
                                        allowed_fields: { type: "array", items: { type: "string" } },
                                        purpose: { type: "string" },
                                        expires_at: { type: "string", format: "date-time" }
                                    }
                                }
                            }
                        }
                    },
                    responses: {
                        201: {
                            description: "Created",
                            content: { "application/json": { schema: { type: "object", properties: { id: { type: "string", format: "uuid" } } } } }
                        },
                        400: { description: "Bad Request", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
                    }
                }
            },
            "/api/v1/consents/{consentId}": {
                get: {
                    tags: ["Consents"],
                    summary: "Get consent",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "consentId", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    responses: {
                        200: { description: "Consent", content: { "application/json": { schema: { $ref: "#/components/schemas/Consent" } } } },
                        404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
                    }
                }
            },
            "/api/v1/consents/{consentId}/revoke": {
                post: {
                    tags: ["Consents"],
                    summary: "Revoke consent",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "consentId", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    responses: {
                        200: { description: "OK", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } } },
                        404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
                    }
                }
            },
            "/api/v1/consents/{consentId}/audit": {
                get: {
                    tags: ["Consents"],
                    summary: "List consent audit events",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "consentId", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    responses: {
                        200: {
                            description: "Events",
                            content: {
                                "application/json": {
                                    schema: {
                                        type: "array",
                                        items: {
                                            type: "object",
                                            properties: {
                                                id: { type: "string", format: "uuid" },
                                                event_type: { type: "string" },
                                                actor_type: { type: "string" },
                                                actor_id: { type: "string" },
                                                data: { type: "object", additionalProperties: true },
                                                created_at: { type: "string", format: "date-time" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/identity/verifications/request": {
                post: {
                    tags: ["Identity Verifications"],
                    summary: "Request identity verification",
                    security: [{ bearerAuth: [] }],
                    requestBody: {
                        required: true,
                        content: {
                            "application/json": {
                                schema: {
                                    type: "object",
                                    properties: {
                                        credential_id: { type: "string", format: "uuid" },
                                        provider: { type: "string" },
                                        document_type: { type: "string" },
                                        confidence_threshold: { type: "number" },
                                        locale: { type: "string" }
                                    }
                                }
                            }
                        }
                    },
                    responses: {
                        201: {
                            description: "Created",
                            content: {
                                "application/json": {
                                    schema: { type: "object", properties: { id: { type: "string", format: "uuid" }, status: { type: "string" } } }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/identity/verifications": {
                get: {
                    tags: ["Identity Verifications"],
                    summary: "List identity verifications",
                    security: [{ bearerAuth: [] }],
                    responses: {
                        200: {
                            description: "Verifications",
                            content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/IdentityVerification" } } } }
                        }
                    }
                }
            },
            "/api/v1/identity/verifications/{id}": {
                get: {
                    tags: ["Identity Verifications"],
                    summary: "Get identity verification",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    responses: {
                        200: { description: "Verification", content: { "application/json": { schema: { $ref: "#/components/schemas/IdentityVerification" } } } },
                        404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
                    }
                }
            },
            "/api/v1/identity/verifications/{id}/status": {
                post: {
                    tags: ["Identity Verifications"],
                    summary: "Get identity verification status",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    responses: {
                        200: { description: "Status", content: { "application/json": { schema: { type: "object", properties: { id: { type: "string" }, status: { type: "string" } } } } } },
                        404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
                    }
                }
            },
            "/api/v1/identity/verifications/{id}/complete": {
                post: {
                    tags: ["Identity Verifications"],
                    summary: "Complete identity verification",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    requestBody: {
                        required: true,
                        content: {
                            "application/json": {
                                schema: {
                                    type: "object",
                                    properties: {
                                        status: { type: "string", enum: ["approved", "rejected", "completed"] },
                                        scores: { type: "object", additionalProperties: { type: "number" } },
                                        reasons: { type: "array", items: { type: "string" } },
                                        signals: { type: "object", additionalProperties: true }
                                    }
                                }
                            }
                        }
                    },
                    responses: { 200: { description: "OK", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } } } }
                }
            },
            "/api/v1/identity/verifications/{id}/cancel": {
                post: {
                    tags: ["Identity Verifications"],
                    summary: "Cancel identity verification",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    responses: {
                        200: { description: "OK", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } } },
                        404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
                    }
                }
            },
            "/api/v1/identity/verifications/{id}/audit": {
                get: {
                    tags: ["Identity Verifications"],
                    summary: "List identity verification audit events",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    responses: {
                        200: {
                            description: "Events",
                            content: {
                                "application/json": {
                                    schema: {
                                        type: "array",
                                        items: {
                                            type: "object",
                                            properties: {
                                                id: { type: "string", format: "uuid" },
                                                verification_id: { type: "string", format: "uuid" },
                                                user_id: { type: "string", format: "uuid" },
                                                event_type: { type: "string" },
                                                data: { type: "object", additionalProperties: true },
                                                created_at: { type: "string", format: "date-time" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/verifiers": {
                post: {
                    tags: ["Verifiers"],
                    summary: "Create verifier (owned by current user)",
                    security: [{ bearerAuth: [] }],
                    requestBody: {
                        required: true,
                        content: {
                            "application/json": {
                                schema: {
                                    type: "object",
                                    required: ["name"],
                                    properties: {
                                        name: { type: "string" },
                                        did: { type: "string" },
                                        website_url: { type: "string" },
                                        description: { type: "string" },
                                        metadata: { type: "object", additionalProperties: true }
                                    }
                                }
                            }
                        }
                    },
                    responses: {
                        201: { description: "Created", content: { "application/json": { schema: { type: "object", properties: { id: { type: "string", format: "uuid" } } } } } }
                    }
                },
                get: {
                    tags: ["Verifiers"],
                    summary: "List verifiers (owned, or search active with q)",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "q", in: "query", required: false, schema: { type: "string" } }],
                    responses: {
                        200: { description: "Verifiers", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Verifier" } } } } }
                    }
                }
            },
            "/api/v1/verifiers/{id}": {
                get: {
                    tags: ["Verifiers"],
                    summary: "Get verifier",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    responses: {
                        200: { description: "Verifier", content: { "application/json": { schema: { $ref: "#/components/schemas/Verifier" } } } },
                        404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
                    }
                },
                patch: {
                    tags: ["Verifiers"],
                    summary: "Update verifier (owner only)",
                    security: [{ bearerAuth: [] }],
                    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
                    requestBody: {
                        required: true,
                        content: {
                            "application/json": {
                                schema: {
                                    type: "object",
                                    properties: {
                                        name: { type: "string" },
                                        did: { type: "string" },
                                        website_url: { type: "string" },
                                        description: { type: "string" },
                                        status: { type: "string", enum: ["active", "inactive"] },
                                        metadata: { type: "object", additionalProperties: true }
                                    }
                                }
                            }
                        }
                    },
                    responses: { 200: { description: "OK", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } } } }
                }
            }
        }
    };
}
function getSwaggerUiHtml(input) {
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(input.title)}</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: ${JSON.stringify(input.specUrl)},
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout"
      });
    </script>
  </body>
</html>`;
}
function escapeHtml(s) {
    return s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}
function mergeOpenApiPaths(discovered, manual) {
    const out = { ...discovered };
    for (const [path, ops] of Object.entries(manual)) {
        out[path] = { ...(out[path] ?? {}), ...ops };
    }
    return out;
}
function enhanceOpenApiFromZod(openapi) {
    const paths = openapi.paths ?? {};
    openapi.paths = paths;
    const errorEnvelopeSchema = z.object({
        error: z.object({
            code: z.string(),
            message: z.string(),
            details: z.record(z.any()),
            request_id: z.string()
        })
    });
    const zodByRoute = {
        "post /api/v1/auth/signup": { request: signupSchema, response: authTokensResponseSchema },
        "post /api/v1/auth/login": { request: loginSchema, response: authTokensResponseSchema },
        "post /api/v1/auth/refresh": { request: refreshSchema, response: authTokensResponseSchema },
        "post /api/v1/auth/forgot-password": { request: forgotPasswordSchema, response: okResponseSchema },
        "post /api/v1/auth/reset-password": { request: resetPasswordSchema, response: okResponseSchema },
        "post /api/v1/auth/logout": { response: okResponseSchema },
        "post /api/v1/credentials/store": { request: storeSchema, response: storeResponseSchema },
        "post /api/v1/credentials/share": { request: shareSchema, response: shareResponseSchema },
        "post /api/v1/fiat/payments/initiate": { request: fiatInitiateSchema, response: initiateResponseSchema },
        "get /api/v1/fiat/payments/{id}/status": { params: fiatPaymentIdParamsSchema, response: paymentStatusResponseSchema },
        "get /api/v1/fiat/payments/{id}/receipt": { params: fiatPaymentIdParamsSchema, query: receiptQuerySchema, response: receiptResponseSchema },
        "post /api/v1/fiat/payments/stripe/webhook": { responses: { "200": okResponseSchema, "501": notConfiguredResponseSchema } },
        "post /api/v1/fiat/payments/reconcile": { responses: { "200": reconcileResponseSchema, "501": notConfiguredResponseSchema } }
    };
    const errorEnvelopeJsonSchema = stripJsonSchemaMeta(zodToJsonSchema(errorEnvelopeSchema));
    const isRecord = (v) => !!v && typeof v === "object" && !Array.isArray(v);
    const ensureErrorResponses = (op) => {
        op.responses ??= {};
        for (const status of ["400", "401", "403", "404", "500"]) {
            op.responses[status] ??= { description: "Error", content: { "application/json": { schema: errorEnvelopeJsonSchema } } };
            op.responses[status].content ??= {};
            op.responses[status].content["application/json"] ??= { schema: errorEnvelopeJsonSchema };
        }
    };
    const addParamsFromZodObject = (op, input) => {
        const jsonSchemaUnknown = stripJsonSchemaMeta(zodToJsonSchema(input.zodSchema));
        if (!isRecord(jsonSchemaUnknown))
            return;
        const propertiesUnknown = jsonSchemaUnknown.properties;
        if (!isRecord(propertiesUnknown))
            return;
        const required = Array.isArray(jsonSchemaUnknown.required)
            ? jsonSchemaUnknown.required.filter((x) => typeof x === "string")
            : [];
        op.parameters ??= [];
        const existing = Array.isArray(op.parameters) ? op.parameters : [];
        const existingNames = new Set(existing
            .map((p) => {
            if (!isRecord(p))
                return "";
            const inValue = typeof p.in === "string" ? p.in : "";
            const nameValue = typeof p.name === "string" ? p.name : "";
            return `${inValue}:${nameValue}`;
        })
            .filter((s) => s.length));
        for (const [name, schema] of Object.entries(propertiesUnknown)) {
            const key = `${input.in}:${name}`;
            if (existingNames.has(key))
                continue;
            existing.push({ in: input.in, name, required: input.in === "path" ? true : required.includes(name), schema });
        }
        op.parameters = existing;
    };
    for (const [key, zod] of Object.entries(zodByRoute)) {
        const [method, path] = key.split(" ", 2);
        const ops = paths[path];
        if (!ops)
            continue;
        const op = ops[method];
        if (!op || typeof op !== "object")
            continue;
        if (zod.params) {
            addParamsFromZodObject(op, { zodSchema: zod.params, in: "path" });
        }
        if (zod.query) {
            addParamsFromZodObject(op, { zodSchema: zod.query, in: "query" });
        }
        if (zod.request && !op.requestBody) {
            const jsonSchema = zodToJsonSchema(zod.request);
            const schema = typeof jsonSchema === "object" && jsonSchema ? stripJsonSchemaMeta(jsonSchema) : {};
            op.requestBody = {
                required: true,
                content: {
                    "application/json": { schema }
                }
            };
        }
        op.responses ??= {};
        const addResponseSchema = (status, schemaZod) => {
            op.responses[status] ??= { description: status === "200" ? "OK" : "Response" };
            op.responses[status].content ??= {};
            if (!op.responses[status].content["application/json"]) {
                const jsonSchema = zodToJsonSchema(schemaZod);
                const schema = typeof jsonSchema === "object" && jsonSchema ? stripJsonSchemaMeta(jsonSchema) : {};
                op.responses[status].content["application/json"] = { schema };
            }
        };
        if (zod.responses) {
            for (const [status, schemaZod] of Object.entries(zod.responses)) {
                addResponseSchema(status, schemaZod);
            }
        }
        else if (zod.response) {
            addResponseSchema("200", zod.response);
        }
        ensureErrorResponses(op);
        const pathParams = extractOpenApiPathParams(path);
        if (pathParams.length) {
            op.parameters ??= [];
            const existing = Array.isArray(op.parameters) ? op.parameters : [];
            const existingNames = new Set(existing
                .map((p) => {
                if (!isRecord(p))
                    return "";
                const inValue = typeof p.in === "string" ? p.in : "";
                const nameValue = typeof p.name === "string" ? p.name : "";
                return `${inValue}:${nameValue}`;
            })
                .filter((s) => s.length));
            for (const name of pathParams) {
                const key = `path:${name}`;
                if (existingNames.has(key))
                    continue;
                existing.push({ in: "path", name, required: true, schema: { type: "string" } });
            }
            op.parameters = existing;
        }
    }
    for (const ops of Object.values(paths)) {
        for (const [method, op] of Object.entries(ops ?? {})) {
            if (!op || typeof op !== "object")
                continue;
            if (!["get", "post", "put", "patch", "delete"].includes(method))
                continue;
            ensureErrorResponses(op);
        }
    }
}
function stripJsonSchemaMeta(schema) {
    const rest = { ...(schema ?? {}) };
    if (rest && typeof rest === "object") {
        delete rest.$schema;
    }
    return rest;
}
function discoverExpressPaths(app) {
    const out = {};
    const stack = getExpressStack(app);
    walkExpressStack(stack, "", (path, method) => {
        const p = normalizeOpenApiPath(path);
        out[p] ??= {};
        const m = method.toLowerCase();
        if (!out[p][m]) {
            out[p][m] = { summary: `${method.toUpperCase()} ${p}`, responses: { 200: { description: "OK" } } };
        }
    });
    return out;
}
function getExpressStack(app) {
    const anyApp = app;
    const stack = anyApp?._router?.stack;
    return Array.isArray(stack) ? stack : [];
}
function walkExpressStack(stack, prefix, onRoute) {
    for (const layer of stack) {
        const l = layer;
        if (l.route?.path && l.route?.methods) {
            const routePath = typeof l.route.path === "string" ? l.route.path : null;
            if (!routePath)
                continue;
            const full = `${prefix}${routePath}`.replaceAll("//", "/");
            for (const [m, enabled] of Object.entries(l.route.methods)) {
                if (enabled)
                    onRoute(full, m);
            }
            continue;
        }
        const childStack = getRouterStack(l.handle);
        if (l.name === "router" && childStack.length) {
            const mount = prefix + (regexpToMountPath(l.regexp) ?? "");
            walkExpressStack(childStack, mount, onRoute);
        }
    }
}
function getRouterStack(handle) {
    const any = handle;
    return Array.isArray(any?.stack) ? any.stack : [];
}
function regexpToMountPath(re) {
    if (!re)
        return null;
    const src = re.source;
    if (src === "^\\/?$")
        return "";
    let s = src;
    s = s.replaceAll("\\/", "/");
    s = s.replace(/^\^/, "");
    s = s.replace(/\(\?=\/\|\$\)/g, "");
    s = s.replace(/\(\?=\\\/\|\$\)/g, "");
    s = s.replace(/\/\?\$$/, "");
    s = s.replace(/\$$/, "");
    s = s.replace(/\(\?:\(\[\^\/]\+\?\)\)/g, "{param}");
    s = s.replace(/\(\?:\(\[\^\\\/]\+\?\)\)/g, "{param}");
    s = s.replace(/\(\?:\[\^\/]\+\?\)/g, "{param}");
    s = s.replace(/\(\?:\[\^\\\/]\+\?\)/g, "{param}");
    if (!s.startsWith("/"))
        s = `/${s}`;
    return s;
}
function normalizeOpenApiPath(path) {
    const p = path.startsWith("/") ? path : `/${path}`;
    return p.replaceAll("//", "/").replace(/:([A-Za-z0-9_]+)/g, "{$1}");
}
function extractOpenApiPathParams(path) {
    const names = [];
    const re = /\{([A-Za-z0-9_]+)\}/g;
    for (;;) {
        const m = re.exec(path);
        if (!m)
            break;
        const name = m[1] ?? "";
        if (name && !names.includes(name))
            names.push(name);
    }
    return names;
}
//# sourceMappingURL=server.js.map