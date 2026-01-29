import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import fs from "node:fs";
import axios from "axios";
import { HeadObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { z } from "zod";
import { createClient } from "redis";
import promClient from "prom-client";
import { requireUser } from "@verza/auth";
import { createIdentityOrchestratorConfig } from "@verza/config";
import { createPgPool, migrateDatabase } from "@verza/db";
import { badRequest, createHttpApp, createRateLimiter, errorHandler, notFound, notFoundHandler } from "@verza/http";
import { createLogger } from "@verza/observability";
const createSessionSchema = z.object({
    user_id: z.string().uuid().optional()
});
const createVerificationSchema = z.object({
    type: z.string().min(1),
    subject_id: z.string().optional()
});
const mediaSchema = z.object({
    key: z.string().min(1),
    kind: z.enum(["liveness", "document"])
});
const idempotencySchema = z.object({
    key: z.string().min(1)
});
const verificationIdSchema = z.object({ id: z.string().uuid() });
const QUEUE_KEY = "verza:identity:jobs:v1";
export async function createIdentityOrchestratorServer() {
    const config = createIdentityOrchestratorConfig(process.env);
    const logger = createLogger({ service: "identity-orchestrator", level: config.LOG_LEVEL });
    const pool = createPgPool(config.IDENTITY_DATABASE_URL);
    await migrateDatabase({ db: "identity", databaseUrl: config.IDENTITY_DATABASE_URL, logger });
    if (config.IDENTITY_RETENTION_DAYS && config.IDENTITY_RETENTION_DAYS > 0) {
        await purgeOrchestratorRetention({ pool, days: config.IDENTITY_RETENTION_DAYS, logger });
    }
    const inference = axios.create({ baseURL: config.INFERENCE_URL, timeout: 60_000 });
    const s3 = createS3ClientIfConfigured(config);
    const redisUrl = config.REDIS_URL && config.REDIS_URL.trim().length ? config.REDIS_URL.trim() : null;
    const createRedisClient = createClient;
    const redis = redisUrl ? createRedisClient({ url: redisUrl }) : null;
    const app = createIdentityOrchestratorApp({ config, logger, pool, inference, redis, s3 });
    const server = createHttpOrHttpsServer(app, config);
    return {
        start: async () => {
            if (redis && !redis.isOpen)
                await redis.connect();
            await new Promise((resolve) => server.listen(config.PORT, config.HOST, resolve));
            const addr = server.address();
            logger.info({ addr }, "identity-orchestrator listening");
            if (redis)
                startWorker({ redis, pool, inference, s3, logger });
            return addr;
        },
        stop: async () => {
            await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
            if (redis?.isOpen)
                await redis.quit();
            await pool.end();
        }
    };
}
export function createIdentityOrchestratorApp(opts) {
    const app = createHttpApp({ logger: opts.logger, corsAllowedOrigins: opts.config.CORS_ALLOWED_ORIGINS ?? [] });
    app.get("/healthz", (_req, res) => res.json({ status: "ok" }));
    if (opts.config.METRICS_ENABLED) {
        const register = new promClient.Registry();
        register.setDefaultLabels({ service: "identity-orchestrator" });
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
    const internalAuth = requireUser({ config: opts.config });
    app.use("/internal/v1", internalAuth);
    const limiterKey = (req) => (req.auth?.userId ? `u:${req.auth.userId}` : `ip:${req.ip}`);
    app.post("/internal/v1/sessions", createRateLimiter({ windowMs: 60_000, limit: 60, keyGenerator: limiterKey }), (req, res, next) => {
        void (async () => {
            const body = createSessionSchema.parse(req.body);
            const id = crypto.randomUUID();
            const userId = req.auth.role === "admin" ? (body.user_id ?? req.auth.userId) : req.auth.userId;
            await opts.pool.query("insert into identity_sessions (id, user_id, created_at) values ($1,$2,$3)", [id, userId, new Date()]);
            res.json({ id, user_id: userId });
        })().catch(next);
    });
    app.post("/internal/v1/verifications", createRateLimiter({ windowMs: 60_000, limit: 30, keyGenerator: limiterKey }), (req, res, next) => {
        void (async () => {
            const body = createVerificationSchema.parse(req.body);
            const id = crypto.randomUUID();
            const ts = new Date();
            await opts.pool.query("insert into identity_verifications_v2 (id, user_id, type, subject_id, status, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7)", [id, req.auth.userId, body.type, body.subject_id ?? null, "created", ts, ts]);
            await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
                crypto.randomUUID(),
                id,
                "verification_created",
                JSON.stringify({ type: body.type, subject_id: body.subject_id ?? null }),
                ts
            ]);
            res.json({ id, status: "created" });
        })().catch(next);
    });
    app.get("/internal/v1/verifications/:id", (req, res, next) => {
        void (async () => {
            const { id } = verificationIdSchema.parse(req.params);
            const result = await opts.pool.query(req.auth.role === "admin"
                ? "select * from identity_verifications_v2 where id=$1 limit 1"
                : "select * from identity_verifications_v2 where id=$1 and user_id=$2 limit 1", req.auth.role === "admin" ? [id] : [id, req.auth.userId]);
            const row = result.rows[0];
            if (!row)
                throw notFound("verification_not_found", "Verification not found");
            res.json(row);
        })().catch(next);
    });
    app.get("/internal/v1/verifications/:id/audit", (req, res, next) => {
        void (async () => {
            const { id } = verificationIdSchema.parse(req.params);
            await assertVerificationAccess({ pool: opts.pool, verificationId: id, auth: req.auth });
            const result = await opts.pool.query("select * from identity_verification_audit_v2 where verification_id=$1 order by created_at asc", [id]);
            res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
        })().catch(next);
    });
    app.post("/internal/v1/verifications/:id/media", createRateLimiter({ windowMs: 60_000, limit: 120, keyGenerator: limiterKey }), (req, res, next) => {
        void (async () => {
            const { id } = verificationIdSchema.parse(req.params);
            const body = mediaSchema.parse(req.body);
            const verification = await assertVerificationAccess({ pool: opts.pool, verificationId: id, auth: req.auth });
            if (!["created", "collecting_media", "failed"].includes(verification.status)) {
                throw badRequest("invalid_state", "Cannot add media in current state");
            }
            await opts.pool.query("insert into identity_media (id, verification_id, key, kind, created_at) values ($1,$2,$3,$4,$5)", [
                crypto.randomUUID(),
                id,
                body.key,
                body.kind,
                new Date()
            ]);
            if (verification.status === "created") {
                await opts.pool.query("update identity_verifications_v2 set status=$1, updated_at=$2 where id=$3", ["collecting_media", new Date(), id]);
            }
            await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
                crypto.randomUUID(),
                id,
                "media_added",
                JSON.stringify(body),
                new Date()
            ]);
            res.json({ status: "ok" });
        })().catch(next);
    });
    app.post("/internal/v1/verifications/:id/run", createRateLimiter({ windowMs: 60_000, limit: 20, keyGenerator: limiterKey }), (req, res, next) => {
        void (async () => {
            const { id } = verificationIdSchema.parse(req.params);
            const asyncFlag = typeof req.query.async === "string" ? req.query.async.toLowerCase() : "";
            const isAsync = asyncFlag === "1" || asyncFlag === "true";
            const idempotencyKey = req.header("idempotency-key") ?? null;
            await assertVerificationAccess({ pool: opts.pool, verificationId: id, auth: req.auth });
            if (isAsync) {
                if (!idempotencyKey)
                    throw badRequest("missing_idempotency_key", "Missing Idempotency-Key");
                if (!opts.redis)
                    throw badRequest("redis_not_configured", "Async execution requires Redis");
                const inserted = await opts.pool.query("insert into identity_idempotency (id, verification_id, key, created_at) values ($1,$2,$3,$4) on conflict (verification_id, key) do nothing returning id", [crypto.randomUUID(), id, idempotencyKey, new Date()]);
                if (!inserted.rowCount) {
                    res.status(202).json({ status: "duplicate" });
                    return;
                }
                const queued = await opts.pool.query("update identity_verifications_v2 set status='queued', updated_at=$1 where id=$2 and status in ('created','collecting_media','failed') returning id", [new Date(), id]);
                if (!queued.rowCount)
                    throw badRequest("invalid_state", "Verification cannot be queued");
                await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
                    crypto.randomUUID(),
                    id,
                    "run_queued",
                    JSON.stringify({ idempotency_key: idempotencyKey }),
                    new Date()
                ]);
                await opts.redis.rPush(QUEUE_KEY, JSON.stringify({ verification_id: id, idempotency_key: idempotencyKey, requested_by: req.auth.userId, requested_at: new Date().toISOString() }));
                res.status(202).json({ status: "queued" });
                return;
            }
            const running = await opts.pool.query("update identity_verifications_v2 set status='running', updated_at=$1 where id=$2 and status in ('created','collecting_media','failed') returning id", [new Date(), id]);
            if (!running.rowCount)
                throw badRequest("invalid_state", "Verification cannot be run");
            await processVerificationJob({ pool: opts.pool, inference: opts.inference, s3: opts.s3, verificationId: id, logger: opts.logger });
            res.json({ status: "completed" });
        })().catch(next);
    });
    app.post("/internal/v1/verifications/:id/idempotency", createRateLimiter({ windowMs: 60_000, limit: 120, keyGenerator: limiterKey }), (req, res, next) => {
        void (async () => {
            const { id } = verificationIdSchema.parse(req.params);
            const body = idempotencySchema.parse(req.body);
            await assertVerificationAccess({ pool: opts.pool, verificationId: id, auth: req.auth });
            const result = await opts.pool.query("select * from identity_idempotency where verification_id=$1 and key=$2 limit 1", [id, body.key]);
            res.json({ exists: (result.rowCount ?? 0) > 0 });
        })().catch(next);
    });
    app.use(notFoundHandler);
    app.use(errorHandler());
    return app;
}
function createHttpOrHttpsServer(app, config) {
    const keyPath = String(config.TLS_KEY_PATH ?? "").trim();
    const certPath = String(config.TLS_CERT_PATH ?? "").trim();
    const caPath = String(config.TLS_CA_PATH ?? "").trim();
    const requireClientCert = Boolean(config.TLS_REQUIRE_CLIENT_CERT);
    if (requireClientCert && (!keyPath || !certPath)) {
        throw new Error("TLS_REQUIRE_CLIENT_CERT requires TLS_KEY_PATH and TLS_CERT_PATH");
    }
    if (!keyPath || !certPath)
        return http.createServer(app);
    const key = fs.readFileSync(keyPath);
    const cert = fs.readFileSync(certPath);
    const ca = caPath ? fs.readFileSync(caPath) : undefined;
    if (requireClientCert && !ca) {
        throw new Error("TLS_REQUIRE_CLIENT_CERT requires TLS_CA_PATH");
    }
    return https.createServer({
        key,
        cert,
        ...(ca ? { ca } : {}),
        ...(requireClientCert ? { requestCert: true, rejectUnauthorized: true } : {})
    }, app);
}
function createS3ClientIfConfigured(config) {
    if (!config.S3_ENDPOINT ||
        !config.S3_ACCESS_KEY_ID ||
        !config.S3_SECRET_ACCESS_KEY ||
        !config.S3_BUCKET ||
        !config.S3_REGION) {
        return null;
    }
    return {
        bucket: config.S3_BUCKET,
        client: new S3Client({
            region: config.S3_REGION,
            endpoint: config.S3_ENDPOINT,
            forcePathStyle: config.S3_FORCE_PATH_STYLE ?? false,
            credentials: {
                accessKeyId: config.S3_ACCESS_KEY_ID,
                secretAccessKey: config.S3_SECRET_ACCESS_KEY
            }
        })
    };
}
async function assertVerificationAccess(opts) {
    const result = await opts.pool.query(opts.auth.role === "admin"
        ? "select * from identity_verifications_v2 where id=$1 limit 1"
        : "select * from identity_verifications_v2 where id=$1 and user_id=$2 limit 1", opts.auth.role === "admin" ? [opts.verificationId] : [opts.verificationId, opts.auth.userId]);
    const row = result.rows[0];
    if (!row)
        throw notFound("verification_not_found", "Verification not found");
    return row;
}
function startWorker(opts) {
    void (async () => {
        for (;;) {
            const item = await opts.redis.blPop(QUEUE_KEY, 0);
            const raw = item?.element;
            if (!raw)
                continue;
            const job = safeJson(raw);
            if (!job || typeof job !== "object" || typeof job.verification_id !== "string")
                continue;
            const updated = await opts.pool.query("update identity_verifications_v2 set status='running', updated_at=$1 where id=$2 and status='queued' returning id", [new Date(), job.verification_id]);
            if (!updated.rowCount)
                continue;
            await processVerificationJob({ pool: opts.pool, inference: opts.inference, s3: opts.s3, verificationId: job.verification_id, logger: opts.logger });
        }
    })().catch((err) => {
        opts.logger.error({ err }, "identity-orchestrator worker crashed");
    });
}
async function processVerificationJob(opts) {
    const tsStart = new Date();
    await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
        crypto.randomUUID(),
        opts.verificationId,
        "inference_started",
        JSON.stringify({ at: tsStart.toISOString() }),
        tsStart
    ]);
    try {
        const media = await opts.pool.query("select key, kind from identity_media where verification_id=$1", [opts.verificationId]);
        const livenessKey = media.rows.find((m) => m.kind === "liveness")?.key ?? null;
        const documentKey = media.rows.find((m) => m.kind === "document")?.key ?? null;
        if (!livenessKey && !documentKey)
            throw new Error("No media uploaded");
        if (opts.s3) {
            for (const key of [livenessKey, documentKey].filter((k) => typeof k === "string" && k.length > 0)) {
                await opts.s3.client.send(new HeadObjectCommand({ Bucket: opts.s3.bucket, Key: key }));
            }
        }
        const outputs = [];
        if (livenessKey) {
            const resp = await opts.inference.post("/v1/liveness/extract_best_frame", { key: livenessKey });
            outputs.push({ kind: "liveness_extract_best_frame", data: resp.data });
        }
        if (documentKey) {
            const resp = await opts.inference.post("/v1/document/extract_portrait", { key: documentKey });
            outputs.push({ kind: "document_extract_portrait", data: resp.data });
        }
        const ts = new Date();
        for (const out of outputs) {
            await opts.pool.query("insert into identity_inference_outputs_v2 (id, verification_id, kind, output_json, created_at) values ($1,$2,$3,$4,$5)", [crypto.randomUUID(), opts.verificationId, out.kind, JSON.stringify(out.data ?? {}), ts]);
        }
        const decision = buildDecision({ hasLiveness: Boolean(livenessKey), hasDocument: Boolean(documentKey), outputs });
        await opts.pool.query("insert into identity_verification_decisions_v2 (id, verification_id, status, scores_json, reasons_json, signals_json, created_at) values ($1,$2,$3,$4,$5,$6,$7)", [crypto.randomUUID(), opts.verificationId, decision.status, JSON.stringify(decision.scores), JSON.stringify(decision.reasons), JSON.stringify(decision.signals), ts]);
        await opts.pool.query("update identity_verifications_v2 set status='completed', attempt_count=attempt_count+1, last_error='', completed_at=$1, updated_at=$2 where id=$3", [ts, ts, opts.verificationId]);
        await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
            crypto.randomUUID(),
            opts.verificationId,
            "inference_completed",
            JSON.stringify({ outputs: outputs.map((o) => o.kind), decision }),
            ts
        ]);
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        const ts = new Date();
        await opts.pool.query("update identity_verifications_v2 set status='failed', attempt_count=attempt_count+1, last_error=$1, updated_at=$2 where id=$3", [msg, ts, opts.verificationId]);
        await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
            crypto.randomUUID(),
            opts.verificationId,
            "inference_failed",
            JSON.stringify({ error: msg }),
            ts
        ]);
        opts.logger.error({ err, verification_id: opts.verificationId }, "inference failed");
        throw err;
    }
}
function buildDecision(opts) {
    const scores = {
        liveness_present: opts.hasLiveness ? 1 : 0,
        document_present: opts.hasDocument ? 1 : 0
    };
    const reasons = [];
    if (!opts.hasLiveness)
        reasons.push("missing_liveness");
    if (!opts.hasDocument)
        reasons.push("missing_document");
    const status = reasons.length ? "needs_review" : "passed";
    const signals = {
        outputs: opts.outputs.reduce((acc, o) => {
            acc[o.kind] = o.data ?? {};
            return acc;
        }, {})
    };
    return { status, scores, reasons, signals };
}
function safeJson(s) {
    try {
        return JSON.parse(s);
    }
    catch {
        return {};
    }
}
async function purgeOrchestratorRetention(opts) {
    try {
        const days = Math.max(0, Math.floor(opts.days));
        if (!days)
            return;
        await opts.pool.query("delete from identity_sessions where created_at < now() - ($1::int * interval '1 day')", [days]);
        await opts.pool.query("delete from identity_verifications_v2 where updated_at < now() - ($1::int * interval '1 day') and status in ('completed','failed')", [days]);
    }
    catch (err) {
        opts.logger.error({ err }, "identity retention purge failed");
    }
}
//# sourceMappingURL=server.js.map