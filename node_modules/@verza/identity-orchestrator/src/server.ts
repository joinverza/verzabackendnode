import type { AddressInfo } from "node:net";
import http from "node:http";
import crypto from "node:crypto";

import axios from "axios";
import { HeadObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { z } from "zod";
import { createClient } from "redis";

import { requireUser } from "@verza/auth";
import { createIdentityOrchestratorConfig } from "@verza/config";
import { createPgPool, migrateDatabase } from "@verza/db";
import { badRequest, createHttpApp, errorHandler, notFound, notFoundHandler } from "@verza/http";
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

type VerificationRow = {
  id: string;
  user_id: string | null;
  type: string;
  subject_id: string | null;
  status: string;
  attempt_count: number;
  last_error: string;
  completed_at: Date | null;
  created_at: Date;
  updated_at: Date;
};

type RedisClient = {
  connect: () => Promise<void>;
  rPush: (key: string, value: string) => Promise<number>;
  blPop: (key: string, timeout: number) => Promise<{ key: string; element: string } | null>;
};

const QUEUE_KEY = "verza:identity:jobs:v1";

export async function createIdentityOrchestratorServer() {
  const config = createIdentityOrchestratorConfig(process.env);
  const logger = createLogger({ service: "identity-orchestrator", level: config.LOG_LEVEL });
  const pool = createPgPool(config.IDENTITY_DATABASE_URL);

  await migrateDatabase({ db: "identity", databaseUrl: config.IDENTITY_DATABASE_URL, logger });

  const app = createHttpApp({ logger, corsAllowedOrigins: config.CORS_ALLOWED_ORIGINS });
  app.get("/healthz", (_req, res) => res.json({ status: "ok" }));

  const inference = axios.create({ baseURL: config.INFERENCE_URL, timeout: 60_000 });

  const internalAuth = requireUser({ config });
  app.use("/internal/v1", internalAuth);

  const s3 = createS3ClientIfConfigured(config);

  const redisUrl = config.REDIS_URL && config.REDIS_URL.trim().length ? config.REDIS_URL.trim() : null;
  const createRedisClient = createClient as unknown as (options: { url: string }) => RedisClient;
  const redis = redisUrl ? createRedisClient({ url: redisUrl }) : null;

  app.post("/internal/v1/sessions", (req, res, next) => {
    void (async () => {
      const body = createSessionSchema.parse(req.body);
      const id = crypto.randomUUID();
      const userId = req.auth.role === "admin" ? (body.user_id ?? req.auth.userId) : req.auth.userId;
      await pool.query("insert into identity_sessions (id, user_id, created_at) values ($1,$2,$3)", [id, userId, new Date()]);
      res.json({ id, user_id: userId });
    })().catch(next);
  });

  app.post("/internal/v1/verifications", (req, res, next) => {
    void (async () => {
      const body = createVerificationSchema.parse(req.body);
      const id = crypto.randomUUID();
      const ts = new Date();
      await pool.query(
        "insert into identity_verifications_v2 (id, user_id, type, subject_id, status, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7)",
        [id, req.auth.userId, body.type, body.subject_id ?? null, "created", ts, ts]
      );
      await pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
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
      const result = await pool.query<VerificationRow>(
        req.auth.role === "admin"
          ? "select * from identity_verifications_v2 where id=$1 limit 1"
          : "select * from identity_verifications_v2 where id=$1 and user_id=$2 limit 1",
        req.auth.role === "admin" ? [id] : [id, req.auth.userId]
      );
      const row = result.rows[0];
      if (!row) throw notFound("verification_not_found", "Verification not found");
      res.json(row);
    })().catch(next);
  });

  app.get("/internal/v1/verifications/:id/audit", (req, res, next) => {
    void (async () => {
      const { id } = verificationIdSchema.parse(req.params);
      await assertVerificationAccess({ pool, verificationId: id, auth: req.auth });
      const result = await pool.query<{
        id: string;
        verification_id: string;
        type: string;
        data_json: string;
        created_at: Date;
      }>("select * from identity_verification_audit_v2 where verification_id=$1 order by created_at asc", [id]);
      res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
    })().catch(next);
  });

  app.post("/internal/v1/verifications/:id/media", (req, res, next) => {
    void (async () => {
      const { id } = verificationIdSchema.parse(req.params);
      const body = mediaSchema.parse(req.body);
      const verification = await assertVerificationAccess({ pool, verificationId: id, auth: req.auth });
      if (!["created", "collecting_media", "failed"].includes(verification.status)) {
        throw badRequest("invalid_state", "Cannot add media in current state");
      }
      await pool.query("insert into identity_media (id, verification_id, key, kind, created_at) values ($1,$2,$3,$4,$5)", [
        crypto.randomUUID(),
        id,
        body.key,
        body.kind,
        new Date()
      ]);
      if (verification.status === "created") {
        await pool.query("update identity_verifications_v2 set status=$1, updated_at=$2 where id=$3", ["collecting_media", new Date(), id]);
      }
      await pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
        crypto.randomUUID(),
        id,
        "media_added",
        JSON.stringify(body),
        new Date()
      ]);
      res.json({ status: "ok" });
    })().catch(next);
  });

  app.post("/internal/v1/verifications/:id/run", (req, res, next) => {
    void (async () => {
      const { id } = verificationIdSchema.parse(req.params);
      const asyncFlag = typeof req.query.async === "string" ? req.query.async.toLowerCase() : "";
      const isAsync = asyncFlag === "1" || asyncFlag === "true";
      const idempotencyKey = req.header("idempotency-key") ?? null;

      await assertVerificationAccess({ pool, verificationId: id, auth: req.auth });

      if (isAsync) {
        if (!idempotencyKey) throw badRequest("missing_idempotency_key", "Missing Idempotency-Key");
        if (!redis) throw badRequest("redis_not_configured", "Async execution requires Redis");

        const inserted = await pool.query<{ id: string }>(
          "insert into identity_idempotency (id, verification_id, key, created_at) values ($1,$2,$3,$4) on conflict (verification_id, key) do nothing returning id",
          [crypto.randomUUID(), id, idempotencyKey, new Date()]
        );
        if (!inserted.rowCount) {
          res.status(202).json({ status: "duplicate" });
          return;
        }

        const queued = await pool.query<{ id: string }>(
          "update identity_verifications_v2 set status='queued', updated_at=$1 where id=$2 and status in ('created','collecting_media','failed') returning id",
          [new Date(), id]
        );
        if (!queued.rowCount) throw badRequest("invalid_state", "Verification cannot be queued");

        await pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
          crypto.randomUUID(),
          id,
          "run_queued",
          JSON.stringify({ idempotency_key: idempotencyKey }),
          new Date()
        ]);

        await redis.rPush(
          QUEUE_KEY,
          JSON.stringify({ verification_id: id, idempotency_key: idempotencyKey, requested_by: req.auth.userId, requested_at: new Date().toISOString() })
        );
        return;
      }

      const running = await pool.query<{ id: string }>(
        "update identity_verifications_v2 set status='running', updated_at=$1 where id=$2 and status in ('created','collecting_media','failed') returning id",
        [new Date(), id]
      );
      if (!running.rowCount) throw badRequest("invalid_state", "Verification cannot be run");

      await processVerificationJob({ pool, inference, s3, verificationId: id, logger });
      res.json({ status: "completed" });
    })().catch(next);
  });

  app.post("/internal/v1/verifications/:id/idempotency", (req, res, next) => {
    void (async () => {
      const { id } = verificationIdSchema.parse(req.params);
      const body = idempotencySchema.parse(req.body);
      await assertVerificationAccess({ pool, verificationId: id, auth: req.auth });
      const result = await pool.query("select * from identity_idempotency where verification_id=$1 and key=$2 limit 1", [id, body.key]);
      res.json({ exists: (result.rowCount ?? 0) > 0 });
    })().catch(next);
  });

  app.use(notFoundHandler);
  app.use(errorHandler());

  const server = http.createServer(app);

  return {
    start: async () => {
      if (redis) {
        await redis.connect();
      }
      await new Promise<void>((resolve) => server.listen(config.PORT, config.HOST, resolve));
      logger.info({ addr: server.address() as AddressInfo }, "identity-orchestrator listening");
      if (redis) {
        startWorker({ redis, pool, inference, s3, logger });
      }
    }
  };
}

function createS3ClientIfConfigured(config: {
  S3_ENDPOINT?: string | undefined;
  S3_ACCESS_KEY_ID?: string | undefined;
  S3_SECRET_ACCESS_KEY?: string | undefined;
  S3_BUCKET?: string | undefined;
  S3_REGION?: string | undefined;
  S3_FORCE_PATH_STYLE?: boolean | undefined;
}) {
  if (
    !config.S3_ENDPOINT ||
    !config.S3_ACCESS_KEY_ID ||
    !config.S3_SECRET_ACCESS_KEY ||
    !config.S3_BUCKET ||
    !config.S3_REGION
  ) {
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

async function assertVerificationAccess(opts: { pool: ReturnType<typeof createPgPool>; verificationId: string; auth: { userId: string; role: string } }) {
  const result = await opts.pool.query<VerificationRow>(
    opts.auth.role === "admin"
      ? "select * from identity_verifications_v2 where id=$1 limit 1"
      : "select * from identity_verifications_v2 where id=$1 and user_id=$2 limit 1",
    opts.auth.role === "admin" ? [opts.verificationId] : [opts.verificationId, opts.auth.userId]
  );
  const row = result.rows[0];
  if (!row) throw notFound("verification_not_found", "Verification not found");
  return row;
}

function startWorker(opts: {
  redis: RedisClient;
  pool: ReturnType<typeof createPgPool>;
  inference: ReturnType<typeof axios.create>;
  s3: { client: S3Client; bucket: string } | null;
  logger: ReturnType<typeof createLogger>;
}) {
  void (async () => {
    for (;;) {
      const item = await opts.redis.blPop(QUEUE_KEY, 0);
      const raw = item?.element;
      if (!raw) continue;
      const job = safeJson(raw) as { verification_id?: string; idempotency_key?: string };
      if (!job || typeof job !== "object" || typeof job.verification_id !== "string") continue;

      const updated = await opts.pool.query<{ id: string }>(
        "update identity_verifications_v2 set status='running', updated_at=$1 where id=$2 and status='queued' returning id",
        [new Date(), job.verification_id]
      );
      if (!updated.rowCount) continue;

      await processVerificationJob({ pool: opts.pool, inference: opts.inference, s3: opts.s3, verificationId: job.verification_id, logger: opts.logger });
    }
  })().catch((err) => {
    opts.logger.error({ err }, "identity-orchestrator worker crashed");
  });
}

async function processVerificationJob(opts: {
  pool: ReturnType<typeof createPgPool>;
  inference: ReturnType<typeof axios.create>;
  s3: { client: S3Client; bucket: string } | null;
  verificationId: string;
  logger: ReturnType<typeof createLogger>;
}) {
  const tsStart = new Date();
  await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
    crypto.randomUUID(),
    opts.verificationId,
    "inference_started",
    JSON.stringify({ at: tsStart.toISOString() }),
    tsStart
  ]);

  try {
    const media = await opts.pool.query<{ key: string; kind: string }>("select key, kind from identity_media where verification_id=$1", [opts.verificationId]);
    const livenessKey = media.rows.find((m) => m.kind === "liveness")?.key ?? null;
    const documentKey = media.rows.find((m) => m.kind === "document")?.key ?? null;
    if (!livenessKey && !documentKey) throw new Error("No media uploaded");

    if (opts.s3) {
      for (const key of [livenessKey, documentKey].filter((k): k is string => typeof k === "string" && k.length > 0)) {
        await opts.s3.client.send(new HeadObjectCommand({ Bucket: opts.s3.bucket, Key: key }));
      }
    }

    const outputs: Array<{ kind: string; data: unknown }> = [];
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
      await opts.pool.query(
        "insert into identity_inference_outputs_v2 (id, verification_id, kind, output_json, created_at) values ($1,$2,$3,$4,$5)",
        [crypto.randomUUID(), opts.verificationId, out.kind, JSON.stringify(out.data ?? {}), ts]
      );
    }

    const decision = buildDecision({ hasLiveness: Boolean(livenessKey), hasDocument: Boolean(documentKey), outputs });
    await opts.pool.query(
      "insert into identity_verification_decisions_v2 (id, verification_id, status, scores_json, reasons_json, signals_json, created_at) values ($1,$2,$3,$4,$5,$6,$7)",
      [crypto.randomUUID(), opts.verificationId, decision.status, JSON.stringify(decision.scores), JSON.stringify(decision.reasons), JSON.stringify(decision.signals), ts]
    );

    await opts.pool.query(
      "update identity_verifications_v2 set status='completed', attempt_count=attempt_count+1, last_error='', completed_at=$1, updated_at=$2 where id=$3",
      [ts, ts, opts.verificationId]
    );
    await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
      crypto.randomUUID(),
      opts.verificationId,
      "inference_completed",
      JSON.stringify({ outputs: outputs.map((o) => o.kind), decision }),
      ts
    ]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    const ts = new Date();
    await opts.pool.query(
      "update identity_verifications_v2 set status='failed', attempt_count=attempt_count+1, last_error=$1, updated_at=$2 where id=$3",
      [msg, ts, opts.verificationId]
    );
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

function buildDecision(opts: {
  hasLiveness: boolean;
  hasDocument: boolean;
  outputs: Array<{ kind: string; data: unknown }>;
}): { status: string; scores: Record<string, number>; reasons: string[]; signals: Record<string, unknown> } {
  const scores: Record<string, number> = {
    liveness_present: opts.hasLiveness ? 1 : 0,
    document_present: opts.hasDocument ? 1 : 0
  };
  const reasons: string[] = [];
  if (!opts.hasLiveness) reasons.push("missing_liveness");
  if (!opts.hasDocument) reasons.push("missing_document");
  const status = reasons.length ? "needs_review" : "passed";
  const signals: Record<string, unknown> = {
    outputs: opts.outputs.reduce<Record<string, unknown>>((acc, o) => {
      acc[o.kind] = o.data ?? {};
      return acc;
    }, {})
  };
  return { status, scores, reasons, signals };
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s) as unknown;
  } catch {
    return {};
  }
}
