import type { AddressInfo } from "node:net";
import http from "node:http";
import crypto from "node:crypto";

import axios from "axios";
import { z } from "zod";

import { createIdentityOrchestratorConfig } from "@verza/config";
import { createPgPool, migrateDatabase } from "@verza/db";
import { badRequest, createHttpApp, errorHandler, notFound, notFoundHandler } from "@verza/http";
import { createLogger } from "@verza/observability";

const createSessionSchema = z.object({
  user_id: z.string().optional()
});

const createVerificationSchema = z.object({
  type: z.string().min(1),
  subject_id: z.string().optional()
});

const mediaSchema = z.object({
  key: z.string().min(1),
  kind: z.string().min(1)
});

const idempotencySchema = z.object({
  key: z.string().min(1)
});

export async function createIdentityOrchestratorServer() {
  const config = createIdentityOrchestratorConfig(process.env);
  const logger = createLogger({ service: "identity-orchestrator", level: config.LOG_LEVEL });
  const pool = createPgPool(config.IDENTITY_DATABASE_URL);

  await migrateDatabase({ db: "identity", databaseUrl: config.IDENTITY_DATABASE_URL, logger });

  const app = createHttpApp({ logger, corsAllowedOrigins: config.CORS_ALLOWED_ORIGINS });
  app.get("/healthz", (_req, res) => res.json({ status: "ok" }));

  const inference = axios.create({ baseURL: config.INFERENCE_URL, timeout: 60_000 });

  app.post("/internal/v1/sessions", (req, res, next) => {
    void (async () => {
      const body = createSessionSchema.parse(req.body);
      const id = crypto.randomUUID();
      await pool.query("insert into identity_sessions (id, user_id, created_at) values ($1,$2,$3)", [id, body.user_id ?? null, new Date()]);
      res.json({ id });
    })().catch(next);
  });

  app.post("/internal/v1/verifications", (req, res, next) => {
    void (async () => {
      const body = createVerificationSchema.parse(req.body);
      const id = crypto.randomUUID();
      const ts = new Date();
      await pool.query(
        "insert into identity_verifications_v2 (id, type, subject_id, status, created_at, updated_at) values ($1,$2,$3,$4,$5,$6)",
        [id, body.type, body.subject_id ?? null, "created", ts, ts]
      );
      res.json({ id, status: "created" });
    })().catch(next);
  });

  app.get("/internal/v1/verifications/:id", (req, res, next) => {
    void (async () => {
      const id = z.string().uuid().parse(req.params.id);
      const result = await pool.query<{
        id: string;
        type: string;
        subject_id: string | null;
        status: string;
        created_at: Date;
        updated_at: Date;
      }>("select * from identity_verifications_v2 where id=$1", [id]);
      const row = result.rows[0];
      if (!row) throw notFound("verification_not_found", "Verification not found");
      res.json(row);
    })().catch(next);
  });

  app.get("/internal/v1/verifications/:id/audit", (req, res, next) => {
    void (async () => {
      const id = z.string().uuid().parse(req.params.id);
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
      const id = z.string().uuid().parse(req.params.id);
      const body = mediaSchema.parse(req.body);
      await pool.query("insert into identity_media (id, verification_id, key, kind, created_at) values ($1,$2,$3,$4,$5)", [
        crypto.randomUUID(),
        id,
        body.key,
        body.kind,
        new Date()
      ]);
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
      const id = z.string().uuid().parse(req.params.id);
      const asyncFlag = typeof req.query.async === "string" ? req.query.async.toLowerCase() : "";
      const isAsync = asyncFlag === "1" || asyncFlag === "true";
      const idempotencyKey = req.header("idempotency-key") ?? null;
      if (isAsync) {
        if (!idempotencyKey) throw badRequest("missing_idempotency_key", "Missing Idempotency-Key");
        await pool.query(
          "insert into identity_idempotency (id, verification_id, key, created_at) values ($1,$2,$3,$4) on conflict (verification_id, key) do nothing",
          [crypto.randomUUID(), id, idempotencyKey, new Date()]
        );
        res.status(202).json({ status: "queued" });
        return;
      }

      await runInference({ pool, inference, verificationId: id });
      res.json({ status: "completed" });
    })().catch(next);
  });

  app.post("/internal/v1/verifications/:id/idempotency", (req, res, next) => {
    void (async () => {
      const id = z.string().uuid().parse(req.params.id);
      const body = idempotencySchema.parse(req.body);
      const result = await pool.query("select * from identity_idempotency where verification_id=$1 and key=$2 limit 1", [id, body.key]);
      res.json({ exists: (result.rowCount ?? 0) > 0 });
    })().catch(next);
  });

  app.use(notFoundHandler);
  app.use(errorHandler());

  const server = http.createServer(app);

  return {
    start: async () => {
      await new Promise<void>((resolve) => server.listen(config.PORT, config.HOST, resolve));
      logger.info({ addr: server.address() as AddressInfo }, "identity-orchestrator listening");
    }
  };
}

async function runInference(opts: { pool: ReturnType<typeof createPgPool>; inference: ReturnType<typeof axios.create>; verificationId: string }) {
  const media = await opts.pool.query<{ key: string; kind: string }>("select key, kind from identity_media where verification_id=$1", [
    opts.verificationId
  ]);
  const livenessKeys = media.rows.filter((m) => m.kind === "liveness").map((m) => m.key);
  const docKeys = media.rows.filter((m) => m.kind === "document").map((m) => m.key);

  if (livenessKeys[0]) await opts.inference.post("/v1/liveness/extract_best_frame", { key: livenessKeys[0] });
  if (docKeys[0]) await opts.inference.post("/v1/document/extract_portrait", { key: docKeys[0] });

  const ts = new Date();
  await opts.pool.query("update identity_verifications_v2 set status=$1, updated_at=$2 where id=$3", ["completed", ts, opts.verificationId]);
  await opts.pool.query("insert into identity_verification_audit_v2 (id, verification_id, type, data_json, created_at) values ($1,$2,$3,$4,$5)", [
    crypto.randomUUID(),
    opts.verificationId,
    "inference_run",
    JSON.stringify({ liveness: Boolean(livenessKeys[0]), document: Boolean(docKeys[0]) }),
    ts
  ]);
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s) as unknown;
  } catch {
    return {};
  }
}
