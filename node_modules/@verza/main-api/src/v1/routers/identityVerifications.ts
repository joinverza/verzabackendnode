import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { badRequest, createRateLimiter, forbidden, notFound } from "@verza/http";

import type { MainApiContext } from "../routes.js";
import { appendAuditEvent } from "./auditLog.js";

const requestSchema = z.object({
  credential_id: z.string().uuid().optional(),
  provider: z.string().default("internal"),
  document_type: z.string().optional(),
  confidence_threshold: z.number().min(0).max(1).default(0.98),
  locale: z.string().optional()
});

const idSchema = z.object({ id: z.string().uuid() });

const completeSchema = z.object({
  status: z.enum(["approved", "rejected", "completed"]).default("completed"),
  scores: z.record(z.string(), z.number()).default({}),
  reasons: z.array(z.string()).default([]),
  signals: z.record(z.string(), z.unknown()).default({}),
  verifier_institution_id: z.string().uuid().optional(),
  standard: z.string().optional(),
  verifier_reference: z.string().optional()
});

const presignSchema = z.object({
  key: z.string().min(1),
  content_type: z.string().min(1)
});

const addMediaSchema = z.object({
  key: z.string().min(1),
  kind: z.enum(["liveness", "document"])
});

export function createIdentityVerificationsRouter(ctx: MainApiContext): Router {
  const router = express.Router();
  const limiterKey = (req: express.Request) => (req.auth?.userId ? `u:${req.auth.userId}` : `ip:${req.ip}`);

  router.post("/request", createRateLimiter({ windowMs: 60_000, limit: 20, keyGenerator: limiterKey }), async (req, res, next) => {
    try {
      const body = requestSchema.parse(req.body ?? {});
      const id = crypto.randomUUID();
      const now = new Date();

      const gatewayUrl = String(ctx.config.IDENTITY_GATEWAY_URL ?? "").trim();
      const shouldUseOrchestrator = body.provider === "orchestrator" && gatewayUrl.length > 0;
      let providerReference = "";
      if (shouldUseOrchestrator) {
        const resp = await identityGatewayJson({
          baseUrl: gatewayUrl,
          path: "/v1/verifications",
          method: "POST",
          headers: passthroughHeaders(req),
          body: { type: body.document_type ?? "kyc", subject_id: body.credential_id ?? undefined }
        });
        providerReference = getStringProp(resp, "id") ?? "";
        if (!providerReference) throw badRequest("identity_gateway_error", "Failed to create verification");
      }

      await ctx.pool.query(
        "insert into identity_verifications (id,tenant_id,user_id,credential_id,status,provider,document_type,confidence_threshold,scores_json,reasons_json,signals_json,locale,client_timestamp,geo_lat,geo_lon,ip,user_agent,server_received_at,standard,verifier_reference) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
        [
          id,
          req.auth.tenantId,
          req.auth.userId,
          body.credential_id ?? null,
          "pending",
          shouldUseOrchestrator ? "orchestrator" : body.provider,
          body.document_type ?? "",
          body.confidence_threshold,
          "{}",
          "[]",
          "{}",
          body.locale ?? "",
          null,
          0,
          0,
          req.ip,
          String(req.headers["user-agent"] ?? ""),
          now,
          shouldUseOrchestrator ? "orchestrator_v2" : "",
          providerReference
        ]
      );
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,tenant_id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)",
        [
          crypto.randomUUID(),
          req.auth.tenantId,
          id,
          req.auth.userId,
          "requested",
          JSON.stringify({ provider: shouldUseOrchestrator ? "orchestrator" : body.provider, verifier_reference: providerReference }),
          now
        ]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "identity_verification_requested",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "identity_verification",
        subjectId: id,
        data: { provider: shouldUseOrchestrator ? "orchestrator" : body.provider, document_type: body.document_type ?? "", verifier_reference: providerReference || undefined }
      });

      res.status(201).json({ id, status: "pending", verifier_reference: providerReference || undefined });
    } catch (err) {
      next(err);
    }
  });

  router.get("/", async (req, res, next) => {
    try {
      const result = await ctx.pool.query(
        "select id,user_id,credential_id,status,provider,document_type,confidence_threshold,locale,server_received_at,completed_at,verifier_institution_id,standard,verifier_reference from identity_verifications where tenant_id=$1 and user_id=$2 order by server_received_at desc",
        [req.auth.tenantId, req.auth.userId]
      );
      res.json(result.rows);
    } catch (err) {
      next(err);
    }
  });

  router.get("/:id", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const isAdmin = req.auth.role === "admin";
      const result = await ctx.pool.query("select * from identity_verifications where id=$1 and tenant_id=$2 and ($3::boolean = true or user_id=$4) limit 1", [
        id,
        req.auth.tenantId,
        isAdmin,
        req.auth.userId
      ]);
      const row = result.rows[0];
      if (!row) throw notFound("identity_verification_not_found", "Identity verification not found");
      const gatewayUrl = String(ctx.config.IDENTITY_GATEWAY_URL ?? "").trim();
      const providerRef = typeof row.verifier_reference === "string" ? row.verifier_reference : "";
      if (row.provider === "orchestrator" && providerRef && gatewayUrl.length) {
        const remote = await identityGatewayJson({
          baseUrl: gatewayUrl,
          path: `/v1/verifications/${encodeURIComponent(providerRef)}`,
          method: "GET",
          headers: passthroughHeaders(req)
        });
        const remoteStatus = getStringProp(remote, "status") ?? "";
        const mapped = mapOrchestratorStatus(remoteStatus);
        if (mapped && mapped !== row.status) {
          await ctx.pool.query(
            "update identity_verifications set status=$1, completed_at=case when $1<>'pending' then coalesce(completed_at,$2) else completed_at end where id=$3 and tenant_id=$4",
            [mapped, new Date(), id, req.auth.tenantId]
          );
          row.status = mapped;
        }
      }
      res.json({
        ...row,
        scores: safeJson(row.scores_json),
        reasons: safeJson(row.reasons_json),
        signals: safeJson(row.signals_json)
      });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:id/audit", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const isAdmin = req.auth.role === "admin";
      const result = await ctx.pool.query(
        "select id,verification_id,user_id,event_type,data_json,created_at from identity_verification_audit_events where verification_id=$1 and tenant_id=$2 and ($3::boolean = true or user_id=$4) order by created_at asc",
        [id, req.auth.tenantId, isAdmin, req.auth.userId]
      );
      const local = result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) }));

      const gatewayUrl = String(ctx.config.IDENTITY_GATEWAY_URL ?? "").trim();
      const verification = await ctx.pool.query<{ provider: string; verifier_reference: string }>(
        "select provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2 and ($3::boolean = true or user_id=$4) limit 1",
        [id, req.auth.tenantId, isAdmin, req.auth.userId]
      );
      const row = verification.rows[0];
      if (!row || row.provider !== "orchestrator" || !row.verifier_reference || !gatewayUrl.length) {
        res.json(local);
        return;
      }

      const remote = await identityGatewayJson({
        baseUrl: gatewayUrl,
        path: `/v1/verifications/${encodeURIComponent(row.verifier_reference)}/audit`,
        method: "GET",
        headers: passthroughHeaders(req)
      });
      const remoteArr = Array.isArray(remote) ? remote : [];
      const mapped = remoteArr.map((r) => ({
        id: typeof r?.id === "string" ? r.id : crypto.randomUUID(),
        verification_id: id,
        user_id: req.auth.userId,
        event_type: typeof r?.type === "string" ? r.type : "orchestrator_event",
        data: r?.data ?? {},
        created_at: r?.created_at ?? new Date().toISOString()
      }));
      const merged = [...local, ...mapped].sort((a: any, b: any) => String(a.created_at).localeCompare(String(b.created_at)));
      res.json(merged);
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/media/presign", createRateLimiter({ windowMs: 60_000, limit: 60, keyGenerator: limiterKey }), async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const body = presignSchema.parse(req.body ?? {});
      const gatewayUrl = String(ctx.config.IDENTITY_GATEWAY_URL ?? "").trim();
      if (!gatewayUrl.length) throw badRequest("identity_gateway_not_configured", "Identity gateway not configured");
      const ver = await ctx.pool.query<{ provider: string; verifier_reference: string }>(
        "select provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2 and user_id=$3 limit 1",
        [id, req.auth.tenantId, req.auth.userId]
      );
      const row = ver.rows[0];
      if (!row || row.provider !== "orchestrator" || !row.verifier_reference) throw notFound("identity_verification_not_found", "Identity verification not found");
      const resp = await identityGatewayJson({
        baseUrl: gatewayUrl,
        path: "/v1/media/presign",
        method: "POST",
        headers: passthroughHeaders(req),
        body
      });
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,tenant_id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)",
        [crypto.randomUUID(), req.auth.tenantId, id, req.auth.userId, "media_presign", JSON.stringify({ key: body.key, content_type: body.content_type }), new Date()]
      );
      res.json(resp);
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/media", createRateLimiter({ windowMs: 60_000, limit: 120, keyGenerator: limiterKey }), async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const body = addMediaSchema.parse(req.body ?? {});
      const gatewayUrl = String(ctx.config.IDENTITY_GATEWAY_URL ?? "").trim();
      if (!gatewayUrl.length) throw badRequest("identity_gateway_not_configured", "Identity gateway not configured");
      const ver = await ctx.pool.query<{ provider: string; verifier_reference: string }>(
        "select provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2 and user_id=$3 limit 1",
        [id, req.auth.tenantId, req.auth.userId]
      );
      const row = ver.rows[0];
      if (!row || row.provider !== "orchestrator" || !row.verifier_reference) throw notFound("identity_verification_not_found", "Identity verification not found");
      const resp = await identityGatewayJson({
        baseUrl: gatewayUrl,
        path: `/v1/verifications/${encodeURIComponent(row.verifier_reference)}/media`,
        method: "POST",
        headers: passthroughHeaders(req),
        body
      });
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,tenant_id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)",
        [crypto.randomUUID(), req.auth.tenantId, id, req.auth.userId, "media_added", JSON.stringify(body), new Date()]
      );
      res.json(resp);
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/run", createRateLimiter({ windowMs: 60_000, limit: 30, keyGenerator: limiterKey }), async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const gatewayUrl = String(ctx.config.IDENTITY_GATEWAY_URL ?? "").trim();
      if (!gatewayUrl.length) throw badRequest("identity_gateway_not_configured", "Identity gateway not configured");
      const ver = await ctx.pool.query<{ provider: string; verifier_reference: string }>(
        "select provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2 and user_id=$3 limit 1",
        [id, req.auth.tenantId, req.auth.userId]
      );
      const row = ver.rows[0];
      if (!row || row.provider !== "orchestrator" || !row.verifier_reference) throw notFound("identity_verification_not_found", "Identity verification not found");
      const asyncFlag = typeof req.query.async === "string" ? req.query.async.toLowerCase() : "";
      const isAsync = asyncFlag === "1" || asyncFlag === "true";
      const idempotencyKey = req.header("idempotency-key") ?? null;
      const resp = await identityGatewayJson({
        baseUrl: gatewayUrl,
        path: `/v1/verifications/${encodeURIComponent(row.verifier_reference)}/run${isAsync ? "?async=1" : ""}`,
        method: "POST",
        headers: { ...passthroughHeaders(req), ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}) }
      });
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,tenant_id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)",
        [crypto.randomUUID(), req.auth.tenantId, id, req.auth.userId, "run_requested", JSON.stringify({ async: isAsync }), new Date()]
      );
      res.json(resp);
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/complete", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const body = completeSchema.parse(req.body ?? {});
      const now = new Date();

      if (req.auth.role !== "admin") throw forbidden("forbidden", "Admin required");

      const existing = await ctx.pool.query<{ id: string; user_id: string; status: string }>(
        "select id,user_id,status from identity_verifications where id=$1 and tenant_id=$2 limit 1",
        [id, req.auth.tenantId]
      );
      const row = existing.rows[0];
      if (!row) throw notFound("identity_verification_not_found", "Identity verification not found");
      if (row.status !== "pending") throw badRequest("invalid_status_transition", "Only pending verifications can be completed");

      await ctx.pool.query(
        "update identity_verifications set status=$1, scores_json=$2, reasons_json=$3, signals_json=$4, completed_at=$5, verifier_institution_id=coalesce($6,verifier_institution_id), standard=coalesce($7,standard), verifier_reference=coalesce($8,verifier_reference) where id=$9 and tenant_id=$10",
        [
          body.status,
          JSON.stringify(body.scores),
          JSON.stringify(body.reasons),
          JSON.stringify(body.signals),
          now,
          body.verifier_institution_id ?? null,
          body.standard ?? null,
          body.verifier_reference ?? null,
          id,
          req.auth.tenantId
        ]
      );
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,tenant_id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)",
        [
          crypto.randomUUID(),
          req.auth.tenantId,
          id,
          row.user_id,
          "completed_admin",
          JSON.stringify({ status: body.status, actor_user_id: req.auth.userId }),
          now
        ]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "identity_verification_completed",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "identity_verification",
        subjectId: id,
        data: { status: body.status, user_id: row.user_id, verifier_institution_id: body.verifier_institution_id ?? null, standard: body.standard ?? null }
      });
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/status", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const isAdmin = req.auth.role === "admin";
      const result = await ctx.pool.query<{ status: string; provider: string; verifier_reference: string }>(
        "select status, provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2 and ($3::boolean = true or user_id=$4) limit 1",
        [id, req.auth.tenantId, isAdmin, req.auth.userId]
      );
      const row = result.rows[0];
      if (row) {
        const gatewayUrl = String(ctx.config.IDENTITY_GATEWAY_URL ?? "").trim();
        if (row.provider === "orchestrator" && row.verifier_reference && gatewayUrl.length) {
          const remote = await identityGatewayJson({
            baseUrl: gatewayUrl,
            path: `/v1/verifications/${encodeURIComponent(row.verifier_reference)}`,
            method: "GET",
            headers: passthroughHeaders(req)
          });
          const remoteStatus = getStringProp(remote, "status") ?? "";
          const mapped = mapOrchestratorStatus(remoteStatus);
          if (mapped && mapped !== row.status) {
            await ctx.pool.query(
              "update identity_verifications set status=$1, completed_at=case when $1<>'pending' then coalesce(completed_at,$2) else completed_at end where id=$3 and tenant_id=$4",
              [mapped, new Date(), id, req.auth.tenantId]
            );
            res.json({ id, status: mapped });
            return;
          }
        }
        res.json({ id, status: row.status });
        return;
      }
      if (!isAdmin) throw notFound("identity_verification_not_found", "Identity verification not found");
      const adminResult = await ctx.pool.query<{ status: string }>("select status from identity_verifications where id=$1 and tenant_id=$2 limit 1", [
        id,
        req.auth.tenantId
      ]);
      const adminRow = adminResult.rows[0];
      if (!adminRow) throw notFound("identity_verification_not_found", "Identity verification not found");
      res.json({ id, status: adminRow.status });
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/cancel", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const now = new Date();
      const updated = await ctx.pool.query(
        "update identity_verifications set status='cancelled' where id=$1 and tenant_id=$2 and user_id=$3 and status='pending'",
        [id, req.auth.tenantId, req.auth.userId]
      );
      if (!updated.rowCount) throw notFound("identity_verification_not_found", "Identity verification not found");
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,tenant_id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)",
        [crypto.randomUUID(), req.auth.tenantId, id, req.auth.userId, "cancelled", "{}", now]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "identity_verification_cancelled",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "identity_verification",
        subjectId: id,
        data: {}
      });
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.use((_req, _res, next) => next(badRequest("invalid_route", "Invalid identity verifications route")));

  return router;
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}

function passthroughHeaders(req: express.Request): Record<string, string> {
  const out: Record<string, string> = {};
  const requestId = req.header("x-request-id");
  if (requestId && requestId.trim().length) out["x-request-id"] = requestId;
  const traceparent = req.header("traceparent");
  if (traceparent && traceparent.trim().length) out.traceparent = traceparent;
  const auth = req.header("authorization");
  if (auth && auth.trim().length) out.authorization = auth;
  return out;
}

async function identityGatewayJson(opts: {
  baseUrl: string;
  path: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: unknown;
}): Promise<unknown> {
  const url = `${opts.baseUrl.replace(/\/+$/, "")}${opts.path}`;
  const init: RequestInit = {
    method: opts.method,
    headers: { "content-type": "application/json", ...opts.headers },
    ...(opts.method === "POST" ? { body: JSON.stringify(opts.body ?? {}) } : {})
  };
  const resp = await fetch(url, init);
  const raw = await resp.text();
  const json = raw ? safeJson(raw) : null;
  if (!resp.ok) {
    const code = (json as any)?.error?.code;
    const msg = (json as any)?.error?.message;
    throw badRequest(typeof code === "string" ? code : "identity_gateway_error", typeof msg === "string" ? msg : "Identity gateway error");
  }
  return json;
}

function getStringProp(value: unknown, key: string): string | null {
  if (!value || typeof value !== "object") return null;
  const v = (value as Record<string, unknown>)[key];
  return typeof v === "string" ? v : null;
}

function mapOrchestratorStatus(status: string) {
  const s = status.toLowerCase();
  if (["created", "collecting_media", "queued", "running"].includes(s)) return "pending";
  if (s === "completed") return "completed";
  if (s === "failed") return "failed";
  return null;
}
