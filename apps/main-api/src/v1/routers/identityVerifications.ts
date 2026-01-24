import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { badRequest, notFound } from "@verza/http";

import type { MainApiContext } from "../routes.js";

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
  signals: z.record(z.string(), z.unknown()).default({})
});

export function createIdentityVerificationsRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.post("/request", async (req, res, next) => {
    try {
      const body = requestSchema.parse(req.body ?? {});
      const id = crypto.randomUUID();
      const now = new Date();

      await ctx.pool.query(
        "insert into identity_verifications (id,user_id,credential_id,status,provider,document_type,confidence_threshold,scores_json,reasons_json,signals_json,locale,client_timestamp,geo_lat,geo_lon,ip,user_agent,server_received_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
        [
          id,
          req.auth.userId,
          body.credential_id ?? null,
          "pending",
          body.provider,
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
          now
        ]
      );
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6)",
        [crypto.randomUUID(), id, req.auth.userId, "requested", "{}", now]
      );

      res.status(201).json({ id, status: "pending" });
    } catch (err) {
      next(err);
    }
  });

  router.get("/", async (req, res, next) => {
    try {
      const result = await ctx.pool.query(
        "select id,user_id,credential_id,status,provider,document_type,confidence_threshold,locale,server_received_at,completed_at,verifier_institution_id,standard,verifier_reference from identity_verifications where user_id=$1 order by server_received_at desc",
        [req.auth.userId]
      );
      res.json(result.rows);
    } catch (err) {
      next(err);
    }
  });

  router.get("/:id", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const result = await ctx.pool.query("select * from identity_verifications where id=$1 and user_id=$2 limit 1", [id, req.auth.userId]);
      const row = result.rows[0];
      if (!row) throw notFound("identity_verification_not_found", "Identity verification not found");
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
      const result = await ctx.pool.query(
        "select id,verification_id,user_id,event_type,data_json,created_at from identity_verification_audit_events where verification_id=$1 and user_id=$2 order by created_at asc",
        [id, req.auth.userId]
      );
      res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/complete", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const body = completeSchema.parse(req.body ?? {});
      const now = new Date();

      const existing = await ctx.pool.query<{ id: string }>("select id from identity_verifications where id=$1 and user_id=$2 limit 1", [
        id,
        req.auth.userId
      ]);
      if (!existing.rowCount) throw notFound("identity_verification_not_found", "Identity verification not found");

      await ctx.pool.query(
        "update identity_verifications set status=$1, scores_json=$2, reasons_json=$3, signals_json=$4, completed_at=$5 where id=$6 and user_id=$7",
        [body.status, JSON.stringify(body.scores), JSON.stringify(body.reasons), JSON.stringify(body.signals), now, id, req.auth.userId]
      );
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6)",
        [crypto.randomUUID(), id, req.auth.userId, "completed", JSON.stringify({ status: body.status }), now]
      );
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/status", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const result = await ctx.pool.query<{ status: string }>("select status from identity_verifications where id=$1 and user_id=$2 limit 1", [
        id,
        req.auth.userId
      ]);
      const row = result.rows[0];
      if (!row) throw notFound("identity_verification_not_found", "Identity verification not found");
      res.json({ id, status: row.status });
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/cancel", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const now = new Date();
      const updated = await ctx.pool.query("update identity_verifications set status='cancelled' where id=$1 and user_id=$2 and status='pending'", [
        id,
        req.auth.userId
      ]);
      if (!updated.rowCount) throw notFound("identity_verification_not_found", "Identity verification not found");
      await ctx.pool.query(
        "insert into identity_verification_audit_events (id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6)",
        [crypto.randomUUID(), id, req.auth.userId, "cancelled", "{}", now]
      );
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
