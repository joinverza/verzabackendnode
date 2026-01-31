import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { badRequest, notFound } from "@verza/http";

import type { MainApiContext } from "../routes.js";
import { appendAuditEvent } from "./auditLog.js";

const createConsentSchema = z.object({
  institution_id: z.string().uuid(),
  credential_id: z.string().uuid(),
  allowed_fields: z.array(z.string()).default([]),
  purpose: z.string().optional(),
  expires_at: z.string().datetime().optional()
});

const consentIdSchema = z.object({ consentId: z.string().uuid() });

export function createConsentsRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.get("/", async (req, res, next) => {
    try {
      const result = await ctx.pool.query(
        "select id,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at from consents where tenant_id=$1 and user_id=$2 order by created_at desc",
        [req.auth.tenantId, req.auth.userId]
      );
      res.json(result.rows.map((r) => ({ ...r, allowed_fields: safeJson(r.allowed_fields_json) })));
    } catch (err) {
      next(err);
    }
  });

  router.post("/", async (req, res, next) => {
    try {
      const body = createConsentSchema.parse(req.body ?? {});
      const now = new Date();
      const expiresAt = body.expires_at ? new Date(body.expires_at) : null;
      if (expiresAt && Number.isNaN(expiresAt.getTime())) throw badRequest("invalid_expires_at", "Invalid expires_at");
      if (expiresAt && expiresAt.getTime() <= now.getTime()) throw badRequest("invalid_expires_at", "expires_at must be in the future");

      const cred = await ctx.pool.query<{ ok: number }>(
        "select 1 as ok from credentials where id=$1 and tenant_id=$2 and owner_user_id=$3 limit 1",
        [body.credential_id, req.auth.tenantId, req.auth.userId]
      );
      if (!cred.rowCount) throw badRequest("credential_not_found", "Credential not found");

      const inst = await ctx.pool.query<{ ok: number }>(
        "select 1 as ok from institutions where id=$1 and tenant_id=$2 and status='active' limit 1",
        [body.institution_id, req.auth.tenantId]
      );
      if (!inst.rowCount) throw badRequest("institution_not_found", "Institution not found");

      const id = crypto.randomUUID();
      await ctx.pool.query("begin");
      try {
        await ctx.pool.query(
          "insert into consents (id,tenant_id,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,created_at,version) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1)",
          [
            id,
            req.auth.tenantId,
            req.auth.userId,
            body.institution_id,
            body.credential_id,
            JSON.stringify(body.allowed_fields),
            body.purpose ?? "",
            "active",
            expiresAt,
            now
          ]
        );
        await ctx.pool.query(
          "insert into consent_versions (id,tenant_id,consent_id,version,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
          [
            crypto.randomUUID(),
            req.auth.tenantId,
            id,
            1,
            req.auth.userId,
            body.institution_id,
            body.credential_id,
            JSON.stringify(body.allowed_fields),
            body.purpose ?? "",
            "active",
            expiresAt,
            null,
            now
          ]
        );
        await ctx.pool.query(
          "insert into consent_audit_events (id,tenant_id,consent_id,event_type,actor_type,actor_id,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)",
          [crypto.randomUUID(), req.auth.tenantId, id, "consent_created", "user", req.auth.userId, "{}", now]
        );
        await ctx.pool.query("commit");
      } catch (err) {
        await ctx.pool.query("rollback");
        throw err;
      }

      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "consent_created",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "consent",
        subjectId: id,
        data: { institution_id: body.institution_id, credential_id: body.credential_id, version: 1 }
      });
      res.status(201).json({ id });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:consentId", async (req, res, next) => {
    try {
      const { consentId } = consentIdSchema.parse(req.params);
      const result = await ctx.pool.query(
        "select id,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at from consents where id=$1 and tenant_id=$2 and user_id=$3 limit 1",
        [consentId, req.auth.tenantId, req.auth.userId]
      );
      const row = result.rows[0];
      if (!row) throw notFound("consent_not_found", "Consent not found");
      res.json({ ...row, allowed_fields: safeJson(row.allowed_fields_json) });
    } catch (err) {
      next(err);
    }
  });

  router.post("/:consentId/revoke", async (req, res, next) => {
    try {
      const { consentId } = consentIdSchema.parse(req.params);
      const now = new Date();
      let newVersion = 0;
      await ctx.pool.query("begin");
      try {
        const updated = await ctx.pool.query<{
          institution_id: string;
          credential_id: string;
          allowed_fields_json: string;
          purpose: string;
          status: string;
          expires_at: Date | null;
          revoked_at: Date | null;
          version: number;
        }>(
          "update consents set revoked_at=$1, status='revoked', version=version+1 where id=$2 and tenant_id=$3 and user_id=$4 and revoked_at is null returning institution_id, credential_id, allowed_fields_json, purpose, status, expires_at, revoked_at, version",
          [now, consentId, req.auth.tenantId, req.auth.userId]
        );
        const row = updated.rows[0];
        if (!row) throw notFound("consent_not_found", "Consent not found");
        newVersion = row.version;
        await ctx.pool.query(
          "insert into consent_versions (id,tenant_id,consent_id,version,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
          [
            crypto.randomUUID(),
            req.auth.tenantId,
            consentId,
            row.version,
            req.auth.userId,
            row.institution_id,
            row.credential_id,
            row.allowed_fields_json,
            row.purpose ?? "",
            row.status ?? "revoked",
            row.expires_at ?? null,
            row.revoked_at ?? now,
            now
          ]
        );
        await ctx.pool.query(
          "insert into consent_audit_events (id,tenant_id,consent_id,event_type,actor_type,actor_id,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7,$8)",
          [crypto.randomUUID(), req.auth.tenantId, consentId, "consent_revoked", "user", req.auth.userId, "{}", now]
        );
        await ctx.pool.query("commit");
      } catch (err) {
        await ctx.pool.query("rollback");
        throw err;
      }

      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "consent_revoked",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "consent",
        subjectId: consentId,
        data: { version: newVersion }
      });
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:consentId/audit", async (req, res, next) => {
    try {
      const { consentId } = consentIdSchema.parse(req.params);
      const access = await ctx.pool.query<{ ok: number }>(
        "select 1 as ok from consents where id=$1 and tenant_id=$2 and user_id=$3 limit 1",
        [consentId, req.auth.tenantId, req.auth.userId]
      );
      if (!access.rowCount) throw notFound("consent_not_found", "Consent not found");
      const result = await ctx.pool.query(
        "select id,event_type,actor_type,actor_id,data_json,created_at from consent_audit_events where tenant_id=$1 and consent_id=$2 order by created_at asc",
        [req.auth.tenantId, consentId]
      );
      res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
    } catch (err) {
      next(err);
    }
  });

  return router;
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return [];
  }
}
