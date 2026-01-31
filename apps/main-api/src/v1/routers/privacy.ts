import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { decryptJson, sha256Hex } from "@verza/crypto";
import { badRequest } from "@verza/http";

import type { MainApiContext } from "../routes.js";
import { appendAuditEvent } from "./auditLog.js";

const dsarCreateSchema = z.object({
  type: z.enum(["export", "delete"]),
  reason: z.string().optional()
});

export function createPrivacyRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.get("/requests", async (req, res, next) => {
    try {
      const result = await ctx.pool.query(
        "select id,tenant_id,user_id,request_type,status,reason,requested_at,processed_at,processed_by,result_json from dsar_requests where tenant_id=$1 and user_id=$2 order by requested_at desc limit 50",
        [req.auth.tenantId, req.auth.userId]
      );
      res.json(result.rows.map((r) => ({ ...r, result: safeJson(String(r.result_json ?? "{}")) })));
    } catch (err) {
      next(err);
    }
  });

  router.post("/request", async (req, res, next) => {
    try {
      const body = dsarCreateSchema.parse(req.body ?? {});
      const id = crypto.randomUUID();
      const now = new Date();
      await ctx.pool.query(
        "insert into dsar_requests (id,tenant_id,user_id,request_type,status,reason,requested_at,processed_at,processed_by,result_json) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        [id, req.auth.tenantId, req.auth.userId, body.type, "requested", body.reason ?? "", now, null, "", "{}"]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: body.type === "delete" ? "dsar_delete_requested" : "dsar_export_requested",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "user",
        subjectId: req.auth.userId,
        data: { dsar_request_id: id }
      });
      res.status(201).json({ id, status: "requested" });
    } catch (err) {
      next(err);
    }
  });

  router.post("/export", async (req, res, next) => {
    try {
      const now = new Date();
      const id = crypto.randomUUID();
      await ctx.pool.query(
        "insert into dsar_requests (id,tenant_id,user_id,request_type,status,reason,requested_at,processed_at,processed_by,result_json) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        [id, req.auth.tenantId, req.auth.userId, "export", "completed", "", now, now, "self", "{}"]
      );

      const user = await ctx.pool.query(
        "select id,tenant_id,email,name,phone,bio,avatar_url,did,role,status,created_at,updated_at from users where id=$1 and tenant_id=$2 limit 1",
        [req.auth.userId, req.auth.tenantId]
      );
      const creds = await ctx.pool.query(
        "select id,type,status,issuer_name,document_number,issue_date,expiry_date,issuing_authority,notes,encrypted_data,created_at,updated_at from credentials where tenant_id=$1 and owner_user_id=$2 order by created_at desc",
        [req.auth.tenantId, req.auth.userId]
      );
      const credentials = creds.rows.map((r: any) => ({
        ...r,
        data: decryptJson({ masterKeyB64: ctx.config.ENCRYPTION_MASTER_KEY_B64, ciphertextB64: r.encrypted_data })
      }));
      const consents = await ctx.pool.query(
        "select id,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at,version from consents where tenant_id=$1 and user_id=$2 order by created_at desc",
        [req.auth.tenantId, req.auth.userId]
      );
      const verifications = await ctx.pool.query(
        "select id,user_id,credential_id,status,provider,document_type,confidence_threshold,locale,server_received_at,completed_at,verifier_institution_id,standard,verifier_reference from identity_verifications where tenant_id=$1 and user_id=$2 order by server_received_at desc",
        [req.auth.tenantId, req.auth.userId]
      );

      const exportObj = {
        generated_at: now.toISOString(),
        user: user.rows[0] ?? null,
        credentials,
        consents: consents.rows.map((r: any) => ({ ...r, allowed_fields: safeJson(String(r.allowed_fields_json ?? "[]")) })),
        identity_verifications: verifications.rows
      };
      const exportSha = sha256Hex(JSON.stringify(exportObj));

      await ctx.pool.query("update dsar_requests set result_json=$1 where id=$2 and tenant_id=$3 and user_id=$4", [
        JSON.stringify({ export_sha256: exportSha }),
        id,
        req.auth.tenantId,
        req.auth.userId
      ]);
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "dsar_export_completed",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "user",
        subjectId: req.auth.userId,
        data: { dsar_request_id: id, export_sha256: exportSha }
      });
      res.json({ request_id: id, export_sha256: exportSha, data: exportObj });
    } catch (err) {
      next(err);
    }
  });

  router.post("/delete", async (req, res, next) => {
    try {
      const body = z.object({ reason: z.string().optional() }).parse(req.body ?? {});
      const id = crypto.randomUUID();
      const now = new Date();

      await ctx.pool.query("begin");
      try {
        await ctx.pool.query(
          "insert into dsar_requests (id,tenant_id,user_id,request_type,status,reason,requested_at,processed_at,processed_by,result_json) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
          [id, req.auth.tenantId, req.auth.userId, "delete", "processing", body.reason ?? "", now, null, "", "{}"]
        );

        await ctx.pool.query("update sessions set revoked_at=$1 where user_id=$2 and revoked_at is null", [now, req.auth.userId]);

        await ctx.pool.query("delete from credential_shares where tenant_id=$1 and owner_user_id=$2", [req.auth.tenantId, req.auth.userId]);
        await ctx.pool.query("delete from consents where tenant_id=$1 and user_id=$2", [req.auth.tenantId, req.auth.userId]);
        await ctx.pool.query("delete from proofs where tenant_id=$1 and user_id=$2", [req.auth.tenantId, req.auth.userId]);
        await ctx.pool.query("delete from identity_verifications where tenant_id=$1 and user_id=$2", [req.auth.tenantId, req.auth.userId]);
        await ctx.pool.query("delete from credentials where tenant_id=$1 and owner_user_id=$2", [req.auth.tenantId, req.auth.userId]);

        const tombstoneEmail = `deleted+${req.auth.userId}@example.invalid`;
        const tombstoneHash = sha256Hex(crypto.randomUUID());
        const updated = await ctx.pool.query(
          "update users set email=$1, name='', phone='', bio='', avatar_url='', did='', status='deleted', password_hash=$2, twofa_enabled=false, twofa_secret='', backup_codes_sha='', updated_at=$3 where id=$4 and tenant_id=$5",
          [tombstoneEmail, tombstoneHash, now, req.auth.userId, req.auth.tenantId]
        );
        if (!updated.rowCount) throw badRequest("user_not_found", "User not found");

        await ctx.pool.query("update dsar_requests set status='completed', processed_at=$1, processed_by=$2, result_json=$3 where id=$4 and tenant_id=$5 and user_id=$6", [
          now,
          "self",
          JSON.stringify({ email_tombstone: tombstoneEmail }),
          id,
          req.auth.tenantId,
          req.auth.userId
        ]);

        await ctx.pool.query("commit");
      } catch (err) {
        await ctx.pool.query("rollback");
        throw err;
      }

      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "dsar_delete_completed",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "user",
        subjectId: req.auth.userId,
        data: { dsar_request_id: id }
      });

      res.json({ status: "ok", request_id: id });
    } catch (err) {
      next(err);
    }
  });

  router.use((_req, _res, next) => next(badRequest("invalid_route", "Invalid privacy route")));

  return router;
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}

