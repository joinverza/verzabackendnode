import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { decryptJson, encryptJson } from "@verza/crypto";
import { badRequest, notFound } from "@verza/http";

import type { MainApiContext } from "../routes.js";
import { getOrCreateProofForCredential } from "./proofs.js";
import { appendAuditEvent } from "./auditLog.js";

export const storeSchema = z.object({
  type: z.string().min(1),
  issuer_name: z.string().optional(),
  document_number: z.string().optional(),
  issue_date: z.string().datetime().optional(),
  expiry_date: z.string().datetime().optional(),
  issuing_authority: z.string().optional(),
  notes: z.string().optional(),
  data: z.unknown()
});

export const shareSchema = z.object({
  credential_id: z.string().uuid(),
  recipient_did: z.string().optional(),
  recipient: z.string().optional(),
  permission: z.string().optional(),
  purpose: z.string().optional(),
  expires_at: z.string().datetime().optional()
});

export const storeResponseSchema = z.object({
  id: z.string().uuid()
});

export const shareResponseSchema = z.object({
  id: z.string().uuid(),
  token: z.string().min(1)
});

const credentialIdSchema = z.object({
  credentialId: z.string().uuid()
});

const shareIdSchema = z.object({
  credentialId: z.string().uuid(),
  shareId: z.string().uuid()
});

const publicShareSchema = z.object({ token: z.string().min(1) });

export function createCredentialsRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.post("/store", async (req, res, next) => {
    try {
      const body = storeSchema.parse(req.body);
      const ts = new Date();
      const id = crypto.randomUUID();
      const enc = encryptJson({
        masterKeyB64: ctx.config.ENCRYPTION_MASTER_KEY_B64,
        plaintext: body.data
      });
      await ctx.pool.query(
        "insert into credentials (id, tenant_id, owner_user_id, owner_did, type, status, issuer_name, document_number, issue_date, expiry_date, issuing_authority, notes, encrypted_data, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        [
          id,
          req.auth.tenantId,
          req.auth.userId,
          "",
          body.type,
          "active",
          body.issuer_name ?? "",
          body.document_number ?? "",
          body.issue_date ? new Date(body.issue_date) : null,
          body.expiry_date ? new Date(body.expiry_date) : null,
          body.issuing_authority ?? "",
          body.notes ?? "",
          enc,
          ts,
          ts
        ]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "credential_stored",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "credential",
        subjectId: id,
        data: {
          type: body.type,
          issuer_name: body.issuer_name ?? "",
          document_number: body.document_number ? "present" : ""
        }
      });
      res.json({ id });
    } catch (err) {
      next(err);
    }
  });

  router.get("/", async (req, res, next) => {
    try {
      const result = await ctx.pool.query(
        "select id, type, status, issuer_name, document_number, created_at, updated_at from credentials where tenant_id=$1 and owner_user_id=$2 order by created_at desc",
        [req.auth.tenantId, req.auth.userId]
      );
      res.json(result.rows);
    } catch (err) {
      next(err);
    }
  });

  router.get("/:credentialId", async (req, res, next) => {
    try {
      const { credentialId } = credentialIdSchema.parse(req.params);
      const result = await ctx.pool.query(
        "select * from credentials where id=$1 and tenant_id=$2 and owner_user_id=$3 limit 1",
        [credentialId, req.auth.tenantId, req.auth.userId]
      );
      const row = result.rows[0];
      if (!row) throw notFound("credential_not_found", "Credential not found");
      const decrypted = decryptJson({ masterKeyB64: ctx.config.ENCRYPTION_MASTER_KEY_B64, ciphertextB64: row.encrypted_data });
      res.json({ ...row, data: decrypted });
    } catch (err) {
      next(err);
    }
  });

  router.patch("/:credentialId", async (req, res, next) => {
    try {
      const { credentialId } = credentialIdSchema.parse(req.params);
      const body = z
        .object({
          status: z.string().optional(),
          notes: z.string().optional()
        })
        .parse(req.body);
      await ctx.pool.query(
        "update credentials set status=coalesce($1,status), notes=coalesce($2,notes), updated_at=$3 where id=$4 and tenant_id=$5 and owner_user_id=$6",
        [body.status ?? null, body.notes ?? null, new Date(), credentialId, req.auth.tenantId, req.auth.userId]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "credential_updated",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "credential",
        subjectId: credentialId,
        data: { status: body.status ?? null, notes: body.notes ? "present" : null }
      });
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:credentialId/proof", async (req, res, next) => {
    try {
      const { credentialId } = credentialIdSchema.parse(req.params);
      const type = typeof req.query.type === "string" && req.query.type.trim().length ? req.query.type.trim() : undefined;
      const proof = await getOrCreateProofForCredential(ctx, {
        tenantId: req.auth.tenantId,
        userId: req.auth.userId,
        credentialId,
        ...(type ? { type } : {})
      });
      res.json(proof);
    } catch (err) {
      next(err);
    }
  });

  router.get("/:credentialId/shares", async (req, res, next) => {
    try {
      const { credentialId } = credentialIdSchema.parse(req.params);
      const result = await ctx.pool.query(
        "select id, credential_id, owner_user_id, recipient_did, recipient, permission, purpose, token, expires_at, revoked_at, created_at from credential_shares where tenant_id=$1 and credential_id=$2 and owner_user_id=$3 order by created_at desc",
        [req.auth.tenantId, credentialId, req.auth.userId]
      );
      res.json(result.rows);
    } catch (err) {
      next(err);
    }
  });

  router.post("/:credentialId/shares/:shareId/revoke", async (req, res, next) => {
    try {
      const { credentialId, shareId } = shareIdSchema.parse(req.params);
      await ctx.pool.query(
        "update credential_shares set revoked_at=$1 where tenant_id=$2 and id=$3 and credential_id=$4 and owner_user_id=$5",
        [new Date(), req.auth.tenantId, shareId, credentialId, req.auth.userId]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "credential_share_revoked",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "credential_share",
        subjectId: shareId,
        data: { credential_id: credentialId }
      });
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.post("/share", async (req, res, next) => {
    try {
      const body = shareSchema.parse(req.body);
      const token = base64Url(crypto.randomBytes(48));
      const id = crypto.randomUUID();
      const expiresAt = body.expires_at ? new Date(body.expires_at) : null;
      const createdAt = new Date();
      const result = await ctx.pool.query<{ ok: number }>(
        "select 1 as ok from credentials where id=$1 and tenant_id=$2 and owner_user_id=$3 limit 1",
        [body.credential_id, req.auth.tenantId, req.auth.userId]
      );
      if (!result.rowCount) throw badRequest("credential_not_found", "Credential not found");
      await ctx.pool.query(
        "insert into credential_shares (id, tenant_id, credential_id, owner_user_id, recipient_did, recipient, permission, purpose, token, expires_at, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        [
          id,
          req.auth.tenantId,
          body.credential_id,
          req.auth.userId,
          body.recipient_did ?? "",
          body.recipient ?? "",
          body.permission ?? "view",
          body.purpose ?? "",
          token,
          expiresAt,
          createdAt
        ]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: req.auth.tenantId,
        eventType: "credential_shared",
        actorType: "user",
        actorId: req.auth.userId,
        subjectType: "credential",
        subjectId: body.credential_id,
        data: { share_id: id, recipient: body.recipient ?? "", recipient_did: body.recipient_did ?? "", permission: body.permission ?? "view" }
      });
      res.json({ id, token });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

export function createPublicSharesRouter(ctx: MainApiContext): Router {
  const router = express.Router();
  router.get("/:token", async (req, res, next) => {
    try {
      const { token } = publicShareSchema.parse(req.params);
      const result = await ctx.pool.query(
        "select cs.token, cs.expires_at, cs.revoked_at, c.encrypted_data from credential_shares cs join credentials c on c.id = cs.credential_id and c.tenant_id = cs.tenant_id where cs.token=$1 limit 1",
        [token]
      );
      const row = result.rows[0];
      if (!row) throw notFound("share_not_found", "Share not found");
      if (row.revoked_at) throw badRequest("share_revoked", "Share revoked");
      if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) throw badRequest("share_expired", "Share expired");
      const data = decryptJson({ masterKeyB64: ctx.config.ENCRYPTION_MASTER_KEY_B64, ciphertextB64: row.encrypted_data });
      res.json({ token, data });
    } catch (err) {
      next(err);
    }
  });
  return router;
}

function base64Url(bytes: Buffer) {
  return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
