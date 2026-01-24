import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { sha256Hex } from "@verza/crypto";

import type { MainApiContext } from "../routes.js";

const rotateSchema = z.object({ name: z.string().optional() });

export function createInstitutionRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.get("/me", async (req, res) => {
    res.json({ id: req.institution.id, name: req.institution.name, status: req.institution.status });
  });

  router.post("/api-keys/rotate", async (req, res, next) => {
    try {
      const body = rotateSchema.parse(req.body ?? {});
      const inst = req.institution;
      const rawKey = base64Url(crypto.randomBytes(32));
      const keyHash = sha256Hex(rawKey);
      const id = crypto.randomUUID();
      const last4 = rawKey.slice(-4);
      await ctx.pool.query(
        "insert into institution_api_keys (id, institution_id, name, key_hash, last4, created_at) values ($1,$2,$3,$4,$5,$6)",
        [id, inst.id, body.name ?? "rotated", keyHash, last4, new Date()]
      );
      res.json({ id, api_key: rawKey, last4 });
    } catch (err) {
      next(err);
    }
  });

  router.get("/consents", async (req, res, next) => {
    try {
      const inst = req.institution;
      const result = await ctx.pool.query(
        "select id,user_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at from consents where institution_id=$1 order by created_at desc",
        [inst.id]
      );
      res.json(result.rows.map((r) => ({ ...r, allowed_fields: safeJson(r.allowed_fields_json) })));
    } catch (err) {
      next(err);
    }
  });

  router.get("/consents/:consent_id", async (req, res, next) => {
    try {
      const consentId = z.string().uuid().parse(req.params.consent_id);
      const inst = req.institution;
      const result = await ctx.pool.query(
        "select id,user_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at from consents where id=$1 and institution_id=$2",
        [consentId, inst.id]
      );
      res.json(result.rows.map((r) => ({ ...r, allowed_fields: safeJson(r.allowed_fields_json) }))[0] ?? {});
    } catch (err) {
      next(err);
    }
  });

  router.get("/consents/:consent_id/audit", async (req, res, next) => {
    try {
      const consentId = z.string().uuid().parse(req.params.consent_id);
      const inst = req.institution;
      const result = await ctx.pool.query(
        "select cae.id,cae.event_type,cae.actor_type,cae.actor_id,cae.data_json,cae.created_at from consent_audit_events cae join consents c on c.id = cae.consent_id where cae.consent_id=$1 and c.institution_id=$2 order by cae.created_at asc",
        [consentId, inst.id]
      );
      res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
    } catch (err) {
      next(err);
    }
  });

  router.get("/consents/:consent_id/credential", async (req, res, next) => {
    try {
      const consentId = z.string().uuid().parse(req.params.consent_id);
      const inst = req.institution;
      const result = await ctx.pool.query(
        "select cr.* from credentials cr join consents c on c.credential_id = cr.id where c.id=$1 and c.institution_id=$2 limit 1",
        [consentId, inst.id]
      );
      res.json(result.rows[0] ?? {});
    } catch (err) {
      next(err);
    }
  });

  router.get("/consents/:consent_id/identity", async (req, res, next) => {
    try {
      const consentId = z.string().uuid().parse(req.params.consent_id);
      const inst = req.institution;
      const result = await ctx.pool.query(
        "select iv.* from identity_verifications iv join consents c on c.user_id = iv.user_id where c.id=$1 and c.institution_id=$2 order by iv.server_received_at desc",
        [consentId, inst.id]
      );
      res.json(
        result.rows.map((r) => ({
          ...r,
          scores: safeJson(r.scores_json),
          reasons: safeJson(r.reasons_json),
          signals: safeJson(r.signals_json)
        }))
      );
    } catch (err) {
      next(err);
    }
  });

  router.post("/identity/attestations", async (_req, res) => {
    res.json({ status: "ok" });
  });

  router.get("/identity/verifications", async (req, res, next) => {
    try {
      const inst = req.institution;
      const result = await ctx.pool.query("select * from identity_verifications where verifier_institution_id=$1 order by server_received_at desc", [
        inst.id
      ]);
      res.json(result.rows);
    } catch (err) {
      next(err);
    }
  });

  router.get("/identity/verifications/:verification_id", async (req, res, next) => {
    try {
      const id = z.string().uuid().parse(req.params.verification_id);
      const inst = req.institution;
      const result = await ctx.pool.query("select * from identity_verifications where id=$1 and verifier_institution_id=$2", [id, inst.id]);
      res.json(result.rows[0] ?? {});
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
    return {};
  }
}

function base64Url(bytes: Buffer) {
  return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

