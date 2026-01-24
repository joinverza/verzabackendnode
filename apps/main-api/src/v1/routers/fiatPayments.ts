import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { requireAdmin } from "@verza/auth";
import { sha256Hex, signReceipt, verifyDidSignedRequest } from "@verza/crypto";
import { badRequest, notFound } from "@verza/http";

import type { MainApiContext } from "../routes.js";

const initiateSchema = z.object({
  amount_minor: z.number().int().positive(),
  currency: z.string().min(3).max(8)
});

const idSchema = z.object({ id: z.string().uuid() });

export function createFiatPaymentsRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.post("/initiate", async (req, res, next) => {
    try {
      const body = initiateSchema.parse(req.body);
      const rawBody = req.bodyRaw ?? Buffer.from(JSON.stringify(req.body ?? {}));
      const did = String(req.header("X-DID") ?? "");
      const timestamp = String(req.header("X-DID-Timestamp") ?? "");
      const nonce = String(req.header("X-DID-Nonce") ?? "");
      const signature = String(req.header("X-DID-Signature") ?? "");
      if (!did || !timestamp || !nonce || !signature) throw badRequest("missing_did_headers", "Missing DID headers");

      const ok = verifyDidSignedRequest({
        method: req.method,
        path: req.originalUrl.split("?")[0] ?? req.originalUrl,
        timestamp,
        nonce,
        rawBody,
        did,
        signature
      });
      if (!ok) throw badRequest("invalid_did_signature", "Invalid DID signature");

      const didHash = sha256Hex(did);
      const id = crypto.randomUUID();
      const ts = new Date();
      await ctx.pool.query(
        "insert into fiat_payment_sessions (id, did_hash, amount_minor, currency, created_at, updated_at) values ($1,$2,$3,$4,$5,$6)",
        [id, didHash, body.amount_minor, body.currency, ts, ts]
      );
      res.json({ id, status: "initiated" });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:id/status", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const result = await ctx.pool.query("select id,status,stripe_status,amount_minor,currency,created_at,updated_at from fiat_payment_sessions where id=$1", [
        id
      ]);
      const row = result.rows[0];
      if (!row) throw notFound("payment_not_found", "Payment not found");
      res.json(row);
    } catch (err) {
      next(err);
    }
  });

  router.get("/:id/receipt", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const format = typeof req.query.format === "string" ? req.query.format : "json";
      const payment = await ctx.pool.query("select id,amount_minor,currency,created_at from fiat_payment_sessions where id=$1", [id]);
      const row = payment.rows[0];
      if (!row) throw notFound("payment_not_found", "Payment not found");
      const receiptBody = { payment_id: row.id, amount_minor: row.amount_minor, currency: row.currency, issued_at: new Date().toISOString() };
      const signed = signReceipt({ seedB64: ctx.config.RECEIPT_ED25519_SEED_B64, receipt: receiptBody });
      const payload = { receipt: receiptBody, ...signed };
      if (format === "json") res.json(payload);
      else res.type("text/plain").send(JSON.stringify(payload));
    } catch (err) {
      next(err);
    }
  });

  router.post("/reconcile", requireAdmin(ctx), async (_req, res) => {
    res.json({ status: "ok" });
  });

  return router;
}
