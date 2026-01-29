import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { forbidden, notFound } from "@verza/http";

import type { MainApiContext } from "../routes.js";

const createSchema = z.object({
  name: z.string().min(1),
  did: z.string().optional(),
  website_url: z.string().url().optional(),
  description: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional()
});

const updateSchema = z.object({
  name: z.string().min(1).optional(),
  did: z.string().optional(),
  website_url: z.string().url().optional(),
  description: z.string().optional(),
  status: z.enum(["active", "inactive"]).optional(),
  metadata: z.record(z.string(), z.unknown()).optional()
});

const idSchema = z.object({ id: z.string().uuid() });

export function createVerifiersRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.post("/", async (req, res, next) => {
    try {
      const body = createSchema.parse(req.body ?? {});
      const id = crypto.randomUUID();
      const now = new Date();
      await ctx.pool.query(
        "insert into verifiers (id, tenant_id, owner_user_id, name, did, status, website_url, description, metadata_json, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        [
          id,
          req.auth.tenantId,
          req.auth.userId,
          body.name,
          body.did ?? "",
          "active",
          body.website_url ?? "",
          body.description ?? "",
          JSON.stringify(body.metadata ?? {}),
          now,
          now
        ]
      );
      res.status(201).json({ id });
    } catch (err) {
      next(err);
    }
  });

  router.get("/", async (req, res, next) => {
    try {
      const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
      if (q) {
        const result = await ctx.pool.query(
          "select id,name,did,status,website_url,description,metadata_json,created_at,updated_at from verifiers where tenant_id=$1 and status='active' and (name ilike $2 or did ilike $2) order by created_at desc limit 50",
          [req.auth.tenantId, `%${q}%`]
        );
        res.json(result.rows.map((r) => ({ ...r, metadata: safeJson(r.metadata_json) })));
        return;
      }

      const result = await ctx.pool.query(
        "select id,name,did,status,website_url,description,metadata_json,created_at,updated_at from verifiers where tenant_id=$1 and owner_user_id=$2 order by created_at desc",
        [req.auth.tenantId, req.auth.userId]
      );
      res.json(result.rows.map((r) => ({ ...r, metadata: safeJson(r.metadata_json) })));
    } catch (err) {
      next(err);
    }
  });

  router.get("/:id", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const result = await ctx.pool.query(
        "select id,owner_user_id,name,did,status,website_url,description,metadata_json,created_at,updated_at from verifiers where id=$1 and tenant_id=$2 limit 1",
        [id, req.auth.tenantId]
      );
      const row = result.rows[0];
      if (!row) throw notFound("verifier_not_found", "Verifier not found");
      if (row.owner_user_id !== req.auth.userId && row.status !== "active") throw notFound("verifier_not_found", "Verifier not found");
      res.json({ ...row, metadata: safeJson(row.metadata_json) });
    } catch (err) {
      next(err);
    }
  });

  router.patch("/:id", async (req, res, next) => {
    try {
      const { id } = idSchema.parse(req.params);
      const body = updateSchema.parse(req.body ?? {});
      const existing = await ctx.pool.query<{ owner_user_id: string; metadata_json: string }>(
        "select owner_user_id,metadata_json from verifiers where id=$1 and tenant_id=$2 limit 1",
        [id, req.auth.tenantId]
      );
      const row = existing.rows[0];
      if (!row) throw notFound("verifier_not_found", "Verifier not found");
      if (row.owner_user_id !== req.auth.userId) throw forbidden("forbidden", "Only owner can update verifier");

      const mergedMetadata =
        body.metadata === undefined ? row.metadata_json : JSON.stringify({ ...(safeJson(row.metadata_json) as Record<string, unknown>), ...body.metadata });

      await ctx.pool.query(
        "update verifiers set name=coalesce($1,name), did=coalesce($2,did), status=coalesce($3,status), website_url=coalesce($4,website_url), description=coalesce($5,description), metadata_json=coalesce($6,metadata_json), updated_at=$7 where id=$8 and tenant_id=$9",
        [
          body.name ?? null,
          body.did ?? null,
          body.status ?? null,
          body.website_url ?? null,
          body.description ?? null,
          mergedMetadata,
          new Date(),
          id,
          req.auth.tenantId
        ]
      );
      res.json({ status: "ok" });
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
