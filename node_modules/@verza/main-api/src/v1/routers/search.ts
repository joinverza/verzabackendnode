import type { Router } from "express";

import express from "express";
import { z } from "zod";

import type { MainApiContext } from "../routes.js";

const querySchema = z.object({
  q: z.string().optional(),
  limit: z.coerce.number().int().positive().max(50).optional()
});

export function createSearchRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.get("/", async (req, res, next) => {
    try {
      const { q, limit } = querySchema.parse(req.query);
      const l = limit ?? 20;
      const term = (q ?? "").trim();
      const like = term.length ? `%${term}%` : "%";

      const credentials = await ctx.pool.query(
        "select id, type, status, issuer_name, document_number, created_at, updated_at from credentials where owner_user_id=$1 and (type ilike $2 or issuer_name ilike $2 or document_number ilike $2) order by created_at desc limit $3",
        [req.auth.userId, like, l]
      );

      const verifiers = await ctx.pool.query(
        "select id, owner_user_id, name, did, status, website_url, description, created_at, updated_at from verifiers where status='active' and (name ilike $1 or did ilike $1) order by created_at desc limit $2",
        [like, l]
      );

      const identityVerifications = await ctx.pool.query(
        "select id, user_id, status, provider, document_type, server_received_at, completed_at from identity_verifications where user_id=$1 and (status ilike $2 or provider ilike $2 or document_type ilike $2) order by server_received_at desc limit $3",
        [req.auth.userId, like, l]
      );

      res.json({ q: term, credentials: credentials.rows, verifiers: verifiers.rows, identity_verifications: identityVerifications.rows });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

