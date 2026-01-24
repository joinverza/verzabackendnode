import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { sha256Hex } from "@verza/crypto";
import { badRequest, notFound } from "@verza/http";

import type { MainApiContext } from "../routes.js";

const createInstitutionSchema = z.object({
  name: z.string().min(1),
  status: z.enum(["active", "suspended"]).optional()
});

const institutionIdSchema = z.object({ institutionId: z.string().uuid() });

const setInstitutionStatusSchema = z.object({
  status: z.enum(["active", "suspended"])
});

const createApiKeySchema = z.object({
  name: z.string().optional()
});

const apiKeyIdParamsSchema = z.object({
  institutionId: z.string().uuid(),
  apiKeyId: z.string().uuid()
});

const addMemberSchema = z.object({
  user_id: z.string().uuid(),
  role: z.string().min(1).default("member"),
  status: z.enum(["active", "removed", "suspended"]).optional()
});

const memberIdParamsSchema = z.object({
  institutionId: z.string().uuid(),
  memberId: z.string().uuid()
});

const updateMemberSchema = z.object({
  role: z.string().min(1).optional(),
  status: z.enum(["active", "removed", "suspended"]).optional()
});

export function createAdminInstitutionsRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.get("/", async (_req, res, next) => {
    try {
      const result = await ctx.pool.query(
        `
        select
          i.id,
          i.name,
          i.status,
          i.created_at,
          i.updated_at,
          coalesce(m.member_count, 0)::int as member_count,
          coalesce(k.api_key_count, 0)::int as api_key_count
        from institutions i
        left join (
          select institution_id, count(*) as member_count
          from institution_members
          group by institution_id
        ) m on m.institution_id = i.id
        left join (
          select institution_id, count(*) as api_key_count
          from institution_api_keys
          group by institution_id
        ) k on k.institution_id = i.id
        order by i.created_at desc
        `
      );
      res.json(result.rows);
    } catch (err) {
      next(err);
    }
  });

  router.post("/", async (req, res, next) => {
    try {
      const body = createInstitutionSchema.parse(req.body ?? {});
      const id = crypto.randomUUID();
      const ts = new Date();
      await ctx.pool.query("insert into institutions (id, name, status, created_at, updated_at) values ($1,$2,$3,$4,$5)", [
        id,
        body.name,
        body.status ?? "active",
        ts,
        ts
      ]);
      res.status(201).json({ id });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:institutionId", async (req, res, next) => {
    try {
      const { institutionId } = institutionIdSchema.parse(req.params);
      const inst = await ctx.pool.query("select id,name,status,created_at,updated_at from institutions where id=$1 limit 1", [
        institutionId
      ]);
      const row = inst.rows[0];
      if (!row) throw notFound("institution_not_found", "Institution not found");
      res.json(row);
    } catch (err) {
      next(err);
    }
  });

  router.post("/:institutionId/status", async (req, res, next) => {
    try {
      const { institutionId } = institutionIdSchema.parse(req.params);
      const body = setInstitutionStatusSchema.parse(req.body ?? {});
      const updated = await ctx.pool.query("update institutions set status=$1, updated_at=$2 where id=$3", [
        body.status,
        new Date(),
        institutionId
      ]);
      if (!updated.rowCount) throw notFound("institution_not_found", "Institution not found");
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:institutionId/api-keys", async (req, res, next) => {
    try {
      const { institutionId } = institutionIdSchema.parse(req.params);
      const inst = await ctx.pool.query<{ ok: number }>("select 1 as ok from institutions where id=$1 limit 1", [institutionId]);
      if (!inst.rowCount) throw notFound("institution_not_found", "Institution not found");
      const result = await ctx.pool.query(
        "select id, institution_id, name, last4, created_at, revoked_at from institution_api_keys where institution_id=$1 order by created_at desc",
        [institutionId]
      );
      res.json(result.rows);
    } catch (err) {
      next(err);
    }
  });

  router.post("/:institutionId/api-keys", async (req, res, next) => {
    try {
      const { institutionId } = institutionIdSchema.parse(req.params);
      const body = createApiKeySchema.parse(req.body ?? {});
      const inst = await ctx.pool.query<{ ok: number }>("select 1 as ok from institutions where id=$1 limit 1", [institutionId]);
      if (!inst.rowCount) throw notFound("institution_not_found", "Institution not found");

      const rawKey = base64Url(crypto.randomBytes(32));
      const keyHash = sha256Hex(rawKey);
      const id = crypto.randomUUID();
      const last4 = rawKey.slice(-4);
      await ctx.pool.query(
        "insert into institution_api_keys (id, institution_id, name, key_hash, last4, created_at) values ($1,$2,$3,$4,$5,$6)",
        [id, institutionId, body.name ?? "admin_created", keyHash, last4, new Date()]
      );
      res.status(201).json({ id, api_key: rawKey, last4 });
    } catch (err) {
      next(err);
    }
  });

  router.post("/:institutionId/api-keys/:apiKeyId/revoke", async (req, res, next) => {
    try {
      const { institutionId, apiKeyId } = apiKeyIdParamsSchema.parse(req.params);
      const now = new Date();
      const updated = await ctx.pool.query(
        "update institution_api_keys set revoked_at=$1 where id=$2 and institution_id=$3 and revoked_at is null",
        [now, apiKeyId, institutionId]
      );
      if (!updated.rowCount) throw notFound("api_key_not_found", "API key not found");
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:institutionId/members", async (req, res, next) => {
    try {
      const { institutionId } = institutionIdSchema.parse(req.params);
      const inst = await ctx.pool.query<{ ok: number }>("select 1 as ok from institutions where id=$1 limit 1", [institutionId]);
      if (!inst.rowCount) throw notFound("institution_not_found", "Institution not found");
      const result = await ctx.pool.query(
        `
        select
          im.id,
          im.institution_id,
          im.user_id,
          im.role,
          im.status,
          im.created_at,
          u.email,
          u.name
        from institution_members im
        join users u on u.id = im.user_id
        where im.institution_id=$1
        order by im.created_at desc
        `,
        [institutionId]
      );
      res.json(result.rows);
    } catch (err) {
      next(err);
    }
  });

  router.post("/:institutionId/members", async (req, res, next) => {
    try {
      const { institutionId } = institutionIdSchema.parse(req.params);
      const body = addMemberSchema.parse(req.body ?? {});

      const inst = await ctx.pool.query<{ ok: number }>("select 1 as ok from institutions where id=$1 limit 1", [institutionId]);
      if (!inst.rowCount) throw notFound("institution_not_found", "Institution not found");

      const user = await ctx.pool.query<{ ok: number }>("select 1 as ok from users where id=$1 limit 1", [body.user_id]);
      if (!user.rowCount) throw badRequest("user_not_found", "User not found");

      const id = crypto.randomUUID();
      const status = body.status ?? "active";
      const result = await ctx.pool.query<{ id: string }>(
        `
        insert into institution_members (id, institution_id, user_id, role, status, created_at)
        values ($1,$2,$3,$4,$5,$6)
        on conflict (institution_id, user_id)
        do update set role=excluded.role, status=excluded.status
        returning id
        `,
        [id, institutionId, body.user_id, body.role, status, new Date()]
      );
      res.status(201).json({ id: result.rows[0]!.id });
    } catch (err) {
      next(err);
    }
  });

  router.post("/:institutionId/members/:memberId", async (req, res, next) => {
    try {
      const { institutionId, memberId } = memberIdParamsSchema.parse(req.params);
      const body = updateMemberSchema.parse(req.body ?? {});
      if (!body.role && !body.status) throw badRequest("invalid_request", "Nothing to update");

      const updated = await ctx.pool.query(
        "update institution_members set role=coalesce($1,role), status=coalesce($2,status) where id=$3 and institution_id=$4",
        [body.role ?? null, body.status ?? null, memberId, institutionId]
      );
      if (!updated.rowCount) throw notFound("member_not_found", "Member not found");
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

function base64Url(bytes: Buffer) {
  return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

