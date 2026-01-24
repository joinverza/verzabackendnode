import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { badRequest } from "@verza/http";

import type { MainApiContext } from "../routes.js";

const readIdSchema = z.object({ id: z.string().uuid() });

export function createNotificationsRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.get("/", async (req, res, next) => {
    try {
      const result = await ctx.pool.query(
        "select id,user_id,type,title,message,data_json,read_at,created_at from notifications where user_id=$1 order by created_at desc",
        [req.auth.userId]
      );
      res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
    } catch (err) {
      next(err);
    }
  });

  router.post("/read-all", async (req, res, next) => {
    try {
      await ctx.pool.query("update notifications set read_at=$1 where user_id=$2 and read_at is null", [new Date(), req.auth.userId]);
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.post("/:id/read", async (req, res, next) => {
    try {
      const { id } = readIdSchema.parse(req.params);
      await ctx.pool.query("update notifications set read_at=$1 where id=$2 and user_id=$3", [new Date(), id, req.auth.userId]);
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.post("/seed", async (req, res, next) => {
    try {
      if ((ctx.config.NODE_ENV ?? "development") === "production") throw badRequest("disabled", "Disabled in production");
      const now = new Date();
      for (let i = 0; i < 3; i++) {
        await ctx.pool.query(
          "insert into notifications (id,user_id,type,title,message,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)",
          [crypto.randomUUID(), req.auth.userId, "seed", `Hello ${i + 1}`, "Seed notification", "{}", now]
        );
      }
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

