import crypto from "node:crypto";
import express from "express";
import { z } from "zod";
import { badRequest, notFound } from "@verza/http";
const createSchema = z.object({
    amount_minor: z.number().int().positive(),
    currency: z.string().min(3).max(8),
    memo: z.string().optional()
});
const idSchema = z.object({ id: z.string().uuid() });
const disputeSchema = z.object({
    id: z.string().uuid(),
    reason: z.string().min(1)
});
export function createEscrowRouter(ctx) {
    const router = express.Router();
    router.post("/create", async (req, res, next) => {
        try {
            const body = createSchema.parse(req.body);
            const id = crypto.randomUUID();
            const ts = new Date();
            await ctx.pool.query("insert into escrows (id, user_id, amount_minor, currency, status, memo, disputed_at, dispute_reason, released_at, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,null,'',null,$7,$8)", [id, req.auth.userId, body.amount_minor, body.currency, "created", body.memo ?? "", ts, ts]);
            res.status(201).json({ id, status: "created" });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/release", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.body);
            const ts = new Date();
            const updated = await ctx.pool.query("update escrows set status='released', released_at=$1, updated_at=$2 where id=$3 and user_id=$4 and status='created' returning id", [ts, ts, id, req.auth.userId]);
            if (!updated.rowCount) {
                const exists = await ctx.pool.query("select status from escrows where id=$1 and user_id=$2 limit 1", [id, req.auth.userId]);
                if (!exists.rowCount)
                    throw notFound("escrow_not_found", "Escrow not found");
                throw badRequest("invalid_escrow_state", "Escrow cannot be released");
            }
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/dispute", async (req, res, next) => {
        try {
            const body = disputeSchema.parse(req.body);
            const ts = new Date();
            const updated = await ctx.pool.query("update escrows set status='disputed', disputed_at=$1, dispute_reason=$2, updated_at=$3 where id=$4 and user_id=$5 and status='created' returning id", [ts, body.reason, ts, body.id, req.auth.userId]);
            if (!updated.rowCount) {
                const exists = await ctx.pool.query("select status from escrows where id=$1 and user_id=$2 limit 1", [body.id, req.auth.userId]);
                if (!exists.rowCount)
                    throw notFound("escrow_not_found", "Escrow not found");
                throw badRequest("invalid_escrow_state", "Escrow cannot be disputed");
            }
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/:id/status", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const result = await ctx.pool.query("select id, user_id, amount_minor, currency, status, memo, disputed_at, dispute_reason, released_at, created_at, updated_at from escrows where id=$1 and user_id=$2 limit 1", [id, req.auth.userId]);
            const row = result.rows[0];
            if (!row)
                throw notFound("escrow_not_found", "Escrow not found");
            res.json(row);
        }
        catch (err) {
            next(err);
        }
    });
    return router;
}
//# sourceMappingURL=escrow.js.map