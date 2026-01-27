import crypto from "node:crypto";
import express from "express";
import { z } from "zod";
import { badRequest, notFound } from "@verza/http";
const requestSchema = z.object({
    operation_type: z.string().min(1).optional()
});
const completeSchema = z.object({
    id: z.string().uuid(),
    midnight_tx_hash: z.string().min(1).optional(),
    cardano_tx_hash: z.string().min(1).optional(),
    status: z.string().min(1).optional()
});
const idSchema = z.object({ id: z.string().uuid() });
export function createVerificationsRouter(ctx) {
    const router = express.Router();
    router.post("/request", async (req, res, next) => {
        try {
            const body = requestSchema.parse(req.body);
            const id = crypto.randomUUID();
            const ts = new Date();
            const operationType = body.operation_type ?? "verification";
            await ctx.pool.query("insert into cross_chain_transactions (id, midnight_tx_hash, cardano_tx_hash, operation_type, status, retry_count, created_at, updated_at) values ($1,null,null,$2,$3,0,$4,$5)", [id, operationType, "requested", ts, ts]);
            res.status(201).json({ id });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/complete", async (req, res, next) => {
        try {
            const body = completeSchema.parse(req.body);
            const ts = new Date();
            const newStatus = body.status ?? "completed";
            if (newStatus === "requested")
                throw badRequest("invalid_status", "Invalid status");
            const updated = await ctx.pool.query("update cross_chain_transactions set midnight_tx_hash=coalesce($1,midnight_tx_hash), cardano_tx_hash=coalesce($2,cardano_tx_hash), status=$3, updated_at=$4 where id=$5 returning id", [body.midnight_tx_hash ?? null, body.cardano_tx_hash ?? null, newStatus, ts, body.id]);
            if (!updated.rowCount)
                throw notFound("verification_not_found", "Verification not found");
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/:id/status", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const result = await ctx.pool.query("select id, midnight_tx_hash, cardano_tx_hash, operation_type, status, retry_count, created_at, updated_at from cross_chain_transactions where id=$1 limit 1", [id]);
            const row = result.rows[0];
            if (!row)
                throw notFound("verification_not_found", "Verification not found");
            res.json(row);
        }
        catch (err) {
            next(err);
        }
    });
    return router;
}
//# sourceMappingURL=verifications.js.map