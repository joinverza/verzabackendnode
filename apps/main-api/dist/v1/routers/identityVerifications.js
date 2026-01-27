import crypto from "node:crypto";
import express from "express";
import { z } from "zod";
import { badRequest, forbidden, notFound } from "@verza/http";
const requestSchema = z.object({
    credential_id: z.string().uuid().optional(),
    provider: z.string().default("internal"),
    document_type: z.string().optional(),
    confidence_threshold: z.number().min(0).max(1).default(0.98),
    locale: z.string().optional()
});
const idSchema = z.object({ id: z.string().uuid() });
const completeSchema = z.object({
    status: z.enum(["approved", "rejected", "completed"]).default("completed"),
    scores: z.record(z.string(), z.number()).default({}),
    reasons: z.array(z.string()).default([]),
    signals: z.record(z.string(), z.unknown()).default({}),
    verifier_institution_id: z.string().uuid().optional(),
    standard: z.string().optional(),
    verifier_reference: z.string().optional()
});
export function createIdentityVerificationsRouter(ctx) {
    const router = express.Router();
    router.post("/request", async (req, res, next) => {
        try {
            const body = requestSchema.parse(req.body ?? {});
            const id = crypto.randomUUID();
            const now = new Date();
            await ctx.pool.query("insert into identity_verifications (id,user_id,credential_id,status,provider,document_type,confidence_threshold,scores_json,reasons_json,signals_json,locale,client_timestamp,geo_lat,geo_lon,ip,user_agent,server_received_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)", [
                id,
                req.auth.userId,
                body.credential_id ?? null,
                "pending",
                body.provider,
                body.document_type ?? "",
                body.confidence_threshold,
                "{}",
                "[]",
                "{}",
                body.locale ?? "",
                null,
                0,
                0,
                req.ip,
                String(req.headers["user-agent"] ?? ""),
                now
            ]);
            await ctx.pool.query("insert into identity_verification_audit_events (id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6)", [crypto.randomUUID(), id, req.auth.userId, "requested", "{}", now]);
            res.status(201).json({ id, status: "pending" });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/", async (req, res, next) => {
        try {
            const result = await ctx.pool.query("select id,user_id,credential_id,status,provider,document_type,confidence_threshold,locale,server_received_at,completed_at,verifier_institution_id,standard,verifier_reference from identity_verifications where user_id=$1 order by server_received_at desc", [req.auth.userId]);
            res.json(result.rows);
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/:id", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const isAdmin = req.auth.role === "admin";
            const result = await ctx.pool.query("select * from identity_verifications where id=$1 and ($2::boolean = true or user_id=$3) limit 1", [
                id,
                isAdmin,
                req.auth.userId
            ]);
            const row = result.rows[0];
            if (!row)
                throw notFound("identity_verification_not_found", "Identity verification not found");
            res.json({
                ...row,
                scores: safeJson(row.scores_json),
                reasons: safeJson(row.reasons_json),
                signals: safeJson(row.signals_json)
            });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/:id/audit", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const isAdmin = req.auth.role === "admin";
            const result = await ctx.pool.query("select id,verification_id,user_id,event_type,data_json,created_at from identity_verification_audit_events where verification_id=$1 and ($2::boolean = true or user_id=$3) order by created_at asc", [id, isAdmin, req.auth.userId]);
            res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/:id/complete", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const body = completeSchema.parse(req.body ?? {});
            const now = new Date();
            if (req.auth.role !== "admin")
                throw forbidden("forbidden", "Admin required");
            const existing = await ctx.pool.query("select id,user_id,status from identity_verifications where id=$1 limit 1", [id]);
            const row = existing.rows[0];
            if (!row)
                throw notFound("identity_verification_not_found", "Identity verification not found");
            if (row.status !== "pending")
                throw badRequest("invalid_status_transition", "Only pending verifications can be completed");
            await ctx.pool.query("update identity_verifications set status=$1, scores_json=$2, reasons_json=$3, signals_json=$4, completed_at=$5, verifier_institution_id=coalesce($6,verifier_institution_id), standard=coalesce($7,standard), verifier_reference=coalesce($8,verifier_reference) where id=$9", [
                body.status,
                JSON.stringify(body.scores),
                JSON.stringify(body.reasons),
                JSON.stringify(body.signals),
                now,
                body.verifier_institution_id ?? null,
                body.standard ?? null,
                body.verifier_reference ?? null,
                id
            ]);
            await ctx.pool.query("insert into identity_verification_audit_events (id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6)", [
                crypto.randomUUID(),
                id,
                row.user_id,
                "completed_admin",
                JSON.stringify({ status: body.status, actor_user_id: req.auth.userId }),
                now
            ]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/:id/status", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const isAdmin = req.auth.role === "admin";
            const result = await ctx.pool.query("select status from identity_verifications where id=$1 and user_id=$2 limit 1", [
                id,
                req.auth.userId
            ]);
            const row = result.rows[0];
            if (row) {
                res.json({ id, status: row.status });
                return;
            }
            if (!isAdmin)
                throw notFound("identity_verification_not_found", "Identity verification not found");
            const adminResult = await ctx.pool.query("select status from identity_verifications where id=$1 limit 1", [id]);
            const adminRow = adminResult.rows[0];
            if (!adminRow)
                throw notFound("identity_verification_not_found", "Identity verification not found");
            res.json({ id, status: adminRow.status });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/:id/cancel", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const now = new Date();
            const updated = await ctx.pool.query("update identity_verifications set status='cancelled' where id=$1 and user_id=$2 and status='pending'", [
                id,
                req.auth.userId
            ]);
            if (!updated.rowCount)
                throw notFound("identity_verification_not_found", "Identity verification not found");
            await ctx.pool.query("insert into identity_verification_audit_events (id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6)", [crypto.randomUUID(), id, req.auth.userId, "cancelled", "{}", now]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.use((_req, _res, next) => next(badRequest("invalid_route", "Invalid identity verifications route")));
    return router;
}
function safeJson(s) {
    try {
        return JSON.parse(s);
    }
    catch {
        return {};
    }
}
//# sourceMappingURL=identityVerifications.js.map