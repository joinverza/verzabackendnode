import crypto from "node:crypto";
import express from "express";
import { z } from "zod";
import { badRequest, notFound } from "@verza/http";
const createConsentSchema = z.object({
    institution_id: z.string().uuid(),
    credential_id: z.string().uuid(),
    allowed_fields: z.array(z.string()).default([]),
    purpose: z.string().optional(),
    expires_at: z.string().datetime().optional()
});
const consentIdSchema = z.object({ consentId: z.string().uuid() });
export function createConsentsRouter(ctx) {
    const router = express.Router();
    router.get("/", async (req, res, next) => {
        try {
            const result = await ctx.pool.query("select id,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at from consents where user_id=$1 order by created_at desc", [req.auth.userId]);
            res.json(result.rows.map((r) => ({ ...r, allowed_fields: safeJson(r.allowed_fields_json) })));
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/", async (req, res, next) => {
        try {
            const body = createConsentSchema.parse(req.body ?? {});
            const now = new Date();
            const expiresAt = body.expires_at ? new Date(body.expires_at) : null;
            if (expiresAt && Number.isNaN(expiresAt.getTime()))
                throw badRequest("invalid_expires_at", "Invalid expires_at");
            if (expiresAt && expiresAt.getTime() <= now.getTime())
                throw badRequest("invalid_expires_at", "expires_at must be in the future");
            const cred = await ctx.pool.query("select 1 as ok from credentials where id=$1 and owner_user_id=$2 limit 1", [
                body.credential_id,
                req.auth.userId
            ]);
            if (!cred.rowCount)
                throw badRequest("credential_not_found", "Credential not found");
            const inst = await ctx.pool.query("select 1 as ok from institutions where id=$1 and status='active' limit 1", [
                body.institution_id
            ]);
            if (!inst.rowCount)
                throw badRequest("institution_not_found", "Institution not found");
            const id = crypto.randomUUID();
            await ctx.pool.query("insert into consents (id,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)", [
                id,
                req.auth.userId,
                body.institution_id,
                body.credential_id,
                JSON.stringify(body.allowed_fields),
                body.purpose ?? "",
                "active",
                expiresAt,
                now
            ]);
            await ctx.pool.query("insert into consent_audit_events (id,consent_id,event_type,actor_type,actor_id,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)", [crypto.randomUUID(), id, "consent_created", "user", req.auth.userId, "{}", now]);
            res.status(201).json({ id });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/:consentId", async (req, res, next) => {
        try {
            const { consentId } = consentIdSchema.parse(req.params);
            const result = await ctx.pool.query("select id,user_id,institution_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at from consents where id=$1 and user_id=$2 limit 1", [consentId, req.auth.userId]);
            const row = result.rows[0];
            if (!row)
                throw notFound("consent_not_found", "Consent not found");
            res.json({ ...row, allowed_fields: safeJson(row.allowed_fields_json) });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/:consentId/revoke", async (req, res, next) => {
        try {
            const { consentId } = consentIdSchema.parse(req.params);
            const now = new Date();
            const updated = await ctx.pool.query("update consents set revoked_at=$1, status='revoked' where id=$2 and user_id=$3 and revoked_at is null", [now, consentId, req.auth.userId]);
            if (!updated.rowCount)
                throw notFound("consent_not_found", "Consent not found");
            await ctx.pool.query("insert into consent_audit_events (id,consent_id,event_type,actor_type,actor_id,data_json,created_at) values ($1,$2,$3,$4,$5,$6,$7)", [crypto.randomUUID(), consentId, "consent_revoked", "user", req.auth.userId, "{}", now]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/:consentId/audit", async (req, res, next) => {
        try {
            const { consentId } = consentIdSchema.parse(req.params);
            const access = await ctx.pool.query("select 1 as ok from consents where id=$1 and user_id=$2 limit 1", [
                consentId,
                req.auth.userId
            ]);
            if (!access.rowCount)
                throw notFound("consent_not_found", "Consent not found");
            const result = await ctx.pool.query("select id,event_type,actor_type,actor_id,data_json,created_at from consent_audit_events where consent_id=$1 order by created_at asc", [consentId]);
            res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
        }
        catch (err) {
            next(err);
        }
    });
    return router;
}
function safeJson(s) {
    try {
        return JSON.parse(s);
    }
    catch {
        return [];
    }
}
//# sourceMappingURL=consents.js.map