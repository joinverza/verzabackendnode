import crypto from "node:crypto";
import express from "express";
import { z } from "zod";
import { sha256Hex } from "@verza/crypto";
import { badRequest, forbidden, notFound } from "@verza/http";
const rotateSchema = z.object({ name: z.string().optional() });
const identityAttestationSchema = z.object({
    verification_id: z.string().uuid(),
    status: z.enum(["approved", "rejected"]),
    standard: z.string().default(""),
    verifier_reference: z.string().default(""),
    scores: z.record(z.string(), z.number()).default({}),
    reasons: z.array(z.string()).default([]),
    signals: z.record(z.string(), z.unknown()).default({}),
    consent_id: z.string().uuid().optional()
});
export function createInstitutionRouter(ctx) {
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
            await ctx.pool.query("insert into institution_api_keys (id, institution_id, name, key_hash, last4, created_at) values ($1,$2,$3,$4,$5,$6)", [id, inst.id, body.name ?? "rotated", keyHash, last4, new Date()]);
            res.json({ id, api_key: rawKey, last4 });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/consents", async (req, res, next) => {
        try {
            const inst = req.institution;
            const result = await ctx.pool.query("select id,user_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at from consents where institution_id=$1 order by created_at desc", [inst.id]);
            res.json(result.rows.map((r) => ({ ...r, allowed_fields: safeJson(r.allowed_fields_json) })));
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/consents/:consent_id", async (req, res, next) => {
        try {
            const consentId = z.string().uuid().parse(req.params.consent_id);
            const inst = req.institution;
            const result = await ctx.pool.query("select id,user_id,credential_id,allowed_fields_json,purpose,status,expires_at,revoked_at,created_at from consents where id=$1 and institution_id=$2", [consentId, inst.id]);
            const row = result.rows[0];
            if (!row)
                throw notFound("consent_not_found", "Consent not found");
            res.json({ ...row, allowed_fields: safeJson(row.allowed_fields_json) });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/consents/:consent_id/audit", async (req, res, next) => {
        try {
            const consentId = z.string().uuid().parse(req.params.consent_id);
            const inst = req.institution;
            const result = await ctx.pool.query("select cae.id,cae.event_type,cae.actor_type,cae.actor_id,cae.data_json,cae.created_at from consent_audit_events cae join consents c on c.id = cae.consent_id where cae.consent_id=$1 and c.institution_id=$2 order by cae.created_at asc", [consentId, inst.id]);
            res.json(result.rows.map((r) => ({ ...r, data: safeJson(r.data_json) })));
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/consents/:consent_id/credential", async (req, res, next) => {
        try {
            const consentId = z.string().uuid().parse(req.params.consent_id);
            const inst = req.institution;
            const now = new Date();
            const consent = await ctx.pool.query("select credential_id,allowed_fields_json,status,revoked_at,expires_at from consents where id=$1 and institution_id=$2 limit 1", [
                consentId,
                inst.id
            ]);
            const c = consent.rows[0];
            if (!c)
                throw notFound("consent_not_found", "Consent not found");
            if (c.status !== "active" || c.revoked_at || (c.expires_at && c.expires_at.getTime() <= now.getTime())) {
                throw forbidden("consent_inactive", "Consent is not active");
            }
            const result = await ctx.pool.query("select id,owner_user_id,owner_did,type,status,issuer_name,document_number,issue_date,expiry_date,issuing_authority,notes,created_at,updated_at from credentials where id=$1 limit 1", [c.credential_id]);
            const row = result.rows[0];
            if (!row)
                throw notFound("credential_not_found", "Credential not found");
            const allowed = safeJsonArray(c.allowed_fields_json);
            res.json(filterCredentialByAllowedFields(row, allowed));
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/consents/:consent_id/identity", async (req, res, next) => {
        try {
            const consentId = z.string().uuid().parse(req.params.consent_id);
            const inst = req.institution;
            const now = new Date();
            const consent = await ctx.pool.query("select user_id,status,revoked_at,expires_at from consents where id=$1 and institution_id=$2 limit 1", [consentId, inst.id]);
            const c = consent.rows[0];
            if (!c)
                throw notFound("consent_not_found", "Consent not found");
            if (c.status !== "active" || c.revoked_at || (c.expires_at && c.expires_at.getTime() <= now.getTime())) {
                throw forbidden("consent_inactive", "Consent is not active");
            }
            const result = await ctx.pool.query("select id,user_id,credential_id,status,provider,document_type,confidence_threshold,scores_json,reasons_json,signals_json,locale,server_received_at,completed_at,verifier_institution_id,standard,verifier_reference from identity_verifications where user_id=$1 order by server_received_at desc", [c.user_id]);
            res.json(result.rows.map((r) => ({
                ...r,
                scores: safeJson(r.scores_json),
                reasons: safeJson(r.reasons_json),
                signals: safeJson(r.signals_json)
            })));
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/identity/attestations", async (req, res, next) => {
        try {
            const inst = req.institution;
            const now = new Date();
            const body = identityAttestationSchema.parse(req.body ?? {});
            const verification = await ctx.pool.query("select id,user_id,status from identity_verifications where id=$1 limit 1", [body.verification_id]);
            const vr = verification.rows[0];
            if (!vr)
                throw notFound("identity_verification_not_found", "Identity verification not found");
            if (vr.status !== "pending")
                throw badRequest("invalid_status_transition", "Only pending verifications can be attested");
            if (body.consent_id) {
                const access = await ctx.pool.query("select 1 as ok from consents where id=$1 and institution_id=$2 and user_id=$3 and status='active' and revoked_at is null and (expires_at is null or expires_at > $4) limit 1", [body.consent_id, inst.id, vr.user_id, now]);
                if (!access.rowCount)
                    throw forbidden("consent_required", "Active consent required");
            }
            else {
                const access = await ctx.pool.query("select 1 as ok from consents where institution_id=$1 and user_id=$2 and status='active' and revoked_at is null and (expires_at is null or expires_at > $3) limit 1", [inst.id, vr.user_id, now]);
                if (!access.rowCount)
                    throw forbidden("consent_required", "Active consent required");
            }
            await ctx.pool.query("update identity_verifications set status=$1, scores_json=$2, reasons_json=$3, signals_json=$4, completed_at=$5, verifier_institution_id=$6, standard=$7, verifier_reference=$8 where id=$9", [
                body.status,
                JSON.stringify(body.scores),
                JSON.stringify(body.reasons),
                JSON.stringify(body.signals),
                now,
                inst.id,
                body.standard,
                body.verifier_reference,
                body.verification_id
            ]);
            await ctx.pool.query("insert into identity_verification_audit_events (id,verification_id,user_id,event_type,data_json,created_at) values ($1,$2,$3,$4,$5,$6)", [
                crypto.randomUUID(),
                body.verification_id,
                vr.user_id,
                "attested_institution",
                JSON.stringify({ institution_id: inst.id, api_key_id: inst.apiKeyId, status: body.status, standard: body.standard }),
                now
            ]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/identity/verifications", async (req, res, next) => {
        try {
            const inst = req.institution;
            const result = await ctx.pool.query("select id,user_id,credential_id,status,provider,document_type,confidence_threshold,locale,server_received_at,completed_at,verifier_institution_id,standard,verifier_reference,scores_json,reasons_json,signals_json from identity_verifications where verifier_institution_id=$1 order by server_received_at desc", [inst.id]);
            res.json(result.rows);
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/identity/verifications/:verification_id", async (req, res, next) => {
        try {
            const id = z.string().uuid().parse(req.params.verification_id);
            const inst = req.institution;
            const result = await ctx.pool.query("select id,user_id,credential_id,status,provider,document_type,confidence_threshold,locale,server_received_at,completed_at,verifier_institution_id,standard,verifier_reference,scores_json,reasons_json,signals_json from identity_verifications where id=$1 and verifier_institution_id=$2", [id, inst.id]);
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
function safeJsonArray(s) {
    try {
        const parsed = JSON.parse(s);
        if (!Array.isArray(parsed))
            return [];
        return parsed.filter((x) => typeof x === "string");
    }
    catch {
        return [];
    }
}
function filterCredentialByAllowedFields(credential, allowedFields) {
    const always = {
        id: true,
        type: true,
        status: true,
        issuer_name: true,
        issue_date: true,
        expiry_date: true,
        issuing_authority: true,
        created_at: true,
        updated_at: true
    };
    const allowSet = new Set(allowedFields);
    const out = {};
    for (const [k, v] of Object.entries(credential)) {
        if (always[k])
            out[k] = v;
        else if (allowSet.has(k))
            out[k] = v;
    }
    return out;
}
function base64Url(bytes) {
    return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
//# sourceMappingURL=institution.js.map