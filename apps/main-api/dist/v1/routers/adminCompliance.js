import crypto from "node:crypto";
import express from "express";
import { z } from "zod";
import { PERMISSIONS, requirePermission } from "@verza/auth";
import { badRequest, notFound } from "@verza/http";
import { sha256Hex } from "@verza/crypto";
import { appendAuditEvent, verifyAuditChain } from "./auditLog.js";
const tenantSchema = z.object({
    tenant_id: z.string().uuid()
});
const exportQuerySchema = z.object({
    tenant_id: z.string().uuid(),
    stream: z.string().optional(),
    from_seq: z.coerce.number().int().positive().optional(),
    to_seq: z.coerce.number().int().positive().optional(),
    limit: z.coerce.number().int().positive().max(5000).optional(),
    format: z.enum(["json", "ndjson"]).optional()
});
const evidenceCreateSchema = z.object({
    tenant_id: z.string().uuid(),
    subject_type: z.string().min(1),
    subject_id: z.string().min(1),
    content_type: z.string().min(1),
    blob_b64: z.string().optional(),
    content_sha256: z.string().optional(),
    owner_user_id: z.string().uuid().optional()
});
const retentionSetSchema = z.object({
    tenant_id: z.string().uuid(),
    resource_type: z.string().min(1),
    retention_days: z.number().int().nonnegative(),
    action: z.enum(["delete", "anonymize"]).default("delete")
});
export function createAdminComplianceRouter(ctx) {
    const router = express.Router();
    router.get("/audit/head", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_HEAD_READ,
        tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const { tenant_id } = tenantSchema.parse(req.query);
            const stream = typeof req.query.stream === "string" && req.query.stream.trim().length ? req.query.stream.trim() : "tenant";
            const result = await ctx.pool.query("select tenant_id,stream,next_seq,head_hash,updated_at from audit_chains where tenant_id=$1 and stream=$2 limit 1", [tenant_id, stream]);
            const row = result.rows[0];
            if (!row)
                throw notFound("audit_chain_not_found", "Audit chain not found");
            await appendAuditEvent(ctx.pool, {
                tenantId: tenant_id,
                eventType: "admin_audit_head_viewed",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "audit_chain",
                subjectId: stream,
                data: {}
            });
            res.json({ tenant_id: row.tenant_id, stream: row.stream, next_seq: Number(row.next_seq), head_hash: row.head_hash, updated_at: row.updated_at });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/audit/events", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_EVENTS_LIST,
        tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const q = exportQuerySchema.parse(req.query);
            const stream = (q.stream ?? "tenant").trim() || "tenant";
            const fromSeq = q.from_seq ?? 1;
            const limit = q.limit ?? 500;
            const result = await ctx.pool.query("select id,tenant_id,stream,seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at,created_at_ms from audit_events where tenant_id=$1 and stream=$2 and seq >= $3 order by seq asc limit $4", [q.tenant_id, stream, fromSeq, limit]);
            await appendAuditEvent(ctx.pool, {
                tenantId: q.tenant_id,
                eventType: "admin_audit_events_listed",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "audit_events",
                subjectId: stream,
                data: { from_seq: fromSeq, limit }
            });
            res.json(result.rows.map((r) => ({ ...r, data: safeJson(String(r.data_json ?? "{}")) })));
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/audit/export", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_EXPORT,
        tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const q = exportQuerySchema.parse(req.query);
            const stream = (q.stream ?? "tenant").trim() || "tenant";
            const fromSeq = q.from_seq ?? 1;
            const limit = q.limit ?? 5000;
            const upper = q.to_seq ?? null;
            const format = q.format ?? "json";
            const result = await ctx.pool.query(upper
                ? "select tenant_id,stream,seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at,created_at_ms from audit_events where tenant_id=$1 and stream=$2 and seq >= $3 and seq <= $4 order by seq asc limit $5"
                : "select tenant_id,stream,seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at,created_at_ms from audit_events where tenant_id=$1 and stream=$2 and seq >= $3 order by seq asc limit $4", upper ? [q.tenant_id, stream, fromSeq, upper, limit] : [q.tenant_id, stream, fromSeq, limit]);
            const items = result.rows.map((r) => ({
                tenant_id: r.tenant_id,
                stream: r.stream,
                seq: Number(r.seq),
                prev_hash: r.prev_hash,
                event_hash: r.event_hash,
                event_type: r.event_type,
                actor_type: r.actor_type,
                actor_id: r.actor_id,
                subject_type: r.subject_type,
                subject_id: r.subject_id,
                data: safeJson(String(r.data_json ?? "{}")),
                created_at: r.created_at,
                created_at_ms: Number(r.created_at_ms)
            }));
            const exportHash = sha256Hex(items.map((i) => i.event_hash).join("\n"));
            await appendAuditEvent(ctx.pool, {
                tenantId: q.tenant_id,
                eventType: "admin_audit_exported",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "audit_export",
                subjectId: stream,
                data: { from_seq: fromSeq, to_seq: upper ?? null, count: items.length, export_sha256: exportHash, format }
            });
            if (format === "ndjson") {
                res.setHeader("content-type", "application/x-ndjson");
                res.write(JSON.stringify({ type: "manifest", tenant_id: q.tenant_id, stream, from_seq: fromSeq, to_seq: upper ?? null, count: items.length, export_sha256: exportHash }) + "\n");
                for (const it of items)
                    res.write(JSON.stringify({ type: "event", ...it }) + "\n");
                res.end();
                return;
            }
            res.json({ manifest: { tenant_id: q.tenant_id, stream, from_seq: fromSeq, to_seq: upper ?? null, count: items.length, export_sha256: exportHash }, events: items });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/audit/verify", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_VERIFY,
        tenantId: (req) => (typeof req?.body?.tenant_id === "string" ? req.body.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const body = z
                .object({
                tenant_id: z.string().uuid(),
                stream: z.string().optional(),
                from_seq: z.number().int().positive().optional(),
                to_seq: z.number().int().positive().optional()
            })
                .parse(req.body ?? {});
            const result = await verifyAuditChain(ctx.pool, {
                tenantId: body.tenant_id,
                ...(body.stream ? { stream: body.stream } : {}),
                ...(typeof body.from_seq === "number" ? { fromSeq: body.from_seq } : {}),
                ...(typeof body.to_seq === "number" ? { toSeq: body.to_seq } : {})
            });
            await appendAuditEvent(ctx.pool, {
                tenantId: body.tenant_id,
                eventType: "admin_audit_chain_verified",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "audit_chain",
                subjectId: (body.stream ?? "tenant").trim() || "tenant",
                data: { from_seq: body.from_seq ?? null, to_seq: body.to_seq ?? null, ok: result?.ok ?? null }
            });
            res.json(result);
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/reports/summary", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_REPORTS_SUMMARY_READ,
        tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const { tenant_id } = tenantSchema.parse(req.query);
            const from = typeof req.query.from === "string" ? new Date(req.query.from) : null;
            const to = typeof req.query.to === "string" ? new Date(req.query.to) : null;
            const fromOk = from && Number.isFinite(from.getTime());
            const toOk = to && Number.isFinite(to.getTime());
            const where = fromOk && toOk ? "tenant_id=$1 and created_at >= $2 and created_at <= $3" : "tenant_id=$1";
            const params = fromOk && toOk ? [tenant_id, from, to] : [tenant_id];
            const events = await ctx.pool.query(`select event_type, count(*)::text as count from audit_events where ${where} group by event_type order by count(*) desc`, params);
            const dsar = await ctx.pool.query(`select request_type, status, count(*)::text as count from dsar_requests where ${where.replace("created_at", "requested_at")} group by request_type, status order by count(*) desc`, params);
            await appendAuditEvent(ctx.pool, {
                tenantId: tenant_id,
                eventType: "admin_reports_summary_viewed",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "reports",
                subjectId: "summary",
                data: { from: fromOk ? from?.toISOString() : null, to: toOk ? to?.toISOString() : null }
            });
            res.json({
                tenant_id,
                from: fromOk ? from?.toISOString() : null,
                to: toOk ? to?.toISOString() : null,
                events: events.rows.map((r) => ({ event_type: r.event_type, count: Number(r.count) })),
                dsar: dsar.rows.map((r) => ({ request_type: r.request_type, status: r.status, count: Number(r.count) }))
            });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/evidence", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_EVIDENCE_CREATE,
        tenantId: (req) => (typeof req?.body?.tenant_id === "string" ? req.body.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const body = evidenceCreateSchema.parse(req.body ?? {});
            const id = crypto.randomUUID();
            const createdAtMs = Date.now();
            const createdAt = new Date(createdAtMs);
            const blobB64 = body.blob_b64 ?? "";
            let contentSha = body.content_sha256 ?? "";
            if (blobB64) {
                const buf = safeB64ToBuf(blobB64);
                if (!buf)
                    throw badRequest("invalid_blob_b64", "Invalid blob_b64");
                contentSha = sha256Hex(buf);
            }
            if (!contentSha)
                throw badRequest("missing_content_sha256", "Missing content_sha256");
            await ctx.pool.query("insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", [
                id,
                body.tenant_id,
                body.owner_user_id ?? null,
                body.subject_type,
                body.subject_id,
                body.content_type,
                contentSha,
                blobB64 ? "inline" : "external",
                blobB64,
                createdAt,
                createdAtMs
            ]);
            await appendAuditEvent(ctx.pool, {
                tenantId: body.tenant_id,
                eventType: "evidence_stored",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: body.subject_type,
                subjectId: body.subject_id,
                data: { evidence_id: id, content_type: body.content_type, content_sha256: contentSha }
            });
            res.status(201).json({ id, content_sha256: contentSha });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/evidence/:id", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_EVIDENCE_READ,
        tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const id = String(req.params.id ?? "");
            if (!id || !id.match(/^[0-9a-f-]{36}$/i))
                throw badRequest("invalid_id", "Invalid id");
            const { tenant_id } = tenantSchema.parse(req.query);
            const includeBlob = typeof req.query.include_blob === "string" && (req.query.include_blob === "1" || req.query.include_blob.toLowerCase() === "true");
            const result = await ctx.pool.query("select id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms from evidence_objects where id=$1 and tenant_id=$2 limit 1", [id, tenant_id]);
            const row = result.rows[0];
            if (!row)
                throw notFound("evidence_not_found", "Evidence not found");
            if (!includeBlob)
                delete row.blob_b64;
            await appendAuditEvent(ctx.pool, {
                tenantId: tenant_id,
                eventType: "admin_evidence_viewed",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "evidence_object",
                subjectId: id,
                data: { include_blob: includeBlob }
            });
            res.json(row);
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/privacy/requests", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_PRIVACY_REQUESTS_LIST,
        tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const { tenant_id } = tenantSchema.parse(req.query);
            const status = typeof req.query.status === "string" && req.query.status.trim().length ? req.query.status.trim() : null;
            const result = await ctx.pool.query(status
                ? "select id,tenant_id,user_id,request_type,status,reason,requested_at,processed_at,processed_by,result_json from dsar_requests where tenant_id=$1 and status=$2 order by requested_at desc limit 500"
                : "select id,tenant_id,user_id,request_type,status,reason,requested_at,processed_at,processed_by,result_json from dsar_requests where tenant_id=$1 order by requested_at desc limit 500", status ? [tenant_id, status] : [tenant_id]);
            await appendAuditEvent(ctx.pool, {
                tenantId: tenant_id,
                eventType: "admin_privacy_requests_listed",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "dsar_requests",
                subjectId: status ?? "all",
                data: {}
            });
            res.json(result.rows.map((r) => ({ ...r, result: safeJson(String(r.result_json ?? "{}")) })));
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/privacy/retention", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_RETENTION_POLICY_SET,
        tenantId: (req) => (typeof req?.body?.tenant_id === "string" ? req.body.tenant_id : null)
    }), async (req, res, next) => {
        try {
            const body = retentionSetSchema.parse(req.body ?? {});
            await ctx.pool.query("insert into retention_policies (tenant_id,resource_type,retention_days,action,updated_at) values ($1,$2,$3,$4,$5) on conflict (tenant_id, resource_type) do update set retention_days=excluded.retention_days, action=excluded.action, updated_at=excluded.updated_at", [body.tenant_id, body.resource_type, body.retention_days, body.action, new Date()]);
            await appendAuditEvent(ctx.pool, {
                tenantId: body.tenant_id,
                eventType: "retention_policy_set",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "retention_policy",
                subjectId: body.resource_type,
                data: { retention_days: body.retention_days, action: body.action }
            });
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/privacy/retention/run", requirePermission(ctx, {
        action: PERMISSIONS.ADMIN_COMPLIANCE_RETENTION_RUN,
        tenantId: (req) => {
            const fromBody = typeof req?.body?.tenant_id === "string" ? req.body.tenant_id : null;
            const fromQuery = typeof req.query.tenant_id === "string" ? req.query.tenant_id : null;
            return fromBody ?? fromQuery ?? null;
        }
    }), async (req, res, next) => {
        try {
            const tenantId = typeof req.body?.tenant_id === "string" ? req.body.tenant_id : typeof req.query.tenant_id === "string" ? req.query.tenant_id : null;
            const tenantFilter = z.string().uuid().parse(tenantId);
            const policies = await ctx.pool.query("select tenant_id,resource_type,retention_days,action from retention_policies where tenant_id=$1", [tenantFilter]);
            const results = [];
            for (const p of policies.rows) {
                if (p.retention_days <= 0)
                    continue;
                const cutoff = new Date(Date.now() - p.retention_days * 24 * 60 * 60 * 1000);
                if (p.resource_type === "identity_verifications" && p.action === "delete") {
                    const del = await ctx.pool.query("delete from identity_verifications where tenant_id=$1 and server_received_at < $2", [p.tenant_id, cutoff]);
                    results.push({ tenant_id: p.tenant_id, resource_type: p.resource_type, action: p.action, cutoff: cutoff.toISOString(), deleted: del.rowCount });
                }
            }
            await appendAuditEvent(ctx.pool, {
                tenantId: tenantFilter,
                eventType: "admin_retention_run",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "retention",
                subjectId: "run",
                data: { results: results.map((r) => ({ ...r, deleted: Number(r.deleted ?? 0) })) }
            });
            res.json({ status: "ok", results });
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
function safeB64ToBuf(s) {
    try {
        return Buffer.from(s, "base64");
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=adminCompliance.js.map