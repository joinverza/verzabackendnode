import express from "express";
import { z } from "zod";
import { PERMISSIONS, requirePermission } from "@verza/auth";
import { badRequest, notFound } from "@verza/http";
import { appendAuditEvent } from "./auditLog.js";
const listSchema = z.object({
    limit: z.string().regex(/^\d+$/).optional(),
    offset: z.string().regex(/^\d+$/).optional()
});
const txIdSchema = z.object({ id: z.string().uuid() });
const setTxStatusSchema = z.object({
    status: z.string().min(1)
});
const credentialIdSchema = z.object({ credential_id: z.string().min(1) });
const upsertCredentialMetadataSchema = z.object({
    credential_id: z.string().min(1),
    midnight_address: z.string().optional(),
    cardano_escrow_id: z.string().optional(),
    verifier_did: z.string().optional(),
    status: z.string().optional()
});
export function createAdminBridgeRouter(ctx) {
    const router = express.Router();
    router.get("/transactions", requirePermission(ctx, { action: PERMISSIONS.ADMIN_BRIDGE_TRANSACTIONS_LIST }), async (req, res, next) => {
        try {
            const q = listSchema.parse(req.query ?? {});
            const limit = Math.min(Number(q.limit ?? "50"), 200);
            const offset = Number(q.offset ?? "0");
            if (!Number.isFinite(limit) || limit <= 0)
                throw badRequest("invalid_limit", "Invalid limit");
            if (!Number.isFinite(offset) || offset < 0)
                throw badRequest("invalid_offset", "Invalid offset");
            const result = await ctx.pool.query("select id, midnight_tx_hash, cardano_tx_hash, operation_type, status, retry_count, created_at, updated_at from cross_chain_transactions order by created_at desc limit $1 offset $2", [limit, offset]);
            await appendAuditEvent(ctx.pool, {
                tenantId: req.auth.tenantId,
                eventType: "admin_bridge_transactions_listed",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "cross_chain_transactions",
                subjectId: "list",
                data: { limit, offset, count: result.rows.length }
            });
            res.json(result.rows);
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/transactions/:id", requirePermission(ctx, { action: PERMISSIONS.ADMIN_BRIDGE_TRANSACTION_READ }), async (req, res, next) => {
        try {
            const { id } = txIdSchema.parse(req.params);
            const result = await ctx.pool.query("select id, midnight_tx_hash, cardano_tx_hash, operation_type, status, retry_count, created_at, updated_at from cross_chain_transactions where id=$1 limit 1", [id]);
            const row = result.rows[0];
            if (!row)
                throw notFound("transaction_not_found", "Transaction not found");
            await appendAuditEvent(ctx.pool, {
                tenantId: req.auth.tenantId,
                eventType: "admin_bridge_transaction_viewed",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "cross_chain_transaction",
                subjectId: id,
                data: {}
            });
            res.json(row);
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/transactions/:id/status", requirePermission(ctx, { action: PERMISSIONS.ADMIN_BRIDGE_TRANSACTION_STATUS_SET }), async (req, res, next) => {
        try {
            const { id } = txIdSchema.parse(req.params);
            const body = setTxStatusSchema.parse(req.body ?? {});
            const ts = new Date();
            const updated = await ctx.pool.query("update cross_chain_transactions set status=$1, updated_at=$2 where id=$3", [
                body.status,
                ts,
                id
            ]);
            if (!updated.rowCount)
                throw notFound("transaction_not_found", "Transaction not found");
            await appendAuditEvent(ctx.pool, {
                tenantId: req.auth.tenantId,
                eventType: "admin_bridge_transaction_status_set",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "cross_chain_transaction",
                subjectId: id,
                data: { status: body.status }
            });
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/transactions/:id/retry", requirePermission(ctx, { action: PERMISSIONS.ADMIN_BRIDGE_TRANSACTION_RETRY }), async (req, res, next) => {
        try {
            const { id } = txIdSchema.parse(req.params);
            const ts = new Date();
            const updated = await ctx.pool.query("update cross_chain_transactions set retry_count=retry_count+1, status='retry_requested', updated_at=$1 where id=$2", [ts, id]);
            if (!updated.rowCount)
                throw notFound("transaction_not_found", "Transaction not found");
            await appendAuditEvent(ctx.pool, {
                tenantId: req.auth.tenantId,
                eventType: "admin_bridge_transaction_retry_requested",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "cross_chain_transaction",
                subjectId: id,
                data: {}
            });
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/credential-metadata/:credential_id", requirePermission(ctx, { action: PERMISSIONS.ADMIN_BRIDGE_CREDENTIAL_METADATA_READ }), async (req, res, next) => {
        try {
            const { credential_id } = credentialIdSchema.parse(req.params);
            const result = await ctx.pool.query("select credential_id, midnight_address, cardano_escrow_id, verifier_did, status, created_at from credential_metadata where credential_id=$1 limit 1", [credential_id]);
            const row = result.rows[0];
            if (!row)
                throw notFound("credential_metadata_not_found", "Credential metadata not found");
            await appendAuditEvent(ctx.pool, {
                tenantId: req.auth.tenantId,
                eventType: "admin_bridge_credential_metadata_viewed",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "credential_metadata",
                subjectId: credential_id,
                data: {}
            });
            res.json(row);
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/credential-metadata/upsert", requirePermission(ctx, { action: PERMISSIONS.ADMIN_BRIDGE_CREDENTIAL_METADATA_UPSERT }), async (req, res, next) => {
        try {
            const body = upsertCredentialMetadataSchema.parse(req.body ?? {});
            const now = new Date();
            await ctx.pool.query(`
        insert into credential_metadata (credential_id, midnight_address, cardano_escrow_id, verifier_did, status, created_at)
        values ($1,$2,$3,$4,$5,$6)
        on conflict (credential_id)
        do update set
          midnight_address=coalesce(excluded.midnight_address, credential_metadata.midnight_address),
          cardano_escrow_id=coalesce(excluded.cardano_escrow_id, credential_metadata.cardano_escrow_id),
          verifier_did=coalesce(excluded.verifier_did, credential_metadata.verifier_did),
          status=coalesce(excluded.status, credential_metadata.status)
        `, [
                body.credential_id,
                body.midnight_address ?? null,
                body.cardano_escrow_id ?? null,
                body.verifier_did ?? null,
                body.status ?? null,
                now
            ]);
            await appendAuditEvent(ctx.pool, {
                tenantId: req.auth.tenantId,
                eventType: "admin_bridge_credential_metadata_upserted",
                actorType: "admin",
                actorId: req.auth.userId,
                subjectType: "credential_metadata",
                subjectId: body.credential_id,
                data: {
                    ...(body.midnight_address ? { midnight_address: body.midnight_address } : {}),
                    ...(body.cardano_escrow_id ? { cardano_escrow_id: body.cardano_escrow_id } : {}),
                    ...(body.verifier_did ? { verifier_did: body.verifier_did } : {}),
                    ...(body.status ? { status: body.status } : {})
                }
            });
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    return router;
}
//# sourceMappingURL=adminBridge.js.map