import express from "express";
import { z } from "zod";
const querySchema = z.object({
    q: z.string().optional(),
    limit: z.coerce.number().int().positive().max(50).optional()
});
export function createSearchRouter(ctx) {
    const router = express.Router();
    router.get("/", async (req, res, next) => {
        try {
            const { q, limit } = querySchema.parse(req.query);
            const l = limit ?? 20;
            const term = (q ?? "").trim();
            const like = term.length ? `%${term}%` : "%";
            const credentials = await ctx.pool.query("select id, type, status, issuer_name, document_number, created_at, updated_at from credentials where tenant_id=$1 and owner_user_id=$2 and (type ilike $3 or issuer_name ilike $3 or document_number ilike $3) order by created_at desc limit $4", [req.auth.tenantId, req.auth.userId, like, l]);
            const verifiers = await ctx.pool.query("select id, owner_user_id, name, did, status, website_url, description, created_at, updated_at from verifiers where tenant_id=$1 and status='active' and (name ilike $2 or did ilike $2) order by created_at desc limit $3", [req.auth.tenantId, like, l]);
            const identityVerifications = await ctx.pool.query("select id, user_id, status, provider, document_type, server_received_at, completed_at from identity_verifications where tenant_id=$1 and user_id=$2 and (status ilike $3 or provider ilike $3 or document_type ilike $3) order by server_received_at desc limit $4", [req.auth.tenantId, req.auth.userId, like, l]);
            res.json({ q: term, credentials: credentials.rows, verifiers: verifiers.rows, identity_verifications: identityVerifications.rows });
        }
        catch (err) {
            next(err);
        }
    });
    return router;
}
//# sourceMappingURL=search.js.map