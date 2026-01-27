import crypto from "node:crypto";
import express from "express";
import { z } from "zod";
import { requireAdmin } from "@verza/auth";
import { badRequest, notFound } from "@verza/http";
const proposeSchema = z.object({
    title: z.string().min(1),
    description: z.string().optional()
});
const voteSchema = z.object({
    proposal_id: z.string().uuid(),
    vote: z.enum(["yes", "no", "abstain"])
});
export function createGovernanceRouter(ctx) {
    const router = express.Router();
    router.post("/propose", requireAdmin(ctx), async (req, res, next) => {
        try {
            const body = proposeSchema.parse(req.body);
            const id = crypto.randomUUID();
            const ts = new Date();
            await ctx.pool.query("insert into governance_proposals (id, created_by_user_id, title, description, status, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7)", [id, req.auth.userId, body.title, body.description ?? "", "open", ts, ts]);
            res.status(201).json({ id });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/vote", async (req, res, next) => {
        try {
            const body = voteSchema.parse(req.body);
            const proposal = await ctx.pool.query("select status from governance_proposals where id=$1 limit 1", [body.proposal_id]);
            if (!proposal.rowCount)
                throw notFound("proposal_not_found", "Proposal not found");
            if (proposal.rows[0].status !== "open")
                throw badRequest("proposal_closed", "Proposal is not open");
            const ts = new Date();
            const id = crypto.randomUUID();
            await ctx.pool.query("insert into governance_votes (id, proposal_id, voter_user_id, vote, created_at) values ($1,$2,$3,$4,$5) on conflict (proposal_id, voter_user_id) do update set vote=excluded.vote, created_at=excluded.created_at", [id, body.proposal_id, req.auth.userId, body.vote, ts]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/proposals", async (req, res, next) => {
        try {
            const rows = await ctx.pool.query(`
        select
          p.id,
          p.created_by_user_id,
          p.title,
          p.description,
          p.status,
          p.created_at,
          p.updated_at,
          coalesce(sum(case when v.vote='yes' then 1 else 0 end), 0)::int as yes_votes,
          coalesce(sum(case when v.vote='no' then 1 else 0 end), 0)::int as no_votes,
          coalesce(sum(case when v.vote='abstain' then 1 else 0 end), 0)::int as abstain_votes,
          max(case when v.voter_user_id=$1 then v.vote else null end) as my_vote
        from governance_proposals p
        left join governance_votes v on v.proposal_id = p.id
        group by p.id
        order by p.created_at desc
        `, [req.auth.userId]);
            res.json(rows.rows);
        }
        catch (err) {
            next(err);
        }
    });
    return router;
}
//# sourceMappingURL=governance.js.map