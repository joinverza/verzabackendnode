import crypto from "node:crypto";
import express from "express";
import Stripe from "stripe";
import { z } from "zod";
import { requireAdmin } from "@verza/auth";
import { sha256Hex, signReceipt, verifyDidSignedRequest } from "@verza/crypto";
import { badRequest, notFound } from "@verza/http";
export const initiateSchema = z.object({
    amount_minor: z.number().int().positive(),
    currency: z.string().min(3).max(8)
});
export const idSchema = z.object({ id: z.string().uuid() });
export const initiateResponseSchema = z.object({
    id: z.string().uuid(),
    status: z.literal("initiated"),
    stripe_payment_intent_id: z.string().nullable(),
    stripe_status: z.string().nullable(),
    stripe_client_secret: z.string().nullable()
});
export const paymentStatusResponseSchema = z.object({
    id: z.string().uuid(),
    status: z.string(),
    stripe_status: z.string().nullable().optional(),
    amount_minor: z.union([z.number().int(), z.string().regex(/^\d+$/)]),
    currency: z.string(),
    created_at: z.any(),
    updated_at: z.any()
});
export const receiptQuerySchema = z.object({
    format: z.string().optional()
});
export const receiptResponseSchema = z.object({
    receipt: z.object({
        payment_id: z.string().uuid(),
        amount_minor: z.union([z.number().int(), z.string().regex(/^\d+$/)]),
        currency: z.string(),
        issued_at: z.string()
    }),
    sig_kid: z.string(),
    sig_b64: z.string()
});
export const reconcileResponseSchema = z.object({
    status: z.literal("ok"),
    checked: z.number().int(),
    updated: z.number().int()
});
export const notConfiguredResponseSchema = z.object({
    status: z.literal("not_configured")
});
export function createFiatPaymentsRouter(ctx) {
    const router = express.Router();
    const stripeKey = String(ctx.config.STRIPE_SECRET_KEY ?? "").trim();
    const stripe = ctx.stripe ?? (stripeKey ? new Stripe(stripeKey, { apiVersion: "2025-08-27.basil" }) : null);
    router.post("/initiate", async (req, res, next) => {
        try {
            const body = initiateSchema.parse(req.body);
            const rawBody = req.bodyRaw ?? Buffer.from(JSON.stringify(req.body ?? {}));
            const did = String(req.header("X-DID") ?? "");
            const timestamp = String(req.header("X-DID-Timestamp") ?? "");
            const nonce = String(req.header("X-DID-Nonce") ?? "");
            const signature = String(req.header("X-DID-Signature") ?? "");
            if (!did || !timestamp || !nonce || !signature)
                throw badRequest("missing_did_headers", "Missing DID headers");
            const ok = verifyDidSignedRequest({
                method: req.method,
                path: req.originalUrl.split("?")[0] ?? req.originalUrl,
                timestamp,
                nonce,
                rawBody,
                did,
                signature
            });
            if (!ok)
                throw badRequest("invalid_did_signature", "Invalid DID signature");
            const didHash = sha256Hex(did);
            const id = crypto.randomUUID();
            const ts = new Date();
            await ctx.pool.query("insert into fiat_payment_sessions (id, did_hash, amount_minor, currency, created_at, updated_at) values ($1,$2,$3,$4,$5,$6)", [id, didHash, body.amount_minor, body.currency, ts, ts]);
            let stripeClientSecret = null;
            let stripePaymentIntentId = null;
            let stripeStatus = null;
            if (stripe) {
                const intent = await stripe.paymentIntents.create({
                    amount: body.amount_minor,
                    currency: body.currency.toLowerCase(),
                    metadata: { verza_payment_id: id, verza_did_hash: didHash }
                });
                stripeClientSecret = intent.client_secret ?? null;
                stripePaymentIntentId = intent.id;
                stripeStatus = intent.status;
                await ctx.pool.query("update fiat_payment_sessions set stripe_payment_intent_id=$1, stripe_client_secret=$2, stripe_status=$3, updated_at=$4 where id=$5", [intent.id, intent.client_secret ?? "", intent.status, new Date(), id]);
            }
            res.json({ id, status: "initiated", stripe_payment_intent_id: stripePaymentIntentId, stripe_status: stripeStatus, stripe_client_secret: stripeClientSecret });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/:id/status", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const result = await ctx.pool.query("select id,status,stripe_status,amount_minor,currency,created_at,updated_at from fiat_payment_sessions where id=$1", [
                id
            ]);
            const row = result.rows[0];
            if (!row)
                throw notFound("payment_not_found", "Payment not found");
            res.json(row);
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/:id/receipt", async (req, res, next) => {
        try {
            const { id } = idSchema.parse(req.params);
            const format = typeof req.query.format === "string" ? req.query.format : "json";
            const payment = await ctx.pool.query("select id,amount_minor,currency,created_at from fiat_payment_sessions where id=$1", [id]);
            const row = payment.rows[0];
            if (!row)
                throw notFound("payment_not_found", "Payment not found");
            const receiptBody = { payment_id: row.id, amount_minor: row.amount_minor, currency: row.currency, issued_at: new Date().toISOString() };
            const signed = signReceipt({ seedB64: ctx.config.RECEIPT_ED25519_SEED_B64, receipt: receiptBody });
            const payload = { receipt: receiptBody, ...signed };
            if (format === "json")
                res.json(payload);
            else
                res.type("text/plain").send(JSON.stringify(payload));
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/stripe/webhook", async (req, res, next) => {
        try {
            if (!stripe)
                return res.status(501).json({ status: "not_configured" });
            const secret = String(ctx.config.STRIPE_WEBHOOK_SECRET ?? "").trim();
            if (!secret)
                return res.status(501).json({ status: "not_configured" });
            const sig = String(req.header("stripe-signature") ?? "");
            if (!sig)
                throw badRequest("missing_stripe_signature", "Missing stripe-signature");
            const raw = req.bodyRaw ?? Buffer.from("");
            const event = stripe.webhooks.constructEvent(raw, sig, secret);
            const eventId = typeof event.id === "string" ? event.id : "";
            const paymentIntentId = await resolvePaymentIntentIdForStripeEvent(stripe, event);
            await ctx.pool.query("begin");
            try {
                if (eventId) {
                    const ins = await ctx.pool.query("insert into stripe_webhook_events (id, type, stripe_payment_intent_id, created_at) values ($1,$2,$3,$4) on conflict (id) do nothing", [eventId, event.type, paymentIntentId ?? "", new Date()]);
                    if (!ins.rowCount) {
                        await ctx.pool.query("commit");
                        return res.json({ status: "ok" });
                    }
                }
                if (!paymentIntentId) {
                    await ctx.pool.query("commit");
                    return res.json({ status: "ok" });
                }
                const sess = await ctx.pool.query("select id, amount_minor, currency from fiat_payment_sessions where stripe_payment_intent_id=$1 limit 1", [paymentIntentId]);
                const row = sess.rows[0];
                if (row) {
                    const mapped = mapStripeEventToPaymentStatus(event);
                    const stripeStatus = extractStripeStatusString(event);
                    await ctx.pool.query("update fiat_payment_sessions set stripe_status=$1, status=$2, updated_at=$3 where id=$4", [
                        stripeStatus,
                        mapped,
                        new Date(),
                        row.id
                    ]);
                    if (mapped === "paid") {
                        await ctx.pool.query("insert into ledger_entries (id, payment_id, amount_minor, currency, stripe_payment_intent_id, created_at) select $1,$2,$3,$4,$5,$6 where not exists (select 1 from ledger_entries where payment_id=$2)", [crypto.randomUUID(), row.id, row.amount_minor, row.currency, paymentIntentId, new Date()]);
                    }
                    if (mapped === "refunded") {
                        const amount = -Math.abs(extractRefundAmountMinor(event) ?? Number(row.amount_minor));
                        await ctx.pool.query("insert into ledger_entries (id, payment_id, amount_minor, currency, stripe_payment_intent_id, created_at) select $1,$2,$3,$4,$5,$6 where not exists (select 1 from ledger_entries where payment_id=$2 and amount_minor < 0)", [crypto.randomUUID(), row.id, amount, row.currency, paymentIntentId, new Date()]);
                    }
                }
                await ctx.pool.query("commit");
            }
            catch (err) {
                await ctx.pool.query("rollback");
                throw err;
            }
            return res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/reconcile", requireAdmin(ctx), async (_req, res, next) => {
        try {
            if (!stripe)
                return res.status(501).json({ status: "not_configured" });
            const result = await ctx.pool.query("select id, stripe_payment_intent_id from fiat_payment_sessions where stripe_payment_intent_id <> '' and status not in ('paid','failed','canceled') order by updated_at asc limit 50");
            let updated = 0;
            for (const row of result.rows) {
                const piId = row.stripe_payment_intent_id;
                if (!piId)
                    continue;
                const pi = await stripe.paymentIntents.retrieve(piId, { expand: ["charges.data"] });
                const mapped = mapStripePaymentIntentReconciledStatus(pi);
                await ctx.pool.query("begin");
                try {
                    await ctx.pool.query("update fiat_payment_sessions set stripe_status=$1, status=$2, updated_at=$3 where id=$4", [
                        pi.status ?? "",
                        mapped,
                        new Date(),
                        row.id
                    ]);
                    if (mapped === "paid") {
                        const sess = await ctx.pool.query("select amount_minor, currency from fiat_payment_sessions where id=$1 limit 1", [row.id]);
                        const s = sess.rows[0];
                        if (s) {
                            await ctx.pool.query("insert into ledger_entries (id, payment_id, amount_minor, currency, stripe_payment_intent_id, created_at) select $1,$2,$3,$4,$5,$6 where not exists (select 1 from ledger_entries where payment_id=$2)", [crypto.randomUUID(), row.id, s.amount_minor, s.currency, piId, new Date()]);
                        }
                    }
                    if (mapped === "refunded") {
                        const sess = await ctx.pool.query("select amount_minor, currency from fiat_payment_sessions where id=$1 limit 1", [row.id]);
                        const s = sess.rows[0];
                        if (s) {
                            await ctx.pool.query("insert into ledger_entries (id, payment_id, amount_minor, currency, stripe_payment_intent_id, created_at) select $1,$2,$3,$4,$5,$6 where not exists (select 1 from ledger_entries where payment_id=$2 and amount_minor < 0)", [crypto.randomUUID(), row.id, -Math.abs(Number(s.amount_minor)), s.currency, piId, new Date()]);
                        }
                    }
                    await ctx.pool.query("commit");
                    updated++;
                }
                catch (err) {
                    await ctx.pool.query("rollback");
                    throw err;
                }
            }
            res.json({ status: "ok", checked: result.rowCount, updated });
        }
        catch (err) {
            next(err);
        }
    });
    return router;
}
function mapStripePaymentIntentStatus(input) {
    if (input.eventType === "payment_intent.payment_failed")
        return "failed";
    if (input.eventType === "payment_intent.canceled")
        return "canceled";
    if (input.eventType === "payment_intent.succeeded")
        return "paid";
    const s = String(input.status ?? "");
    if (s === "succeeded")
        return "paid";
    if (s === "canceled")
        return "canceled";
    if (s === "processing")
        return "processing";
    if (s === "requires_confirmation" || s === "requires_action" || s === "requires_capture")
        return "processing";
    if (s === "requires_payment_method")
        return "initiated";
    return "initiated";
}
function mapStripeEventToPaymentStatus(event) {
    if (event.type === "charge.refunded")
        return "refunded";
    if (event.type === "charge.dispute.created" || event.type === "charge.dispute.updated")
        return "disputed";
    if (event.type === "charge.dispute.closed") {
        const dispute = event.data.object;
        const st = typeof dispute.status === "string" ? dispute.status : "";
        if (st === "won")
            return "paid";
        if (st === "lost")
            return "failed";
        return "disputed";
    }
    const pi = event.data.object;
    return mapStripePaymentIntentStatus({ eventType: event.type, status: pi?.status });
}
function extractStripeStatusString(event) {
    if (event.type.startsWith("payment_intent.")) {
        const pi = event.data.object;
        return String(pi?.status ?? "");
    }
    if (event.type.startsWith("charge.")) {
        const charge = event.data.object;
        if (event.type === "charge.refunded")
            return "refunded";
        return String(charge?.status ?? "");
    }
    if (event.type.startsWith("charge.dispute.")) {
        const dispute = event.data.object;
        return String(dispute?.status ?? "");
    }
    return "";
}
function extractRefundAmountMinor(event) {
    if (event.type !== "charge.refunded")
        return null;
    const charge = event.data.object;
    return typeof charge.amount_refunded === "number" ? charge.amount_refunded : null;
}
async function resolvePaymentIntentIdForStripeEvent(stripe, event) {
    if (event.type.startsWith("payment_intent.")) {
        const pi = event.data.object;
        return typeof pi?.id === "string" ? pi.id : null;
    }
    if (event.type.startsWith("charge.")) {
        const charge = event.data.object;
        return typeof charge?.payment_intent === "string" ? charge.payment_intent : null;
    }
    if (event.type.startsWith("charge.dispute.")) {
        const dispute = event.data.object;
        const piId = dispute?.payment_intent;
        if (typeof piId === "string")
            return piId;
        const chargeId = typeof dispute.charge === "string" ? dispute.charge : null;
        if (!chargeId)
            return null;
        const charge = await stripe.charges.retrieve(chargeId);
        return typeof charge?.payment_intent === "string" ? charge.payment_intent : null;
    }
    return null;
}
function mapStripePaymentIntentReconciledStatus(pi) {
    const charges = pi?.charges?.data;
    const charge = Array.isArray(charges) ? charges[0] : undefined;
    if (charge && typeof charge.amount_refunded === "number" && charge.amount_refunded > 0)
        return "refunded";
    return mapStripePaymentIntentStatus({ eventType: null, status: pi.status });
}
//# sourceMappingURL=fiatPayments.js.map