import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import Stripe from "stripe";
import { createAccessToken, requireAdmin } from "@verza/auth";
import { sha256Hex } from "@verza/crypto";
import { createHttpApp, errorHandler, notFoundHandler } from "@verza/http";
import { createLogger } from "@verza/observability";
import { createAdminBridgeRouter } from "./adminBridge.js";
import { createAdminInstitutionsRouter } from "./adminInstitutions.js";
import { createFiatPaymentsRouter } from "./fiatPayments.js";
void test("fiat/stripe: webhook handles paid/refunded/disputed and idempotency", async () => {
    const sessionsById = new Map();
    const sessionsByPi = new Map();
    const webhookEventIds = new Set();
    const ledgerEntries = [];
    const pool = {
        query: async (sql, params = []) => {
            const q = sql.replace(/\s+/g, " ").trim().toLowerCase();
            if (q === "begin" || q === "commit" || q === "rollback")
                return { rowCount: 1, rows: [] };
            if (q.startsWith("insert into stripe_webhook_events")) {
                const [eventId] = params;
                if (webhookEventIds.has(eventId))
                    return { rowCount: 0, rows: [] };
                webhookEventIds.add(eventId);
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select id, amount_minor, currency from fiat_payment_sessions where stripe_payment_intent_id=$1")) {
                const [piId] = params;
                const row = sessionsByPi.get(piId);
                if (!row)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ id: row.id, amount_minor: row.amount_minor, currency: row.currency }] };
            }
            if (q.startsWith("update fiat_payment_sessions set stripe_status=$1")) {
                const [stripeStatus, status, , id] = params;
                const sess = sessionsById.get(id);
                if (!sess)
                    return { rowCount: 0, rows: [] };
                sess.stripe_status = stripeStatus;
                sess.status = status;
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into ledger_entries")) {
                const [, paymentId, amountMinor] = params;
                const alreadyPaid = ledgerEntries.some((e) => e.payment_id === paymentId);
                const alreadyRefunded = ledgerEntries.some((e) => e.payment_id === paymentId && e.amount_minor < 0);
                if (amountMinor < 0) {
                    if (alreadyRefunded)
                        return { rowCount: 0, rows: [] };
                    ledgerEntries.push({ payment_id: paymentId, amount_minor: amountMinor });
                    return { rowCount: 1, rows: [] };
                }
                if (alreadyPaid)
                    return { rowCount: 0, rows: [] };
                ledgerEntries.push({ payment_id: paymentId, amount_minor: amountMinor });
                return { rowCount: 1, rows: [] };
            }
            throw new Error(`Unhandled SQL in test stub: ${sql}`);
        }
    };
    const stripe = new Stripe("sk_test_123", { apiVersion: "2025-08-27.basil" });
    const webhookSecret = "whsec_test_123";
    const paymentId = "00000000-0000-0000-0000-000000000010";
    const piId = "pi_1";
    const baseSession = {
        id: paymentId,
        did_hash: "did_hash",
        amount_minor: 1000,
        currency: "USD",
        status: "initiated",
        stripe_status: "",
        stripe_payment_intent_id: piId
    };
    sessionsById.set(paymentId, baseSession);
    sessionsByPi.set(piId, baseSession);
    const logger = createLogger({ service: "main-api-test", level: "silent" });
    const app = createHttpApp({ logger, corsAllowedOrigins: [] });
    app.use("/api/v1/fiat/payments", createFiatPaymentsRouter({
        config: { STRIPE_WEBHOOK_SECRET: webhookSecret, RECEIPT_ED25519_SEED_B64: Buffer.alloc(32).toString("base64") },
        logger,
        pool,
        stripe
    }));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}`;
    const postStripeWebhook = async (event) => {
        const payload = JSON.stringify(event);
        const stripeWebhooks = stripe.webhooks;
        const signature = stripeWebhooks.generateTestHeaderString({ payload, secret: webhookSecret });
        const resp = await fetch(`${baseUrl}/api/v1/fiat/payments/stripe/webhook`, {
            method: "POST",
            headers: { "content-type": "application/json", "stripe-signature": signature },
            body: payload
        });
        assert.equal(resp.status, 200);
        assert.deepEqual(await resp.json(), { status: "ok" });
    };
    await postStripeWebhook({
        id: "evt_paid",
        object: "event",
        type: "payment_intent.succeeded",
        data: { object: { id: piId, object: "payment_intent", status: "succeeded" } }
    });
    assert.equal(baseSession.status, "paid");
    assert.equal(baseSession.stripe_status, "succeeded");
    assert.deepEqual(ledgerEntries, [{ payment_id: paymentId, amount_minor: 1000 }]);
    await postStripeWebhook({
        id: "evt_paid",
        object: "event",
        type: "payment_intent.succeeded",
        data: { object: { id: piId, object: "payment_intent", status: "succeeded" } }
    });
    assert.equal(ledgerEntries.length, 1);
    await postStripeWebhook({
        id: "evt_refund",
        object: "event",
        type: "charge.refunded",
        data: { object: { id: "ch_1", object: "charge", payment_intent: piId, amount_refunded: 500, status: "succeeded" } }
    });
    assert.equal(baseSession.status, "refunded");
    assert.equal(baseSession.stripe_status, "refunded");
    assert.equal(ledgerEntries.length, 2);
    assert.equal(ledgerEntries[1].amount_minor, -500);
    await postStripeWebhook({
        id: "evt_refund",
        object: "event",
        type: "charge.refunded",
        data: { object: { id: "ch_1", object: "charge", payment_intent: piId, amount_refunded: 500, status: "succeeded" } }
    });
    assert.equal(ledgerEntries.length, 2);
    await postStripeWebhook({
        id: "evt_dispute_closed_lost",
        object: "event",
        type: "charge.dispute.closed",
        data: { object: { id: "dp_1", object: "dispute", payment_intent: piId, status: "lost" } }
    });
    assert.equal(baseSession.status, "failed");
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
void test("fiat/stripe: reconcile updates pending sessions and writes ledger", async () => {
    const secret = "x".repeat(32);
    const token = createAccessToken({
        secret,
        issuer: "verza",
        audience: "verza",
        ttlSeconds: 900,
        claims: { sub: "00000000-0000-0000-0000-000000000001", email: "a@example.com", role: "admin", sid: "s1" }
    });
    const sessionsById = new Map();
    const sessionsByPi = new Map();
    const ledgerEntries = [];
    const pool = {
        query: async (sql, params = []) => {
            const q = sql.replace(/\s+/g, " ").trim().toLowerCase();
            if (q === "begin" || q === "commit" || q === "rollback")
                return { rowCount: 1, rows: [] };
            if (q.startsWith("select id, stripe_payment_intent_id from fiat_payment_sessions where stripe_payment_intent_id <> ''")) {
                const rows = Array.from(sessionsById.values())
                    .filter((s) => s.stripe_payment_intent_id && !["paid", "failed", "canceled"].includes(s.status))
                    .map((s) => ({ id: s.id, stripe_payment_intent_id: s.stripe_payment_intent_id }));
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("update fiat_payment_sessions set stripe_status=$1")) {
                const [stripeStatus, status, , id] = params;
                const sess = sessionsById.get(id);
                if (!sess)
                    return { rowCount: 0, rows: [] };
                sess.stripe_status = stripeStatus;
                sess.status = status;
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select amount_minor, currency from fiat_payment_sessions where id=$1")) {
                const [id] = params;
                const sess = sessionsById.get(id);
                if (!sess)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ amount_minor: sess.amount_minor, currency: sess.currency }] };
            }
            if (q.startsWith("insert into ledger_entries")) {
                const [, paymentId, amountMinor] = params;
                const alreadyPaid = ledgerEntries.some((e) => e.payment_id === paymentId);
                const alreadyRefunded = ledgerEntries.some((e) => e.payment_id === paymentId && e.amount_minor < 0);
                if (amountMinor < 0) {
                    if (alreadyRefunded)
                        return { rowCount: 0, rows: [] };
                    ledgerEntries.push({ payment_id: paymentId, amount_minor: amountMinor });
                    return { rowCount: 1, rows: [] };
                }
                if (alreadyPaid)
                    return { rowCount: 0, rows: [] };
                ledgerEntries.push({ payment_id: paymentId, amount_minor: amountMinor });
                return { rowCount: 1, rows: [] };
            }
            throw new Error(`Unhandled SQL in test stub: ${sql}`);
        }
    };
    const s1 = {
        id: "00000000-0000-0000-0000-000000000101",
        did_hash: "d",
        amount_minor: 1234,
        currency: "USD",
        status: "processing",
        stripe_status: "processing",
        stripe_payment_intent_id: "pi_paid"
    };
    const s2 = {
        id: "00000000-0000-0000-0000-000000000102",
        did_hash: "d",
        amount_minor: 2000,
        currency: "USD",
        status: "processing",
        stripe_status: "processing",
        stripe_payment_intent_id: "pi_refunded"
    };
    sessionsById.set(s1.id, s1);
    sessionsById.set(s2.id, s2);
    sessionsByPi.set(s1.stripe_payment_intent_id, s1);
    sessionsByPi.set(s2.stripe_payment_intent_id, s2);
    const fakeStripe = {
        paymentIntents: {
            retrieve: async (id) => {
                if (id === "pi_paid")
                    return { id, status: "succeeded", charges: { data: [{ amount_refunded: 0 }] } };
                if (id === "pi_refunded")
                    return { id, status: "succeeded", charges: { data: [{ amount_refunded: 100 }] } };
                throw new Error("unexpected pi id");
            }
        }
    };
    const logger = createLogger({ service: "main-api-test", level: "silent" });
    const app = createHttpApp({ logger, corsAllowedOrigins: [] });
    app.use("/api/v1/fiat/payments", createFiatPaymentsRouter({
        config: { JWT_SECRET: secret, JWT_ISSUER: "verza", JWT_AUDIENCE: "verza", RECEIPT_ED25519_SEED_B64: Buffer.alloc(32).toString("base64") },
        logger,
        pool,
        stripe: fakeStripe
    }));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}`;
    const resp = await fetch(`${baseUrl}/api/v1/fiat/payments/reconcile`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` }
    });
    assert.equal(resp.status, 200);
    assert.deepEqual(await resp.json(), { status: "ok", checked: 2, updated: 2 });
    assert.equal(s1.status, "paid");
    assert.equal(s2.status, "refunded");
    assert.equal(ledgerEntries.length, 2);
    assert.equal(ledgerEntries[0].amount_minor, 1234);
    assert.equal(ledgerEntries[1].amount_minor, -2000);
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
void test("admin/bridge: auth required and workflows behave", async () => {
    const secret = "x".repeat(32);
    const adminToken = createAccessToken({
        secret,
        issuer: "verza",
        audience: "verza",
        ttlSeconds: 900,
        claims: { sub: "00000000-0000-0000-0000-000000000001", email: "a@example.com", role: "admin", sid: "s1" }
    });
    const txId = "00000000-0000-0000-0000-000000000201";
    const txs = new Map();
    txs.set(txId, {
        id: txId,
        midnight_tx_hash: null,
        cardano_tx_hash: null,
        operation_type: "escrow",
        status: "pending",
        retry_count: 0,
        created_at: new Date(),
        updated_at: new Date()
    });
    const pool = {
        query: async (sql, params = []) => {
            const q = sql.replace(/\s+/g, " ").trim().toLowerCase();
            if (q.startsWith("select id, midnight_tx_hash") && q.includes("where id=$1")) {
                const [id] = params;
                const row = txs.get(id);
                return { rowCount: row ? 1 : 0, rows: row ? [{ ...row }] : [] };
            }
            if (q.startsWith("select id, midnight_tx_hash")) {
                const [limit, offset] = params;
                const rows = Array.from(txs.values())
                    .slice(offset, offset + limit)
                    .map((t) => ({ ...t }));
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("update cross_chain_transactions set status=$1")) {
                const [status, updatedAt, id] = params;
                const row = txs.get(id);
                if (!row)
                    return { rowCount: 0, rows: [] };
                row.status = status;
                row.updated_at = updatedAt;
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("update cross_chain_transactions set retry_count=retry_count+1")) {
                const [updatedAt, id] = params;
                const row = txs.get(id);
                if (!row)
                    return { rowCount: 0, rows: [] };
                row.retry_count += 1;
                row.status = "retry_requested";
                row.updated_at = updatedAt;
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select credential_id, midnight_address")) {
                return { rowCount: 0, rows: [] };
            }
            if (q.startsWith("insert into credential_metadata")) {
                return { rowCount: 1, rows: [] };
            }
            throw new Error(`Unhandled SQL in test stub: ${sql}`);
        }
    };
    const logger = createLogger({ service: "main-api-test", level: "silent" });
    const app = createHttpApp({ logger, corsAllowedOrigins: [] });
    const ctx = { config: { JWT_SECRET: secret, JWT_ISSUER: "verza", JWT_AUDIENCE: "verza" }, logger, pool };
    app.use("/admin/bridge", requireAdmin(ctx), createAdminBridgeRouter(ctx));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}`;
    const unauthorized = await fetch(`${baseUrl}/admin/bridge/transactions`);
    assert.equal(unauthorized.status, 401);
    const invalidLimit = await fetch(`${baseUrl}/admin/bridge/transactions?limit=0&offset=0`, {
        headers: { authorization: `Bearer ${adminToken}` }
    });
    assert.equal(invalidLimit.status, 400);
    const invalidLimitBody = (await invalidLimit.json());
    assert.equal(invalidLimitBody.error.code, "invalid_limit");
    const list = await fetch(`${baseUrl}/admin/bridge/transactions?limit=1&offset=0`, { headers: { authorization: `Bearer ${adminToken}` } });
    assert.equal(list.status, 200);
    const rows = (await list.json());
    assert.equal(rows.length, 1);
    const retry = await fetch(`${baseUrl}/admin/bridge/transactions/${txId}/retry`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}` }
    });
    assert.equal(retry.status, 200);
    assert.deepEqual(await retry.json(), { status: "ok" });
    assert.equal(txs.get(txId).retry_count, 1);
    assert.equal(txs.get(txId).status, "retry_requested");
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
void test("admin/institutions: api keys and members workflows behave", async () => {
    const secret = "x".repeat(32);
    const adminToken = createAccessToken({
        secret,
        issuer: "verza",
        audience: "verza",
        ttlSeconds: 900,
        claims: { sub: "00000000-0000-0000-0000-000000000001", email: "a@example.com", role: "admin", sid: "s1", tid: "t-1" }
    });
    const institutions = new Map();
    const apiKeys = new Map();
    const users = new Map();
    const members = new Map();
    const memberByInstitutionUser = new Map();
    const userId = "00000000-0000-0000-0000-000000000301";
    users.set(userId, { id: userId, email: "u@example.com", name: "User" });
    const pool = {
        query: async (sql, params = []) => {
            const q = sql.replace(/\s+/g, " ").trim().toLowerCase();
            if (q.includes("from institutions i") && q.includes("left join")) {
                const [tenantId] = params;
                const rows = Array.from(institutions.values())
                    .filter((i) => i.tenant_id === tenantId)
                    .map((i) => {
                    const member_count = Array.from(members.values()).filter((m) => m.institution_id === i.id).length;
                    const api_key_count = Array.from(apiKeys.values()).filter((k) => k.institution_id === i.id).length;
                    return { ...i, member_count, api_key_count };
                });
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("insert into institutions")) {
                const [id, tenantId, name, status, createdAt, updatedAt] = params;
                institutions.set(id, { id, tenant_id: tenantId, name, status, created_at: createdAt, updated_at: updatedAt });
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select id,name,status,created_at,updated_at from institutions where id=$1 and tenant_id=$2")) {
                const [id, tenantId] = params;
                const row = institutions.get(id);
                if (!row || row.tenant_id !== tenantId)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ ...row }] };
            }
            if (q.startsWith("update institutions set status=$1")) {
                const [status, updatedAt, id, tenantId] = params;
                const row = institutions.get(id);
                if (!row || row.tenant_id !== tenantId)
                    return { rowCount: 0, rows: [] };
                row.status = status;
                row.updated_at = updatedAt;
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select 1 as ok from institutions where id=$1 and tenant_id=$2")) {
                const [id, tenantId] = params;
                const row = institutions.get(id);
                if (!row || row.tenant_id !== tenantId)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ ok: 1 }] };
            }
            if (q.startsWith("insert into institution_api_keys")) {
                const [id, institutionId, , keyHash, last4] = params;
                apiKeys.set(id, { id, institution_id: institutionId, key_hash: keyHash, last4, revoked_at: null });
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select id, institution_id, name, last4, created_at, revoked_at from institution_api_keys")) {
                const [institutionId] = params;
                const rows = Array.from(apiKeys.values())
                    .filter((k) => k.institution_id === institutionId)
                    .map((k) => ({ ...k, created_at: new Date() }));
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("update institution_api_keys set revoked_at=$1")) {
                const [revokedAt, apiKeyId, institutionId] = params;
                const row = apiKeys.get(apiKeyId);
                if (!row || row.institution_id !== institutionId || row.revoked_at)
                    return { rowCount: 0, rows: [] };
                row.revoked_at = revokedAt;
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select 1 as ok from users where id=$1")) {
                const [id] = params;
                return { rowCount: users.has(id) ? 1 : 0, rows: users.has(id) ? [{ ok: 1 }] : [] };
            }
            if (q.startsWith("insert into institution_members") && q.includes("on conflict")) {
                const [id, institutionId, userIdParam, role, status, createdAt] = params;
                const key = `${institutionId}:${userIdParam}`;
                const existingId = memberByInstitutionUser.get(key);
                if (existingId) {
                    const existing = members.get(existingId);
                    existing.role = role;
                    existing.status = status;
                    return { rowCount: 1, rows: [{ id: existing.id }] };
                }
                members.set(id, { id, institution_id: institutionId, user_id: userIdParam, role, status, created_at: createdAt });
                memberByInstitutionUser.set(key, id);
                return { rowCount: 1, rows: [{ id }] };
            }
            if (q.startsWith("select im.id") && q.includes("from institution_members im") && q.includes("join users u")) {
                const [institutionId] = params;
                const rows = Array.from(members.values())
                    .filter((m) => m.institution_id === institutionId)
                    .map((m) => ({ ...m, email: users.get(m.user_id).email, name: users.get(m.user_id).name }));
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("update institution_members set role=coalesce")) {
                const [role, status, memberId, institutionId] = params;
                const row = members.get(memberId);
                if (!row || row.institution_id !== institutionId)
                    return { rowCount: 0, rows: [] };
                if (role)
                    row.role = role;
                if (status)
                    row.status = status;
                return { rowCount: 1, rows: [] };
            }
            throw new Error(`Unhandled SQL in test stub: ${sql}`);
        }
    };
    const logger = createLogger({ service: "main-api-test", level: "silent" });
    const app = createHttpApp({ logger, corsAllowedOrigins: [] });
    const ctx = { config: { JWT_SECRET: secret, JWT_ISSUER: "verza", JWT_AUDIENCE: "verza" }, logger, pool };
    app.use("/admin/institutions", requireAdmin(ctx), createAdminInstitutionsRouter(ctx));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}`;
    const created = await fetch(`${baseUrl}/admin/institutions`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "Test Inst" })
    });
    assert.equal(created.status, 201);
    const createdBody = (await created.json());
    const institutionId = createdBody.id;
    assert.ok(institutionId);
    const listed = await fetch(`${baseUrl}/admin/institutions`, { headers: { authorization: `Bearer ${adminToken}` } });
    assert.equal(listed.status, 200);
    const listBody = (await listed.json());
    assert.equal(listBody.length, 1);
    const apiKeyResp = await fetch(`${baseUrl}/admin/institutions/${institutionId}/api-keys`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
        body: JSON.stringify({ name: "k1" })
    });
    assert.equal(apiKeyResp.status, 201);
    const apiKeyBody = (await apiKeyResp.json());
    assert.equal(apiKeyBody.last4, apiKeyBody.api_key.slice(-4));
    const keyHash = sha256Hex(apiKeyBody.api_key);
    assert.equal(apiKeys.get(apiKeyBody.id).key_hash, keyHash);
    const memberCreate = await fetch(`${baseUrl}/admin/institutions/${institutionId}/members`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
        body: JSON.stringify({ user_id: userId })
    });
    assert.equal(memberCreate.status, 201);
    const memberBody = (await memberCreate.json());
    const memberId = memberBody.id;
    assert.ok(memberId);
    const memberList = await fetch(`${baseUrl}/admin/institutions/${institutionId}/members`, { headers: { authorization: `Bearer ${adminToken}` } });
    assert.equal(memberList.status, 200);
    const memberRows = (await memberList.json());
    assert.equal(memberRows.length, 1);
    assert.equal(memberRows[0].email, "u@example.com");
    const invalidUpdate = await fetch(`${baseUrl}/admin/institutions/${institutionId}/members/${memberId}`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
        body: JSON.stringify({})
    });
    assert.equal(invalidUpdate.status, 400);
    const invalidUpdateBody = (await invalidUpdate.json());
    assert.equal(invalidUpdateBody.error.code, "invalid_request");
    const updated = await fetch(`${baseUrl}/admin/institutions/${institutionId}/members/${memberId}`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
        body: JSON.stringify({ status: "suspended" })
    });
    assert.equal(updated.status, 200);
    assert.deepEqual(await updated.json(), { status: "ok" });
    const revoke = await fetch(`${baseUrl}/admin/institutions/${institutionId}/api-keys/${apiKeyBody.id}/revoke`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}` }
    });
    assert.equal(revoke.status, 200);
    assert.deepEqual(await revoke.json(), { status: "ok" });
    assert.ok(apiKeys.get(apiKeyBody.id).revoked_at);
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
//# sourceMappingURL=fiatPayments.flow.test.js.map