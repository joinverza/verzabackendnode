import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import express from "express";
import { createServer } from "node:http";
import { errorHandler, notFoundHandler } from "@verza/http";
import { createIdentityVerificationsRouter } from "./identityVerifications.js";
void test("identity verifications orchestrator flow via gateway", async () => {
    const gatewaySeen = [];
    const gateway = express();
    gateway.use(express.json());
    gateway.post("/v1/verifications", (req, res) => {
        gatewaySeen.push({ method: "POST", path: req.path });
        res.json({ id: "prov-1", status: "created" });
    });
    gateway.get("/v1/verifications/prov-1", (req, res) => {
        gatewaySeen.push({ method: "GET", path: req.path });
        res.json({ id: "prov-1", user_id: "user-1", type: "kyc", subject_id: null, status: "completed", attempt_count: 1, last_error: "", completed_at: new Date().toISOString(), created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    });
    gateway.post("/v1/media/presign", (req, res) => {
        gatewaySeen.push({ method: "POST", path: req.path });
        res.json({ url: "http://example.com/put", method: "PUT", headers: { "content-type": String(req.body?.content_type ?? "") } });
    });
    gateway.post("/v1/verifications/prov-1/media", (req, res) => {
        gatewaySeen.push({ method: "POST", path: req.path });
        res.json({ status: "ok" });
    });
    gateway.post("/v1/verifications/prov-1/run", (req, res) => {
        gatewaySeen.push({ method: "POST", path: req.path });
        res.json({ status: "completed" });
    });
    gateway.get("/v1/verifications/prov-1/audit", (_req, res) => {
        gatewaySeen.push({ method: "GET", path: "/v1/verifications/prov-1/audit" });
        res.json([
            { id: "a1", verification_id: "prov-1", type: "inference_completed", data: { ok: true }, created_at: new Date().toISOString() }
        ]);
    });
    const gatewayServer = createServer(gateway);
    await new Promise((resolve) => gatewayServer.listen(0, "127.0.0.1", resolve));
    const gatewayAddr = gatewayServer.address();
    const gatewayUrl = `http://127.0.0.1:${gatewayAddr.port}`;
    const verificationsById = new Map();
    const auditByVerification = new Map();
    const auditChains = new Map();
    const pool = {
        query: async (sql, params = []) => {
            const q = sql.replace(/\s+/g, " ").trim().toLowerCase();
            if (q === "begin" || q === "commit" || q === "rollback") {
                return { rowCount: 0, rows: [] };
            }
            if (q.startsWith("select next_seq, head_hash from audit_chains where tenant_id=$1 and stream=$2")) {
                const [tenantId, stream] = params;
                const key = `${tenantId}:${stream}`;
                const row = auditChains.get(key);
                if (!row)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ next_seq: row.next_seq, head_hash: row.head_hash }] };
            }
            if (q.startsWith("insert into audit_chains (tenant_id, stream, next_seq, head_hash, updated_at) values")) {
                const [tenantId, stream] = params;
                const key = `${tenantId}:${stream}`;
                if (!auditChains.has(key))
                    auditChains.set(key, { next_seq: 1, head_hash: "" });
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("update audit_chains set next_seq=next_seq+1, head_hash=$1, updated_at=$2 where tenant_id=$3 and stream=$4")) {
                const [headHash, , tenantId, stream] = params;
                const key = `${tenantId}:${stream}`;
                const row = auditChains.get(key) ?? { next_seq: 1, head_hash: "" };
                auditChains.set(key, { next_seq: row.next_seq + 1, head_hash: headHash });
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into audit_events (id,tenant_id,stream,seq,prev_hash,event_hash,event_type")) {
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into identity_verifications")) {
                const [id, tenant_id, user_id, credential_id, status, provider, document_type, confidence_threshold, scores_json, reasons_json, signals_json, locale, client_timestamp, geo_lat, geo_lon, ip, user_agent, server_received_at, standard, verifier_reference] = params;
                verificationsById.set(id, {
                    id,
                    tenant_id,
                    user_id,
                    credential_id,
                    status,
                    provider,
                    document_type,
                    confidence_threshold,
                    scores_json,
                    reasons_json,
                    signals_json,
                    locale,
                    client_timestamp,
                    geo_lat,
                    geo_lon,
                    ip,
                    user_agent,
                    server_received_at,
                    standard,
                    verifier_reference,
                    completed_at: null,
                    verifier_institution_id: null
                });
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into identity_verification_audit_events")) {
                const [id, tenant_id, verification_id, user_id, event_type, data_json, created_at] = params;
                const arr = auditByVerification.get(verification_id) ?? [];
                arr.push({ id, tenant_id, verification_id, user_id, event_type, data_json, created_at });
                auditByVerification.set(verification_id, arr);
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select id,user_id,credential_id,status,provider")) {
                const [tenantId, userId] = params;
                const rows = [...verificationsById.values()].filter((r) => r.tenant_id === tenantId && r.user_id === userId);
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("select * from identity_verifications where id=$1 and tenant_id=$2")) {
                const [id, tenantId] = params;
                const row = verificationsById.get(id);
                if (!row || row.tenant_id !== tenantId)
                    return { rowCount: 0, rows: [] };
                return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
            }
            if (q.startsWith("select provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2")) {
                const [id, tenantId] = params;
                const row = verificationsById.get(id);
                if (!row || row.tenant_id !== tenantId)
                    return { rowCount: 0, rows: [] };
                return { rowCount: row ? 1 : 0, rows: row ? [{ provider: row.provider, verifier_reference: row.verifier_reference }] : [] };
            }
            if (q.startsWith("select status, provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2")) {
                const [id, tenantId] = params;
                const row = verificationsById.get(id);
                if (!row || row.tenant_id !== tenantId)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ status: row.status, provider: row.provider, verifier_reference: row.verifier_reference }] };
            }
            if (q.startsWith("select id,verification_id,user_id,event_type")) {
                const [verificationId, tenantId] = params;
                const rows = (auditByVerification.get(verificationId) ?? [])
                    .filter((r) => r.tenant_id === tenantId)
                    .map((r) => ({
                    id: r.id,
                    verification_id: r.verification_id,
                    user_id: r.user_id,
                    event_type: r.event_type,
                    data_json: r.data_json,
                    created_at: r.created_at
                }));
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("update identity_verifications set status=$1")) {
                const [status, completedAt, id] = params;
                const row = verificationsById.get(id);
                if (!row)
                    return { rowCount: 0, rows: [] };
                row.status = status;
                if (status !== "pending" && !row.completed_at)
                    row.completed_at = completedAt;
                return { rowCount: 1, rows: [] };
            }
            throw new Error(`Unhandled SQL in test stub: ${sql}`);
        }
    };
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
        const headerUser = typeof req.headers["x-test-user"] === "string" ? req.headers["x-test-user"] : "user-1";
        req.auth = { userId: headerUser, role: "user", sessionId: `sess-${headerUser}`, email: "u@example.com", tenantId: "t-1" };
        next();
    });
    app.use("/identity/verifications", createIdentityVerificationsRouter({
        pool,
        logger: { error: () => { }, info: () => { } },
        config: { IDENTITY_GATEWAY_URL: gatewayUrl }
    }));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}`;
    const created = await fetch(`${baseUrl}/identity/verifications/request`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer token" },
        body: JSON.stringify({ provider: "orchestrator", document_type: "kyc" })
    });
    assert.equal(created.status, 201);
    const createdJson = (await created.json());
    assert.equal(createdJson.status, "pending");
    assert.equal(createdJson.verifier_reference, "prov-1");
    const otherTenantVerificationId = crypto.randomUUID();
    verificationsById.set(otherTenantVerificationId, {
        id: otherTenantVerificationId,
        tenant_id: "t-2",
        user_id: "user-1",
        credential_id: null,
        status: "pending",
        provider: "orchestrator",
        document_type: "kyc",
        confidence_threshold: 0.98,
        scores_json: "{}",
        reasons_json: "[]",
        signals_json: "{}",
        locale: "",
        client_timestamp: null,
        geo_lat: 0,
        geo_lon: 0,
        ip: "127.0.0.1",
        user_agent: "x",
        server_received_at: new Date(),
        standard: "orchestrator_v2",
        verifier_reference: "prov-1",
        completed_at: null,
        verifier_institution_id: null
    });
    const leaked = auditByVerification.get(createdJson.id) ?? [];
    leaked.push({
        id: crypto.randomUUID(),
        tenant_id: "t-2",
        verification_id: createdJson.id,
        user_id: "user-1",
        event_type: "leak_test",
        data_json: "{}",
        created_at: new Date()
    });
    auditByVerification.set(createdJson.id, leaked);
    const list = await fetch(`${baseUrl}/identity/verifications`, {
        headers: { authorization: "Bearer token" }
    });
    assert.equal(list.status, 200);
    const listJson = (await list.json());
    assert.ok(listJson.some((v) => v.id === createdJson.id));
    assert.ok(!listJson.some((v) => v.id === otherTenantVerificationId));
    const getOtherTenant = await fetch(`${baseUrl}/identity/verifications/${otherTenantVerificationId}`, {
        headers: { authorization: "Bearer token" }
    });
    assert.equal(getOtherTenant.status, 404);
    const presign = await fetch(`${baseUrl}/identity/verifications/${createdJson.id}/media/presign`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer token" },
        body: JSON.stringify({ key: "k", content_type: "image/jpeg" })
    });
    assert.equal(presign.status, 200);
    const presignJson = (await presign.json());
    assert.equal(presignJson.method, "PUT");
    const addMedia = await fetch(`${baseUrl}/identity/verifications/${createdJson.id}/media`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer token" },
        body: JSON.stringify({ key: "k", kind: "document" })
    });
    assert.equal(addMedia.status, 200);
    const run = await fetch(`${baseUrl}/identity/verifications/${createdJson.id}/run`, {
        method: "POST",
        headers: { authorization: "Bearer token", "idempotency-key": "k1" }
    });
    assert.equal(run.status, 200);
    const status = await fetch(`${baseUrl}/identity/verifications/${createdJson.id}/status`, {
        method: "POST",
        headers: { authorization: "Bearer token" }
    });
    assert.equal(status.status, 200);
    assert.deepEqual(await status.json(), { id: createdJson.id, status: "completed" });
    const audit = await fetch(`${baseUrl}/identity/verifications/${createdJson.id}/audit`, {
        headers: { authorization: "Bearer token" }
    });
    assert.equal(audit.status, 200);
    const auditJson = (await audit.json());
    assert.ok(auditJson.some((e) => e.event_type === "requested"));
    assert.ok(auditJson.some((e) => e.event_type === "inference_completed"));
    assert.ok(!auditJson.some((e) => e.event_type === "leak_test"));
    const otherAudit = await fetch(`${baseUrl}/identity/verifications/${otherTenantVerificationId}/audit`, {
        headers: { authorization: "Bearer token" }
    });
    assert.equal(otherAudit.status, 200);
    const otherAuditJson = (await otherAudit.json());
    assert.equal(otherAuditJson.length, 0);
    assert.ok(gatewaySeen.some((x) => x.path === "/v1/verifications"));
    assert.ok(gatewaySeen.some((x) => x.path === "/v1/verifications/prov-1"));
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    await new Promise((resolve, reject) => gatewayServer.close((err) => (err ? reject(err) : resolve())));
});
void test("identity verifications burst create/run/status stays healthy", async () => {
    const gateway = express();
    gateway.use(express.json());
    let providerSeq = 0;
    gateway.post("/v1/verifications", (_req, res) => {
        providerSeq += 1;
        res.json({ id: `prov-${providerSeq}`, status: "created" });
    });
    gateway.get("/v1/verifications/:id", (req, res) => {
        res.json({ id: req.params.id, user_id: "user-1", type: "kyc", subject_id: null, status: "completed", attempt_count: 1, last_error: "", completed_at: new Date().toISOString(), created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    });
    gateway.post("/v1/verifications/:id/run", (_req, res) => {
        res.json({ status: "completed" });
    });
    const gatewayServer = createServer(gateway);
    await new Promise((resolve) => gatewayServer.listen(0, "127.0.0.1", resolve));
    const gatewayAddr = gatewayServer.address();
    const gatewayUrl = `http://127.0.0.1:${gatewayAddr.port}`;
    const verificationsById = new Map();
    const auditByVerification = new Map();
    const auditChains = new Map();
    const pool = {
        query: async (sql, params = []) => {
            const q = sql.replace(/\s+/g, " ").trim().toLowerCase();
            if (q === "begin" || q === "commit" || q === "rollback") {
                return { rowCount: 0, rows: [] };
            }
            if (q.startsWith("select next_seq, head_hash from audit_chains where tenant_id=$1 and stream=$2")) {
                const [tenantId, stream] = params;
                const key = `${tenantId}:${stream}`;
                const row = auditChains.get(key);
                if (!row)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ next_seq: row.next_seq, head_hash: row.head_hash }] };
            }
            if (q.startsWith("insert into audit_chains (tenant_id, stream, next_seq, head_hash, updated_at) values")) {
                const [tenantId, stream] = params;
                const key = `${tenantId}:${stream}`;
                if (!auditChains.has(key))
                    auditChains.set(key, { next_seq: 1, head_hash: "" });
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("update audit_chains set next_seq=next_seq+1, head_hash=$1, updated_at=$2 where tenant_id=$3 and stream=$4")) {
                const [headHash, , tenantId, stream] = params;
                const key = `${tenantId}:${stream}`;
                const row = auditChains.get(key) ?? { next_seq: 1, head_hash: "" };
                auditChains.set(key, { next_seq: row.next_seq + 1, head_hash: headHash });
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into audit_events (id,tenant_id,stream,seq,prev_hash,event_hash,event_type")) {
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into identity_verifications")) {
                const [id, tenant_id, user_id, credential_id, status, provider, document_type, confidence_threshold, scores_json, reasons_json, signals_json, locale, client_timestamp, geo_lat, geo_lon, ip, user_agent, server_received_at, standard, verifier_reference] = params;
                verificationsById.set(id, {
                    id,
                    tenant_id,
                    user_id,
                    credential_id,
                    status,
                    provider,
                    document_type,
                    confidence_threshold,
                    scores_json,
                    reasons_json,
                    signals_json,
                    locale,
                    client_timestamp,
                    geo_lat,
                    geo_lon,
                    ip,
                    user_agent,
                    server_received_at,
                    standard,
                    verifier_reference,
                    completed_at: null,
                    verifier_institution_id: null
                });
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into identity_verification_audit_events")) {
                const [id, tenant_id, verification_id, user_id, event_type, data_json, created_at] = params;
                const arr = auditByVerification.get(verification_id) ?? [];
                arr.push({ id, tenant_id, verification_id, user_id, event_type, data_json, created_at });
                auditByVerification.set(verification_id, arr);
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select id,user_id,credential_id,status,provider")) {
                const [tenantId, userId] = params;
                const rows = [...verificationsById.values()].filter((r) => r.tenant_id === tenantId && r.user_id === userId);
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("select provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2")) {
                const [id, tenantId] = params;
                const row = verificationsById.get(id);
                if (!row || row.tenant_id !== tenantId)
                    return { rowCount: 0, rows: [] };
                return { rowCount: row ? 1 : 0, rows: row ? [{ provider: row.provider, verifier_reference: row.verifier_reference }] : [] };
            }
            if (q.startsWith("select status, provider, verifier_reference from identity_verifications where id=$1 and tenant_id=$2")) {
                const [id, tenantId] = params;
                const row = verificationsById.get(id);
                if (!row || row.tenant_id !== tenantId)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ status: row.status, provider: row.provider, verifier_reference: row.verifier_reference }] };
            }
            if (q.startsWith("update identity_verifications set status=$1")) {
                const [status, completedAt, id] = params;
                const row = verificationsById.get(id);
                if (!row)
                    return { rowCount: 0, rows: [] };
                row.status = status;
                if (status !== "pending" && !row.completed_at)
                    row.completed_at = completedAt;
                return { rowCount: 1, rows: [] };
            }
            throw new Error(`Unhandled SQL in test stub: ${sql}`);
        }
    };
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
        req.auth = { userId: "user-1", role: "user", sessionId: "sess-1", email: "u@example.com", tenantId: "t-1" };
        next();
    });
    app.use("/identity/verifications", createIdentityVerificationsRouter({
        pool,
        logger: { error: () => { }, info: () => { } },
        config: { IDENTITY_GATEWAY_URL: gatewayUrl }
    }));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}`;
    const createdByUser = new Map();
    for (let i = 0; i < 15; i += 1) {
        const userId = `user-${Math.floor(i / 5) + 1}`;
        const created = await fetch(`${baseUrl}/identity/verifications/request`, {
            method: "POST",
            headers: { "content-type": "application/json", authorization: "Bearer token", "x-test-user": userId },
            body: JSON.stringify({ provider: "orchestrator", document_type: "kyc" })
        });
        assert.equal(created.status, 201);
        const createdJson = (await created.json());
        const arr = createdByUser.get(userId) ?? [];
        arr.push(String(createdJson.id));
        createdByUser.set(userId, arr);
        const run = await fetch(`${baseUrl}/identity/verifications/${createdJson.id}/run`, {
            method: "POST",
            headers: { authorization: "Bearer token", "idempotency-key": `k-${i}`, "x-test-user": userId }
        });
        assert.equal(run.status, 200);
        const status = await fetch(`${baseUrl}/identity/verifications/${createdJson.id}/status`, {
            method: "POST",
            headers: { authorization: "Bearer token", "x-test-user": userId }
        });
        assert.equal(status.status, 200);
        assert.deepEqual(await status.json(), { id: createdJson.id, status: "completed" });
    }
    for (const [userId, ids] of createdByUser.entries()) {
        const list = await fetch(`${baseUrl}/identity/verifications`, {
            headers: { authorization: "Bearer token", "x-test-user": userId }
        });
        assert.equal(list.status, 200);
        const listJson = (await list.json());
        for (const id of ids)
            assert.ok(listJson.some((v) => v.id === id));
    }
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    await new Promise((resolve, reject) => gatewayServer.close((err) => (err ? reject(err) : resolve())));
});
void test("identity verifications orchestrator flow surfaces gateway failures", async () => {
    const gateway = express();
    gateway.use(express.json());
    gateway.post("/v1/verifications", (_req, res) => {
        res.status(500).json({ error: { code: "upstream", message: "gateway failed" } });
    });
    const gatewayServer = createServer(gateway);
    await new Promise((resolve) => gatewayServer.listen(0, "127.0.0.1", resolve));
    const gatewayAddr = gatewayServer.address();
    const gatewayUrl = `http://127.0.0.1:${gatewayAddr.port}`;
    const pool = {
        query: async () => {
            throw new Error("DB should not be called when gateway fails");
        }
    };
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
        req.auth = { userId: "user-1", role: "user", sessionId: "sess-1", email: "u@example.com", tenantId: "t-1" };
        next();
    });
    app.use("/identity/verifications", createIdentityVerificationsRouter({
        pool,
        logger: { error: () => { }, info: () => { } },
        config: { IDENTITY_GATEWAY_URL: gatewayUrl }
    }));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}`;
    const resp = await fetch(`${baseUrl}/identity/verifications/request`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer token" },
        body: JSON.stringify({ provider: "orchestrator", document_type: "kyc" })
    });
    assert.equal(resp.status, 400);
    const json = (await resp.json());
    assert.equal(json?.error?.code, "upstream");
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    await new Promise((resolve, reject) => gatewayServer.close((err) => (err ? reject(err) : resolve())));
});
//# sourceMappingURL=identityVerifications.flow.test.js.map