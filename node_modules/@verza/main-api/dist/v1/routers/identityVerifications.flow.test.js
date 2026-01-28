import assert from "node:assert/strict";
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
        res.json({ url: "http://example.com/put", method: "PUT", headers: { "content-type": String(req.body.content_type ?? "") } });
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
    const pool = {
        query: async (sql, params = []) => {
            const q = sql.replace(/\s+/g, " ").trim().toLowerCase();
            if (q.startsWith("insert into identity_verifications")) {
                const [id, user_id, credential_id, status, provider, document_type, confidence_threshold, scores_json, reasons_json, signals_json, locale, client_timestamp, geo_lat, geo_lon, ip, user_agent, server_received_at, standard, verifier_reference] = params;
                verificationsById.set(id, {
                    id,
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
                const [id, verification_id, user_id, event_type, data_json, created_at] = params;
                const arr = auditByVerification.get(verification_id) ?? [];
                arr.push({ id, verification_id, user_id, event_type, data_json, created_at });
                auditByVerification.set(verification_id, arr);
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select id,user_id,credential_id,status,provider")) {
                const [userId] = params;
                const rows = [...verificationsById.values()].filter((r) => r.user_id === userId);
                return { rowCount: rows.length, rows };
            }
            if (q.startsWith("select * from identity_verifications where id=$1")) {
                const [id] = params;
                const row = verificationsById.get(id);
                return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
            }
            if (q.startsWith("select provider, verifier_reference from identity_verifications where id=$1")) {
                const [id] = params;
                const row = verificationsById.get(id);
                return { rowCount: row ? 1 : 0, rows: row ? [{ provider: row.provider, verifier_reference: row.verifier_reference }] : [] };
            }
            if (q.startsWith("select status, provider, verifier_reference from identity_verifications where id=$1 and user_id=$2")) {
                const [id, userId] = params;
                const row = verificationsById.get(id);
                if (!row || row.user_id !== userId)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ status: row.status, provider: row.provider, verifier_reference: row.verifier_reference }] };
            }
            if (q.startsWith("select id,verification_id,user_id,event_type")) {
                const [verificationId] = params;
                const rows = (auditByVerification.get(verificationId) ?? []).map((r) => ({
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
        req.auth = { userId: "user-1", role: "user", sessionId: "sess-1", email: "u@example.com" };
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
    assert.ok(gatewaySeen.some((x) => x.path === "/v1/verifications"));
    assert.ok(gatewaySeen.some((x) => x.path === "/v1/verifications/prov-1"));
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    await new Promise((resolve, reject) => gatewayServer.close((err) => (err ? reject(err) : resolve())));
});
//# sourceMappingURL=identityVerifications.flow.test.js.map