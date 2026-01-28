import assert from "node:assert/strict";
import test from "node:test";
import express from "express";
import { createServer } from "node:http";
import { errorHandler, notFoundHandler } from "@verza/http";
import { requireInstitutionApiKey } from "./index.js";
void test("requireInstitutionApiKey: missing key returns 401", async () => {
    const app = express();
    app.get("/x", requireInstitutionApiKey({
        config: { JWT_SECRET: "x".repeat(32), JWT_ISSUER: "" },
        pool: { query: async () => ({ rowCount: 0, rows: [] }) }
    }), (_req, res) => res.json({ ok: true }));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const resp = await fetch(`http://127.0.0.1:${addr.port}/x`);
    assert.equal(resp.status, 401);
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
void test("requireInstitutionApiKey: valid key sets req.institution", async () => {
    const app = express();
    app.get("/x", requireInstitutionApiKey({
        config: { JWT_SECRET: "x".repeat(32), JWT_ISSUER: "" },
        pool: {
            query: async () => ({
                rowCount: 1,
                rows: [{ id: "k1", institution_id: "i1", revoked_at: null, name: "Inst", status: "active" }]
            })
        }
    }), (req, res) => res.json({ institution: req.institution }));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const resp = await fetch(`http://127.0.0.1:${addr.port}/x`, { headers: { "x-institution-api-key": "raw-key" } });
    assert.equal(resp.status, 200);
    const body = (await resp.json());
    assert.deepEqual(body.institution, { id: "i1", name: "Inst", status: "active", apiKeyId: "k1" });
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
//# sourceMappingURL=requireInstitutionApiKey.test.js.map