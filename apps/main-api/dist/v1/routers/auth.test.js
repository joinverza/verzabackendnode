import assert from "node:assert/strict";
import test from "node:test";
import express from "express";
import { createServer } from "node:http";
import { createAuthRouter } from "./auth.js";
void test("POST /forgot-password is always ok (no user)", async () => {
    const app = express();
    app.use(express.json());
    const pool = {
        query: async () => ({ rowCount: 0, rows: [] })
    };
    const logger = { error: () => { }, info: () => { } };
    app.use("/auth", createAuthRouter({
        pool,
        logger,
        config: {
            JWT_SECRET: "x".repeat(32),
            JWT_ISSUER: "verza",
            JWT_AUDIENCE: "verza",
            ACCESS_TOKEN_TTL_SECONDS: 900,
            REFRESH_TOKEN_TTL_SECONDS: 60 * 60 * 24 * 30,
            PASSWORD_RESET_BASE_URL: "",
            SMTP_HOST: "",
            SMTP_PORT: 0,
            SMTP_SECURE: false,
            SMTP_USER: "",
            SMTP_PASS: "",
            SMTP_FROM: "",
            TWILIO_ACCOUNT_SID: "",
            TWILIO_AUTH_TOKEN: "",
            TWILIO_FROM_NUMBER: "",
            RECEIPT_ED25519_SEED_B64: "x",
            ENCRYPTION_MASTER_KEY_B64: "x"
        }
    }));
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const url = `http://127.0.0.1:${addr.port}/auth/forgot-password`;
    const resp = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "nobody@example.com" })
    });
    assert.equal(resp.status, 200);
    assert.deepEqual(await resp.json(), { status: "ok" });
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
//# sourceMappingURL=auth.test.js.map