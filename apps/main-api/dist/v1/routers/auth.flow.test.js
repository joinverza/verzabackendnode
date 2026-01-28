import assert from "node:assert/strict";
import test from "node:test";
import express from "express";
import { createServer } from "node:http";
import { sha256Hex } from "@verza/crypto";
import { errorHandler, notFoundHandler } from "@verza/http";
import { createAuthRouter } from "./auth.js";
void test("auth flow: signup -> login -> refresh -> logout", async () => {
    const app = express();
    app.use(express.json());
    const usersByEmail = new Map();
    const usersById = new Map();
    const sessionsById = new Map();
    const sessionsByRefreshHash = new Map();
    const pool = {
        query: async (sql, params = []) => {
            const q = sql.replace(/\s+/g, " ").trim().toLowerCase();
            if (q.startsWith("select id from users where email=$1")) {
                const email = typeof params[0] === "string" ? params[0] : "";
                const u = usersByEmail.get(email);
                return { rowCount: u ? 1 : 0, rows: u ? [{ id: u.id }] : [] };
            }
            if (q.startsWith("insert into users")) {
                const [id, email, name, password_hash] = params;
                const row = {
                    id,
                    email,
                    name,
                    password_hash,
                    role: "user",
                    twofa_enabled: false,
                    twofa_secret: "",
                    backup_codes_sha: "[]"
                };
                usersByEmail.set(email, row);
                usersById.set(id, row);
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into sessions")) {
                const [id, user_id, refresh_token_hash, created_at, expires_at, user_agent, ip] = params;
                const row = { id, user_id, refresh_token_hash, created_at, expires_at, revoked_at: null, user_agent, ip };
                sessionsById.set(id, row);
                sessionsByRefreshHash.set(refresh_token_hash, row);
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select id,email,password_hash,role,twofa_enabled,twofa_secret,backup_codes_sha from users where email=$1")) {
                const email = typeof params[0] === "string" ? params[0] : "";
                const u = usersByEmail.get(email);
                return { rowCount: u ? 1 : 0, rows: u ? [u] : [] };
            }
            if (q.startsWith("update users set last_login_at=$1")) {
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select s.id, s.user_id, s.expires_at, s.revoked_at, u.role, u.email from sessions s join users u")) {
                const refreshHash = typeof params[0] === "string" ? params[0] : "";
                const s = sessionsByRefreshHash.get(refreshHash);
                if (!s)
                    return { rowCount: 0, rows: [] };
                const u = usersById.get(s.user_id);
                if (!u)
                    return { rowCount: 0, rows: [] };
                return { rowCount: 1, rows: [{ id: s.id, user_id: s.user_id, expires_at: s.expires_at, revoked_at: s.revoked_at, role: u.role, email: u.email }] };
            }
            if (q.startsWith("update sessions set refresh_token_hash=$1")) {
                const [newHash, newExpiresAt, id] = params;
                const s = sessionsById.get(id);
                if (!s)
                    return { rowCount: 0, rows: [] };
                sessionsByRefreshHash.delete(s.refresh_token_hash);
                s.refresh_token_hash = newHash;
                s.expires_at = newExpiresAt;
                sessionsByRefreshHash.set(newHash, s);
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("update sessions set revoked_at=$1 where id=$2 and user_id=$3")) {
                const [revokedAt, id, userId] = params;
                const s = sessionsById.get(id);
                if (s && s.user_id === userId)
                    s.revoked_at = revokedAt;
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("update sessions set revoked_at=$1 where user_id=$2")) {
                const [revokedAt, userId] = params;
                for (const s of sessionsById.values()) {
                    if (s.user_id === userId && !s.revoked_at)
                        s.revoked_at = revokedAt;
                }
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("insert into password_reset_tokens")) {
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("update password_reset_tokens set used_at=$1")) {
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("update users set password_hash=$1")) {
                return { rowCount: 1, rows: [] };
            }
            if (q.startsWith("select user_id, expires_at, used_at from password_reset_tokens")) {
                return { rowCount: 0, rows: [] };
            }
            throw new Error(`Unhandled SQL in test stub: ${sql}`);
        }
    };
    const logger = { error: () => { }, info: () => { } };
    app.use("/auth", createAuthRouter({
        pool,
        logger,
        config: {
            JWT_SECRET: "x".repeat(32),
            JWT_ISSUER: "",
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
            STRIPE_SECRET_KEY: "",
            STRIPE_WEBHOOK_SECRET: "",
            RECEIPT_ED25519_SEED_B64: "x",
            ENCRYPTION_MASTER_KEY_B64: "x",
            REDIS_URL: ""
        }
    }));
    app.use(notFoundHandler);
    app.use(errorHandler());
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}/auth`;
    const signup = await fetch(`${baseUrl}/signup`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "a@example.com", password: "password123", name: "A" })
    });
    assert.equal(signup.status, 200);
    const signupBody = (await signup.json());
    assert.equal(typeof signupBody.access_token, "string");
    assert.equal(typeof signupBody.refresh_token, "string");
    assert.equal(typeof signupBody.user?.id, "string");
    const login = await fetch(`${baseUrl}/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "a@example.com", password: "password123" })
    });
    assert.equal(login.status, 200);
    const loginBody = (await login.json());
    assert.equal(typeof loginBody.access_token, "string");
    assert.equal(typeof loginBody.refresh_token, "string");
    assert.equal(typeof loginBody.user?.id, "string");
    const refreshHash = sha256Hex(String(loginBody.refresh_token));
    const session = sessionsByRefreshHash.get(refreshHash);
    assert.ok(session);
    const refresh = await fetch(`${baseUrl}/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: loginBody.refresh_token })
    });
    assert.equal(refresh.status, 200);
    const refreshBody = (await refresh.json());
    assert.equal(typeof refreshBody.access_token, "string");
    assert.equal(typeof refreshBody.refresh_token, "string");
    const logout = await fetch(`${baseUrl}/logout`, {
        method: "POST",
        headers: { authorization: `Bearer ${refreshBody.access_token}` }
    });
    assert.equal(logout.status, 200);
    assert.deepEqual(await logout.json(), { status: "ok" });
    const logoutSession = sessionsById.get(session.id);
    assert.ok(logoutSession?.revoked_at);
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
//# sourceMappingURL=auth.flow.test.js.map