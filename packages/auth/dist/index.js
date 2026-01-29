import crypto from "node:crypto";
import { sha256Hex } from "@verza/crypto";
import { forbidden, unauthorized } from "@verza/http";
export function createAccessToken(opts) {
    const header = { alg: "HS256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: opts.issuer,
        aud: opts.audience,
        sub: opts.claims.sub,
        email: opts.claims.email,
        role: opts.claims.role,
        sid: opts.claims.sid,
        ...(opts.claims.tid ? { tid: opts.claims.tid } : {}),
        iat: now,
        exp: now + opts.ttlSeconds
    };
    return signHs256Jwt({ header, payload, secret: opts.secret });
}
export function generateRefreshToken() {
    const bytes = crypto.randomBytes(48);
    return base64Url(bytes);
}
export function verifyAccessToken(opts) {
    const parsed = verifyHs256Jwt({ token: opts.token, secret: opts.secret });
    if (!parsed)
        return null;
    const { payload } = parsed;
    if (typeof payload.sub !== "string" || typeof payload.email !== "string" || typeof payload.role !== "string" || typeof payload.sid !== "string") {
        return null;
    }
    if (typeof payload.iss !== "string" || typeof payload.aud !== "string")
        return null;
    if (typeof payload.exp !== "number" || typeof payload.iat !== "number")
        return null;
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now)
        return null;
    if (payload.iss !== opts.issuer)
        return null;
    if (payload.aud !== opts.audience)
        return null;
    return payload;
}
export function requireUser(ctx) {
    return (req, _res, next) => {
        try {
            const auth = req.header("authorization") ?? "";
            const m = auth.match(/^Bearer\s+(.+)$/i);
            if (!m?.[1])
                throw unauthorized("missing_auth", "Missing bearer token");
            const claims = verifyAccessToken({
                token: m[1],
                secret: ctx.config.JWT_SECRET,
                issuer: ctx.config.JWT_ISSUER,
                audience: ctx.config.JWT_AUDIENCE
            });
            if (!claims)
                throw unauthorized("invalid_token", "Invalid token");
            req.auth = { userId: claims.sub, role: claims.role, sessionId: claims.sid, email: claims.email, tenantId: claims.tid ?? "" };
            next();
        }
        catch (err) {
            next(err);
        }
    };
}
export function requireAdmin(ctx) {
    const user = requireUser(ctx);
    return (req, res, next) => {
        user(req, res, (err) => {
            if (err)
                return next(err);
            if (req.auth.role !== "admin")
                return next(forbidden("forbidden", "Admin required"));
            next();
        });
    };
}
export function requireInstitutionApiKey(ctx) {
    return (req, _res, next) => {
        void (async () => {
            const rawKey = req.header("x-institution-api-key") ??
                req.header("x-api-key") ??
                parseApiKeyAuthHeader(req.header("authorization") ?? "");
            if (!rawKey)
                throw unauthorized("missing_api_key", "Missing API key");
            const keyHash = sha256Hex(rawKey);
            const result = await ctx.pool.query("select k.id, k.institution_id, k.revoked_at, i.name, i.status, i.tenant_id from institution_api_keys k join institutions i on i.id = k.institution_id where k.key_hash=$1 limit 1", [keyHash]);
            const row = result.rows[0];
            if (!row)
                throw unauthorized("invalid_api_key", "Invalid API key");
            if (row.revoked_at)
                throw unauthorized("revoked_api_key", "API key revoked");
            if (row.status !== "active")
                throw unauthorized("inactive_institution", "Institution inactive");
            req.institution = { id: row.institution_id, name: row.name, status: row.status, apiKeyId: row.id, tenantId: row.tenant_id ?? "" };
            next();
        })().catch(next);
    };
}
function parseApiKeyAuthHeader(value) {
    const m = value.match(/^ApiKey\s+(.+)$/i);
    return m?.[1] ?? null;
}
export function generateTwoFactorSetup() {
    const secret = base32NoPadding(crypto.randomBytes(20));
    const backupCodes = [];
    for (let i = 0; i < 10; i++) {
        backupCodes.push(crypto.randomUUID().replaceAll("-", "").slice(0, 10));
    }
    return { secret, backupCodes };
}
export function verifyTotp(opts) {
    const code = opts.code.trim();
    if (!/^\d{6}$/.test(code))
        return false;
    const key = base32Decode(opts.secretBase32);
    if (!key)
        return false;
    const step = 30;
    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / step);
    for (const delta of [-1, 0, 1]) {
        const expected = totpAtCounter(key, counter + delta);
        if (timingSafeEqualStr(expected, code))
            return true;
    }
    return false;
}
export function verifyTwoFactorOrThrow(opts) {
    const codesSha = parseJsonArray(opts.backupCodesShaJson);
    if (opts.twofaCode && verifyTotp({ secretBase32: opts.totpSecretBase32, code: opts.twofaCode }))
        return {};
    if (opts.backupCode) {
        const h = sha256Hex(opts.backupCode);
        if (codesSha.includes(h))
            return { usedBackupCodeSha: h };
    }
    throw unauthorized("invalid_twofa", "Invalid 2FA code");
}
function parseJsonArray(s) {
    try {
        const parsed = JSON.parse(s || "[]");
        if (!Array.isArray(parsed))
            return [];
        return parsed.filter((x) => typeof x === "string");
    }
    catch {
        return [];
    }
}
function totpAtCounter(key, counter) {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(counter), 0);
    const hmac = crypto.createHmac("sha1", key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    return String(code % 1_000_000).padStart(6, "0");
}
function timingSafeEqualStr(a, b) {
    const aa = Buffer.from(a);
    const bb = Buffer.from(b);
    if (aa.length !== bb.length)
        return false;
    return crypto.timingSafeEqual(aa, bb);
}
const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32NoPadding(bytes) {
    let bits = 0;
    let value = 0;
    let output = "";
    for (const b of bytes) {
        value = (value << 8) | b;
        bits += 8;
        while (bits >= 5) {
            output += base32Alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0)
        output += base32Alphabet[(value << (5 - bits)) & 31];
    return output;
}
function base32Decode(input) {
    const s = input.replaceAll("=", "").toUpperCase().trim();
    let bits = 0;
    let value = 0;
    const out = [];
    for (const c of s) {
        const idx = base32Alphabet.indexOf(c);
        if (idx === -1)
            return null;
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            out.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return Buffer.from(out);
}
function signHs256Jwt(opts) {
    const h = base64Url(Buffer.from(JSON.stringify(opts.header), "utf8"));
    const p = base64Url(Buffer.from(JSON.stringify(opts.payload), "utf8"));
    const toSign = `${h}.${p}`;
    const sig = crypto.createHmac("sha256", opts.secret).update(toSign).digest();
    return `${toSign}.${base64Url(sig)}`;
}
function verifyHs256Jwt(opts) {
    const parts = opts.token.split(".");
    if (parts.length !== 3)
        return null;
    const [h, p, s] = parts;
    const toSign = `${h}.${p}`;
    const expected = crypto.createHmac("sha256", opts.secret).update(toSign).digest();
    const sig = base64UrlToBuf(s);
    if (!sig || sig.length !== expected.length)
        return null;
    if (!crypto.timingSafeEqual(sig, expected))
        return null;
    const headerJson = safeJson(base64UrlToBuf(h));
    if (!isRecord(headerJson))
        return null;
    if (headerJson.alg !== "HS256" || headerJson.typ !== "JWT")
        return null;
    const payloadJson = safeJson(base64UrlToBuf(p));
    if (!isRecord(payloadJson))
        return null;
    return { header: headerJson, payload: payloadJson };
}
function safeJson(buf) {
    if (!buf)
        return null;
    try {
        return JSON.parse(buf.toString("utf8"));
    }
    catch {
        return null;
    }
}
function isRecord(value) {
    return typeof value === "object" && value !== null;
}
function base64Url(bytes) {
    return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function base64UrlToBuf(s) {
    const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
    try {
        return Buffer.from(s.replaceAll("-", "+").replaceAll("_", "/") + pad, "base64");
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=index.js.map