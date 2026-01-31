import type { RequestHandler } from "express";
import type { Pool } from "pg";

import crypto from "node:crypto";

import { sha256Hex } from "@verza/crypto";
import { forbidden, unauthorized } from "@verza/http";

type JwtClaims = {
  iss: string;
  aud: string;
  sub: string;
  email: string;
  role: string;
  sid: string;
  tid?: string;
  iat: number;
  exp: number;
};

export function createAccessToken(opts: {
  secret: string;
  issuer: string;
  audience: string;
  ttlSeconds: number;
  claims: { sub: string; email: string; role: string; sid: string; tid?: string };
}) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload: JwtClaims = {
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

export function verifyAccessToken(opts: { token: string; secret: string; issuer: string; audience: string }) {
  const parsed = verifyHs256Jwt({ token: opts.token, secret: opts.secret });
  if (!parsed) return null;
  const { payload } = parsed;
  if (typeof payload.sub !== "string" || typeof payload.email !== "string" || typeof payload.role !== "string" || typeof payload.sid !== "string") {
    return null;
  }
  if (typeof payload.iss !== "string" || typeof payload.aud !== "string") return null;
  if (typeof payload.exp !== "number" || typeof payload.iat !== "number") return null;
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) return null;
  if (payload.iss !== opts.issuer) return null;
  if (payload.aud !== opts.audience) return null;
  return payload as JwtClaims;
}

export type AuthContext = {
  config: { JWT_SECRET: string; JWT_ISSUER: string; JWT_AUDIENCE: string };
};

export const PERMISSIONS = {
  ADMIN_BRIDGE_TRANSACTIONS_LIST: "admin.bridge.transactions.list",
  ADMIN_BRIDGE_TRANSACTION_READ: "admin.bridge.transactions.read",
  ADMIN_BRIDGE_TRANSACTION_STATUS_SET: "admin.bridge.transactions.status.set",
  ADMIN_BRIDGE_TRANSACTION_RETRY: "admin.bridge.transactions.retry",
  ADMIN_BRIDGE_CREDENTIAL_METADATA_READ: "admin.bridge.credential_metadata.read",
  ADMIN_BRIDGE_CREDENTIAL_METADATA_UPSERT: "admin.bridge.credential_metadata.upsert",

  ADMIN_INSTITUTIONS_LIST: "admin.institutions.list",
  ADMIN_INSTITUTIONS_CREATE: "admin.institutions.create",
  ADMIN_INSTITUTIONS_READ: "admin.institutions.read",
  ADMIN_INSTITUTIONS_STATUS_SET: "admin.institutions.status.set",
  ADMIN_INSTITUTIONS_API_KEYS_LIST: "admin.institutions.api_keys.list",
  ADMIN_INSTITUTIONS_API_KEYS_CREATE: "admin.institutions.api_keys.create",
  ADMIN_INSTITUTIONS_API_KEYS_REVOKE: "admin.institutions.api_keys.revoke",
  ADMIN_INSTITUTIONS_MEMBERS_LIST: "admin.institutions.members.list",
  ADMIN_INSTITUTIONS_MEMBERS_UPSERT: "admin.institutions.members.upsert",
  ADMIN_INSTITUTIONS_MEMBERS_UPDATE: "admin.institutions.members.update",

  ADMIN_COMPLIANCE_AUDIT_HEAD_READ: "admin.compliance.audit.head.read",
  ADMIN_COMPLIANCE_AUDIT_EVENTS_LIST: "admin.compliance.audit.events.list",
  ADMIN_COMPLIANCE_AUDIT_EXPORT: "admin.compliance.audit.export",
  ADMIN_COMPLIANCE_AUDIT_VERIFY: "admin.compliance.audit.verify",
  ADMIN_COMPLIANCE_REPORTS_SUMMARY_READ: "admin.compliance.reports.summary.read",
  ADMIN_COMPLIANCE_EVIDENCE_CREATE: "admin.compliance.evidence.create",
  ADMIN_COMPLIANCE_EVIDENCE_READ: "admin.compliance.evidence.read",
  ADMIN_COMPLIANCE_PRIVACY_REQUESTS_LIST: "admin.compliance.privacy.requests.list",
  ADMIN_COMPLIANCE_RETENTION_POLICY_SET: "admin.compliance.privacy.retention.set",
  ADMIN_COMPLIANCE_RETENTION_RUN: "admin.compliance.privacy.retention.run"
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export function requireUser(ctx: AuthContext): RequestHandler {
  return (req, _res, next) => {
    try {
      const auth = req.header("authorization") ?? "";
      const m = auth.match(/^Bearer\s+(.+)$/i);
      if (!m?.[1]) throw unauthorized("missing_auth", "Missing bearer token");
      const claims = verifyAccessToken({
        token: m[1],
        secret: ctx.config.JWT_SECRET,
        issuer: ctx.config.JWT_ISSUER,
        audience: ctx.config.JWT_AUDIENCE
      });
      if (!claims) throw unauthorized("invalid_token", "Invalid token");
      req.auth = { userId: claims.sub, role: claims.role, sessionId: claims.sid, email: claims.email, tenantId: claims.tid ?? "" };
      next();
    } catch (err) {
      next(err);
    }
  };
}

export function requireAdmin(ctx: AuthContext): RequestHandler {
  const user = requireUser(ctx);
  return (req, res, next) => {
    user(req, res, (err) => {
      if (err) return next(err);
      if (req.auth.role !== "admin") return next(forbidden("forbidden", "Admin required"));
      next();
    });
  };
}

export type RequirePermissionArgs = {
  action: Permission;
  tenantId?: (req: Parameters<RequestHandler>[0]) => string | null;
};

export function requirePermission(ctx: AuthContext, args: RequirePermissionArgs): RequestHandler {
  const ensure = requireUser(ctx);
  return (req, res, next) => {
    const done = (err?: unknown) => {
      if (err) return next(err);
      if (!isActionAllowed(req.auth.role, args.action)) return next(forbidden("forbidden", "Permission denied"));
      const actionTenantId = args.tenantId ? args.tenantId(req) : null;
      if (actionTenantId && req.auth.tenantId && actionTenantId !== req.auth.tenantId) return next(forbidden("forbidden", "Cross-tenant access denied"));
      next();
    };

    const hasAuth = Boolean((req as any)?.auth?.userId);
    if (hasAuth) return done();
    ensure(req, res, done);
  };
}

function isActionAllowed(role: string, action: Permission) {
  return role === "admin" && action.length > 0;
}

export type InstitutionAuthContext = {
  pool: Pool;
};

export function requireInstitutionApiKey(ctx: InstitutionAuthContext & AuthContext): RequestHandler {
  return (req, _res, next) => {
    void (async () => {
      const rawKey =
        req.header("x-institution-api-key") ??
        req.header("x-api-key") ??
        parseApiKeyAuthHeader(req.header("authorization") ?? "");
      if (!rawKey) throw unauthorized("missing_api_key", "Missing API key");
      const keyHash = sha256Hex(rawKey);
      const result = await ctx.pool.query<{
        id: string;
        institution_id: string;
        revoked_at: Date | null;
        name: string;
        status: string;
        tenant_id: string;
      }>(
        "select k.id, k.institution_id, k.revoked_at, i.name, i.status, i.tenant_id from institution_api_keys k join institutions i on i.id = k.institution_id where k.key_hash=$1 limit 1",
        [keyHash]
      );
      const row = result.rows[0];
      if (!row) throw unauthorized("invalid_api_key", "Invalid API key");
      if (row.revoked_at) throw unauthorized("revoked_api_key", "API key revoked");
      if (row.status !== "active") throw unauthorized("inactive_institution", "Institution inactive");
      req.institution = { id: row.institution_id, name: row.name, status: row.status, apiKeyId: row.id, tenantId: row.tenant_id ?? "" };
      next();
    })().catch(next);
  };
}

function parseApiKeyAuthHeader(value: string) {
  const m = value.match(/^ApiKey\s+(.+)$/i);
  return m?.[1] ?? null;
}

declare module "express-serve-static-core" {
  interface Request {
    auth: { userId: string; role: string; sessionId: string; email: string; tenantId: string };
    institution: { id: string; name: string; status: string; apiKeyId: string; tenantId: string };
  }
}

export function generateTwoFactorSetup() {
  const secret = base32NoPadding(crypto.randomBytes(20));
  const backupCodes: string[] = [];
  for (let i = 0; i < 10; i++) {
    backupCodes.push(crypto.randomUUID().replaceAll("-", "").slice(0, 10));
  }
  return { secret, backupCodes };
}

export function verifyTotp(opts: { secretBase32: string; code: string }) {
  const code = opts.code.trim();
  if (!/^\d{6}$/.test(code)) return false;
  const key = base32Decode(opts.secretBase32);
  if (!key) return false;
  const step = 30;
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / step);
  for (const delta of [-1, 0, 1]) {
    const expected = totpAtCounter(key, counter + delta);
    if (timingSafeEqualStr(expected, code)) return true;
  }
  return false;
}

export function verifyTwoFactorOrThrow(opts: {
  totpSecretBase32: string;
  backupCodesShaJson: string;
  twofaCode?: string;
  backupCode?: string;
}) {
  const codesSha = parseJsonArray(opts.backupCodesShaJson);
  if (opts.twofaCode && verifyTotp({ secretBase32: opts.totpSecretBase32, code: opts.twofaCode })) return {};
  if (opts.backupCode) {
    const h = sha256Hex(opts.backupCode);
    if (codesSha.includes(h)) return { usedBackupCodeSha: h };
  }
  throw unauthorized("invalid_twofa", "Invalid 2FA code");
}

function parseJsonArray(s: string) {
  try {
    const parsed: unknown = JSON.parse(s || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((x): x is string => typeof x === "string");
  } catch {
    return [];
  }
}

function totpAtCounter(key: Buffer, counter: number) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter), 0);
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

function timingSafeEqualStr(a: string, b: string) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32NoPadding(bytes: Buffer) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      output += base32Alphabet[(value >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
  }
  if (bits > 0) output += base32Alphabet[(value << (5 - bits)) & 31]!;
  return output;
}

function base32Decode(input: string) {
  const s = input.replaceAll("=", "").toUpperCase().trim();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of s) {
    const idx = base32Alphabet.indexOf(c);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function signHs256Jwt(opts: { header: Record<string, unknown>; payload: Record<string, unknown>; secret: string }) {
  const h = base64Url(Buffer.from(JSON.stringify(opts.header), "utf8"));
  const p = base64Url(Buffer.from(JSON.stringify(opts.payload), "utf8"));
  const toSign = `${h}.${p}`;
  const sig = crypto.createHmac("sha256", opts.secret).update(toSign).digest();
  return `${toSign}.${base64Url(sig)}`;
}

function verifyHs256Jwt(opts: { token: string; secret: string }): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  const parts = opts.token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  const toSign = `${h}.${p}`;
  const expected = crypto.createHmac("sha256", opts.secret).update(toSign).digest();
  const sig = base64UrlToBuf(s);
  if (!sig || sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(sig, expected)) return null;
  const headerJson = safeJson(base64UrlToBuf(h));
  if (!isRecord(headerJson)) return null;
  if (headerJson.alg !== "HS256" || headerJson.typ !== "JWT") return null;
  const payloadJson = safeJson(base64UrlToBuf(p));
  if (!isRecord(payloadJson)) return null;
  return { header: headerJson, payload: payloadJson };
}

function safeJson(buf: Buffer | null): unknown {
  if (!buf) return null;
  try {
    return JSON.parse(buf.toString("utf8")) as unknown;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function base64Url(bytes: Buffer) {
  return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBuf(s: string) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  try {
    return Buffer.from(s.replaceAll("-", "+").replaceAll("_", "/") + pad, "base64");
  } catch {
    return null;
  }
}
