import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createAccessToken, verifyAccessToken } from "./index.js";

function base64Url(bytes: Buffer) {
  return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function signHs256Jwt(opts: { header: Record<string, unknown>; payload: Record<string, unknown>; secret: string }) {
  const h = base64Url(Buffer.from(JSON.stringify(opts.header), "utf8"));
  const p = base64Url(Buffer.from(JSON.stringify(opts.payload), "utf8"));
  const toSign = `${h}.${p}`;
  const sig = crypto.createHmac("sha256", opts.secret).update(toSign).digest();
  return `${toSign}.${base64Url(sig)}`;
}

void test("verifyAccessToken accepts a valid token", () => {
  const secret = "s".repeat(32);
  const token = createAccessToken({
    secret,
    issuer: "verza",
    audience: "verza",
    ttlSeconds: 900,
    claims: { sub: "u1", email: "u@example.com", role: "user", sid: "s1" }
  });
  const claims = verifyAccessToken({ token, secret, issuer: "verza", audience: "verza" });
  assert.ok(claims);
  assert.equal(claims.sub, "u1");
  assert.equal(claims.email, "u@example.com");
  assert.equal(claims.role, "user");
  assert.equal(claims.sid, "s1");
});

void test("verifyAccessToken rejects issuer mismatch", () => {
  const secret = "s".repeat(32);
  const token = createAccessToken({
    secret,
    issuer: "iss",
    audience: "aud",
    ttlSeconds: 900,
    claims: { sub: "u1", email: "u@example.com", role: "user", sid: "s1" }
  });
  assert.equal(verifyAccessToken({ token, secret, issuer: "other", audience: "aud" }), null);
});

void test("verifyAccessToken rejects exp at current time", () => {
  const secret = "s".repeat(32);
  const now = Math.floor(Date.now() / 1000);
  const token = signHs256Jwt({
    secret,
    header: { alg: "HS256", typ: "JWT" },
    payload: { sub: "u1", email: "u@example.com", role: "user", sid: "s1", iat: now - 10, exp: now }
  });
  assert.equal(verifyAccessToken({ token, secret, issuer: "verza", audience: "verza" }), null);
});

void test("verifyAccessToken rejects missing required claims", () => {
  const secret = "s".repeat(32);
  const now = Math.floor(Date.now() / 1000);
  const token = signHs256Jwt({
    secret,
    header: { alg: "HS256", typ: "JWT" },
    payload: { sub: "u1", email: "u@example.com", role: "user", iat: now, exp: now + 60 }
  });
  assert.equal(verifyAccessToken({ token, secret, issuer: "verza", audience: "verza" }), null);
});

void test("verifyAccessToken rejects wrong header values even if signature matches", () => {
  const secret = "s".repeat(32);
  const now = Math.floor(Date.now() / 1000);
  const token = signHs256Jwt({
    secret,
    header: { alg: "none", typ: "JWT" },
    payload: { sub: "u1", email: "u@example.com", role: "user", sid: "s1", iat: now, exp: now + 60 }
  });
  assert.equal(verifyAccessToken({ token, secret, issuer: "verza", audience: "verza" }), null);
});

void test("verifyAccessToken rejects signature mismatch", () => {
  const secret = "s".repeat(32);
  const token = createAccessToken({
    secret,
    issuer: "verza",
    audience: "verza",
    ttlSeconds: 900,
    claims: { sub: "u1", email: "u@example.com", role: "user", sid: "s1" }
  });
  const tampered = token.replace(/\.[^.]+$/, ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(verifyAccessToken({ token: tampered, secret, issuer: "verza", audience: "verza" }), null);
});

void test("verifyAccessToken rejects malformed tokens", () => {
  const secret = "s".repeat(32);
  assert.equal(verifyAccessToken({ token: "abc", secret, issuer: "verza", audience: "verza" }), null);
  assert.equal(verifyAccessToken({ token: "a.b.c.d", secret, issuer: "verza", audience: "verza" }), null);
  assert.equal(verifyAccessToken({ token: "!!..", secret, issuer: "verza", audience: "verza" }), null);
});
