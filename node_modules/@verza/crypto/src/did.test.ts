import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { verifyDidSignedRequest } from "./index.js";

function didFromJwk(jwk: Record<string, unknown>) {
  const encoded = Buffer.from(JSON.stringify(jwk), "utf8").toString("base64url");
  return `did:jwk:${encoded}`;
}

function base64Url(bytes: Buffer) {
  return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

void test("verifyDidSignedRequest accepts a valid did:jwk signature", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const did = didFromJwk(jwk);

  const method = "POST";
  const path = "/v1/verifications";
  const timestamp = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const rawBody = Buffer.from(JSON.stringify({ hello: "world" }), "utf8");
  const bodyHashHex = crypto.createHash("sha256").update(rawBody).digest("hex");
  const canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHashHex}`;

  const sig = crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey);
  const ok = verifyDidSignedRequest({
    method,
    path,
    timestamp,
    nonce,
    rawBody,
    did,
    signature: base64Url(sig)
  });
  assert.equal(ok, true);
});

void test("verifyDidSignedRequest rejects mismatched body", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const did = didFromJwk(jwk);

  const method = "POST";
  const path = "/v1/verifications";
  const timestamp = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const rawBody = Buffer.from("{}", "utf8");
  const bodyHashHex = crypto.createHash("sha256").update(rawBody).digest("hex");
  const canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHashHex}`;
  const sig = crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey);

  const ok = verifyDidSignedRequest({
    method,
    path,
    timestamp,
    nonce,
    rawBody: Buffer.from('{"different":true}', "utf8"),
    did,
    signature: sig.toString("base64")
  });
  assert.equal(ok, false);
});

void test("verifyDidSignedRequest rejects old timestamps", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const did = didFromJwk(jwk);

  const method = "POST";
  const path = "/v1/verifications";
  const timestamp = new Date(Date.now() - 10 * 60_000).toISOString();
  const nonce = crypto.randomUUID();
  const rawBody = Buffer.from("{}", "utf8");
  const bodyHashHex = crypto.createHash("sha256").update(rawBody).digest("hex");
  const canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHashHex}`;
  const sig = crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey);

  assert.equal(
    verifyDidSignedRequest({ method, path, timestamp, nonce, rawBody, did, signature: base64Url(sig) }),
    false
  );
});

void test("verifyDidSignedRequest rejects future timestamps", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const did = didFromJwk(jwk);

  const method = "POST";
  const path = "/v1/verifications";
  const timestamp = new Date(Date.now() + 90_000).toISOString();
  const nonce = crypto.randomUUID();
  const rawBody = Buffer.from("{}", "utf8");
  const bodyHashHex = crypto.createHash("sha256").update(rawBody).digest("hex");
  const canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHashHex}`;
  const sig = crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey);

  assert.equal(
    verifyDidSignedRequest({ method, path, timestamp, nonce, rawBody, did, signature: base64Url(sig) }),
    false
  );
});
