import assert from "node:assert/strict";
import test from "node:test";

import express from "express";
import { createServer } from "node:http";

import { createAccessToken } from "@verza/auth";

import { createIdentityGatewayServer } from "./server.js";

void test("identity-gateway proxies sessions and passes key headers", async () => {
  const seen: { path: string; headers: Record<string, string | string[] | undefined>; body: any } = {
    path: "",
    headers: {},
    body: null
  };

  const orchestrator = express();
  orchestrator.use(express.json());
  orchestrator.post("/internal/v1/sessions", (req, res) => {
    seen.path = req.path;
    seen.headers = req.headers as any;
    seen.body = req.body;
    res.json({ ok: true, echoed: true });
  });
  const orchServer = createServer(orchestrator);
  await new Promise<void>((resolve) => orchServer.listen(0, "127.0.0.1", resolve));
  const orchAddr = orchServer.address() as any;

  const prevEnv = { ...process.env };
  process.env.HOST = "127.0.0.1";
  process.env.PORT = "0";
  process.env.ORCHESTRATOR_URL = `http://127.0.0.1:${orchAddr.port}`;
  process.env.JWT_SECRET = "x".repeat(32);
  process.env.JWT_ISSUER = "verza";
  process.env.JWT_AUDIENCE = "verza";
  process.env.S3_ENDPOINT = "http://127.0.0.1:9000";
  process.env.S3_ACCESS_KEY_ID = "x";
  process.env.S3_SECRET_ACCESS_KEY = "y";
  process.env.S3_BUCKET = "b";
  process.env.S3_REGION = "us-east-1";
  process.env.S3_FORCE_PATH_STYLE = "1";
  process.env.METRICS_ENABLED = "0";
  process.env.CORS_ALLOWED_ORIGINS = "";

  const gw = createIdentityGatewayServer();
  const addr = await gw.start();
  const gwPort = addr.port;

  const token = createAccessToken({
    secret: process.env.JWT_SECRET,
    issuer: process.env.JWT_ISSUER,
    audience: process.env.JWT_AUDIENCE,
    ttlSeconds: 900,
    claims: { sub: "u1", email: "u1@example.com", role: "user", sid: "s1", tid: "t-1" }
  });

  const resp = await fetch(`http://127.0.0.1:${gwPort}/v1/sessions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-request-id": "rid",
      traceparent: "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
      authorization: `Bearer ${token}`
    },
    body: JSON.stringify({ user_id: "u1" })
  });
  assert.equal(resp.status, 200);
  assert.deepEqual(await resp.json(), { ok: true, echoed: true });

  assert.equal(seen.path, "/internal/v1/sessions");
  assert.equal(seen.headers["x-request-id"], "rid");
  assert.equal(seen.headers.traceparent, "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01");
  assert.equal(seen.headers.authorization, `Bearer ${token}`);
  assert.deepEqual(seen.body, { user_id: "u1" });

  await gw.stop();
  process.env = prevEnv;

  await new Promise<void>((resolve, reject) => orchServer.close((err) => (err ? reject(err) : resolve())));
});
