import assert from "node:assert/strict";
import test from "node:test";

import { createServer } from "node:http";

import { createAccessToken } from "@verza/auth";
import { createLogger } from "@verza/observability";

import { createIdentityOrchestratorApp } from "./server.js";

type VerificationRow = {
  id: string;
  user_id: string | null;
  type: string;
  subject_id: string | null;
  status: string;
  attempt_count: number;
  last_error: string;
  completed_at: Date | null;
  created_at: Date;
  updated_at: Date;
};

void test("identity-orchestrator flow: create -> media -> run sync completes", async () => {
  const userId = "00000000-0000-0000-0000-000000000001";
  const secret = "x".repeat(32);
  const token = createAccessToken({
    secret,
    issuer: "verza",
    audience: "verza",
    ttlSeconds: 900,
    claims: { sub: userId, email: "u@example.com", role: "user", sid: "s1" }
  });

  const verificationsById = new Map<string, VerificationRow>();
  const mediaByVerification = new Map<string, Array<{ key: string; kind: string }>>();
  const idempotency = new Set<string>();

  const pool = {
    query: async (sql: string, params: unknown[] = []) => {
      const q = sql.replace(/\s+/g, " ").trim().toLowerCase();

      if (q.startsWith("insert into identity_sessions")) {
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("insert into identity_verifications_v2")) {
        const [id, u, type, subjectId, status, createdAt, updatedAt] = params as [
          string,
          string,
          string,
          string | null,
          string,
          Date,
          Date
        ];
        verificationsById.set(id, {
          id,
          user_id: u,
          type,
          subject_id: subjectId ?? null,
          status,
          attempt_count: 0,
          last_error: "",
          completed_at: null,
          created_at: createdAt,
          updated_at: updatedAt
        });
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("insert into identity_verification_audit_v2")) {
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("select * from identity_verifications_v2 where id=$1 and user_id=$2")) {
        const [id, u] = params as [string, string];
        const row = verificationsById.get(id);
        if (!row || row.user_id !== u) return { rowCount: 0, rows: [] };
        return { rowCount: 1, rows: [row] };
      }

      if (q.startsWith("select * from identity_verifications_v2 where id=$1 limit 1")) {
        const [id] = params as [string];
        const row = verificationsById.get(id);
        if (!row) return { rowCount: 0, rows: [] };
        return { rowCount: 1, rows: [row] };
      }

      if (q.startsWith("update identity_verifications_v2 set status=$1")) {
        const [status, updatedAt, id] = params as [string, Date, string];
        const row = verificationsById.get(id);
        if (row) {
          row.status = status;
          row.updated_at = updatedAt;
        }
        return { rowCount: row ? 1 : 0, rows: [] };
      }

      if (q.startsWith("insert into identity_media")) {
        const [, verificationId, key, kind] = params as [string, string, string, string, Date];
        const arr = mediaByVerification.get(verificationId) ?? [];
        arr.push({ key, kind });
        mediaByVerification.set(verificationId, arr);
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("update identity_verifications_v2 set status='running'")) {
        const [updatedAt, id] = params as [Date, string];
        const row = verificationsById.get(id);
        if (!row) return { rowCount: 0, rows: [] };
        if (!["created", "collecting_media", "failed"].includes(row.status)) return { rowCount: 0, rows: [] };
        row.status = "running";
        row.updated_at = updatedAt;
        return { rowCount: 1, rows: [{ id }] };
      }

      if (q.startsWith("select key, kind from identity_media where verification_id=$1")) {
        const [verificationId] = params as [string];
        const rows = (mediaByVerification.get(verificationId) ?? []).map((m) => ({ key: m.key, kind: m.kind }));
        return { rowCount: rows.length, rows };
      }

      if (q.startsWith("insert into identity_inference_outputs_v2")) {
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("insert into identity_verification_decisions_v2")) {
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("update identity_verifications_v2 set status='completed'")) {
        const [completedAt, updatedAt, id] = params as [Date, Date, string];
        const row = verificationsById.get(id);
        if (!row) return { rowCount: 0, rows: [] };
        row.status = "completed";
        row.attempt_count += 1;
        row.last_error = "";
        row.completed_at = completedAt;
        row.updated_at = updatedAt;
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("update identity_verifications_v2 set status='failed'")) {
        const [msg, updatedAt, id] = params as [string, Date, string];
        const row = verificationsById.get(id);
        if (!row) return { rowCount: 0, rows: [] };
        row.status = "failed";
        row.attempt_count += 1;
        row.last_error = msg;
        row.updated_at = updatedAt;
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("insert into identity_idempotency")) {
        const [_id, verificationId, key] = params as [string, string, string, Date];
        const k = `${verificationId}:${key}`;
        if (idempotency.has(k)) return { rowCount: 0, rows: [] };
        idempotency.add(k);
        return { rowCount: 1, rows: [{ id: _id }] };
      }

      if (q.startsWith("update identity_verifications_v2 set status='queued'")) {
        const [updatedAt, id] = params as [Date, string];
        const row = verificationsById.get(id);
        if (!row) return { rowCount: 0, rows: [] };
        if (!["created", "collecting_media", "failed"].includes(row.status)) return { rowCount: 0, rows: [] };
        row.status = "queued";
        row.updated_at = updatedAt;
        return { rowCount: 1, rows: [{ id }] };
      }

      if (q.startsWith("select * from identity_idempotency")) {
        const [verificationId, key] = params as [string, string];
        return { rowCount: idempotency.has(`${verificationId}:${key}`) ? 1 : 0, rows: [] };
      }

      throw new Error(`Unhandled SQL in test stub: ${sql}`);
    }
  } as any;

  const inference = {
    post: async () => ({ data: { ok: true } })
  } as any;

  const redisPushed: string[] = [];
  const redis = {
    isOpen: true,
    connect: async () => {},
    quit: async () => {},
    rPush: async (_key: string, value: string) => {
      redisPushed.push(value);
      return redisPushed.length;
    },
    blPop: async () => null
  } as any;

  const logger = createLogger({ service: "identity-orchestrator-test", level: "silent" });

  const app = createIdentityOrchestratorApp({
    config: { JWT_SECRET: secret, JWT_ISSUER: "verza", JWT_AUDIENCE: "verza", CORS_ALLOWED_ORIGINS: [], METRICS_ENABLED: false },
    logger,
    pool,
    inference,
    redis,
    s3: null
  });

  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as any;
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  const createVerification = await fetch(`${baseUrl}/internal/v1/verifications`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ type: "kyc" })
  });
  assert.equal(createVerification.status, 200);
  const { id: verificationId } = (await createVerification.json()) as any;
  assert.equal(typeof verificationId, "string");

  const addMedia1 = await fetch(`${baseUrl}/internal/v1/verifications/${verificationId}/media`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ key: "liveness.mp4", kind: "liveness" })
  });
  assert.equal(addMedia1.status, 200);

  const addMedia2 = await fetch(`${baseUrl}/internal/v1/verifications/${verificationId}/media`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ key: "doc.jpg", kind: "document" })
  });
  assert.equal(addMedia2.status, 200);

  const run = await fetch(`${baseUrl}/internal/v1/verifications/${verificationId}/run`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` }
  });
  assert.equal(run.status, 200);
  assert.deepEqual(await run.json(), { status: "completed" });

  const get = await fetch(`${baseUrl}/internal/v1/verifications/${verificationId}`, {
    headers: { authorization: `Bearer ${token}` }
  });
  assert.equal(get.status, 200);
  const row = (await get.json()) as any;
  assert.equal(row.status, "completed");
  assert.equal(row.attempt_count, 1);
  assert.ok(row.completed_at);

  const asyncMissingKey = await fetch(`${baseUrl}/internal/v1/verifications/${verificationId}/run?async=1`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` }
  });
  assert.equal(asyncMissingKey.status, 400);

  const v2 = await fetch(`${baseUrl}/internal/v1/verifications`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ type: "kyc" })
  });
  const { id: v2Id } = (await v2.json()) as any;

  const addMedia3 = await fetch(`${baseUrl}/internal/v1/verifications/${v2Id}/media`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ key: "liveness.mp4", kind: "liveness" })
  });
  assert.equal(addMedia3.status, 200);

  const asyncRun = await fetch(`${baseUrl}/internal/v1/verifications/${v2Id}/run?async=true`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "idempotency-key": "k1" }
  });
  assert.equal(asyncRun.status, 202);
  assert.deepEqual(await asyncRun.json(), { status: "queued" });
  assert.equal(redisPushed.length, 1);

  const asyncDup = await fetch(`${baseUrl}/internal/v1/verifications/${v2Id}/run?async=true`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "idempotency-key": "k1" }
  });
  assert.equal(asyncDup.status, 202);
  assert.deepEqual(await asyncDup.json(), { status: "duplicate" });
  assert.equal(redisPushed.length, 1);

  const idemCheck = await fetch(`${baseUrl}/internal/v1/verifications/${v2Id}/idempotency`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ key: "k1" })
  });
  assert.equal(idemCheck.status, 200);
  assert.deepEqual(await idemCheck.json(), { exists: true });

  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
