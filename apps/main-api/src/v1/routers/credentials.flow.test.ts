import assert from "node:assert/strict";
import test from "node:test";

import express from "express";
import { createServer } from "node:http";

import { errorHandler, notFoundHandler } from "@verza/http";

import { createCredentialsRouter } from "./credentials.js";

void test("credentials: store encrypts and get decrypts roundtrip", async () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    (req as any).auth = { userId: "user-1", role: "user", sessionId: "sess-1", email: "u@example.com" };
    next();
  });

  const credentialsById = new Map<string, any>();

  const pool = {
    query: async (sql: string, params: unknown[] = []) => {
      const q = sql.replace(/\s+/g, " ").trim().toLowerCase();

      if (q.startsWith("insert into credentials")) {
        const [id, owner_user_id, owner_did, type, status, issuer_name, document_number, issue_date, expiry_date, issuing_authority, notes, encrypted_data] =
          params as any[];
        credentialsById.set(id, {
          id,
          owner_user_id,
          owner_did,
          type,
          status,
          issuer_name,
          document_number,
          issue_date,
          expiry_date,
          issuing_authority,
          notes,
          encrypted_data
        });
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("select * from credentials where id=$1 and owner_user_id=$2")) {
        const [id, ownerUserId] = params as [string, string];
        const row = credentialsById.get(id);
        if (!row || row.owner_user_id !== ownerUserId) return { rowCount: 0, rows: [] };
        return { rowCount: 1, rows: [row] };
      }

      if (q.startsWith("select id, type, status, issuer_name, document_number")) {
        const [ownerUserId] = params as [string];
        const rows = [...credentialsById.values()].filter((r) => r.owner_user_id === ownerUserId);
        return { rowCount: rows.length, rows };
      }

      throw new Error(`Unhandled SQL in test stub: ${sql}`);
    }
  } as any;

  const logger = { error: () => {}, info: () => {} } as any;

  const masterKeyB64 = Buffer.alloc(32, 7).toString("base64");
  app.use(
    "/credentials",
    createCredentialsRouter({
      pool,
      logger,
      config: {
        ENCRYPTION_MASTER_KEY_B64: masterKeyB64
      }
    } as any)
  );
  app.use(notFoundHandler);
  app.use(errorHandler());

  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as any;
  const baseUrl = `http://127.0.0.1:${addr.port}/credentials`;

  const payload = { type: "passport", data: { hello: "world", n: 1 } };
  const store = await fetch(`${baseUrl}/store`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  assert.equal(store.status, 200);
  const storeBody = (await store.json()) as any;
  assert.equal(typeof storeBody.id, "string");

  const rawRow = credentialsById.get(storeBody.id);
  assert.ok(rawRow);
  assert.equal(typeof rawRow.encrypted_data, "string");
  assert.notEqual(rawRow.encrypted_data, JSON.stringify(payload.data));

  const get = await fetch(`${baseUrl}/${storeBody.id}`, { method: "GET" });
  assert.equal(get.status, 200);
  const getBody = (await get.json()) as any;
  assert.deepEqual(getBody.data, payload.data);

  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
