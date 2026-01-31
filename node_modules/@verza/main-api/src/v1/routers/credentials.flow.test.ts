import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import express from "express";
import { createServer } from "node:http";

import { errorHandler, notFoundHandler } from "@verza/http";

import { createCredentialsRouter } from "./credentials.js";

void test("credentials: store encrypts and get decrypts roundtrip", async () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    (req as any).auth = { userId: "user-1", role: "user", sessionId: "sess-1", email: "u@example.com", tenantId: "t-1" };
    next();
  });

  const credentialsById = new Map<string, any>();
  const auditChains = new Map<string, { next_seq: number; head_hash: string }>();

  const pool = {
    query: async (sql: string, params: unknown[] = []) => {
      const q = sql.replace(/\s+/g, " ").trim().toLowerCase();

      if (q === "begin" || q === "commit" || q === "rollback") {
        return { rowCount: 0, rows: [] };
      }

      if (q.startsWith("select next_seq, head_hash from audit_chains where tenant_id=$1 and stream=$2")) {
        const [tenantId, stream] = params as [string, string];
        const key = `${tenantId}:${stream}`;
        const row = auditChains.get(key);
        if (!row) return { rowCount: 0, rows: [] };
        return { rowCount: 1, rows: [{ next_seq: row.next_seq, head_hash: row.head_hash }] };
      }

      if (q.startsWith("insert into audit_chains (tenant_id, stream, next_seq, head_hash, updated_at) values")) {
        const [tenantId, stream] = params as [string, string];
        const key = `${tenantId}:${stream}`;
        if (!auditChains.has(key)) auditChains.set(key, { next_seq: 1, head_hash: "" });
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("update audit_chains set next_seq=next_seq+1, head_hash=$1, updated_at=$2 where tenant_id=$3 and stream=$4")) {
        const [headHash, , tenantId, stream] = params as [string, unknown, string, string];
        const key = `${tenantId}:${stream}`;
        const row = auditChains.get(key) ?? { next_seq: 1, head_hash: "" };
        auditChains.set(key, { next_seq: row.next_seq + 1, head_hash: headHash });
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("insert into audit_events (id,tenant_id,stream,seq,prev_hash,event_hash,event_type")) {
        return { rowCount: 1, rows: [] };
      }

      if (q.startsWith("insert into credentials")) {
        const [id, tenant_id, owner_user_id, owner_did, type, status, issuer_name, document_number, issue_date, expiry_date, issuing_authority, notes, encrypted_data] =
          params as any[];
        credentialsById.set(id, {
          id,
          tenant_id,
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

      if (q.startsWith("select * from credentials where id=$1 and tenant_id=$2 and owner_user_id=$3")) {
        const [id, tenantId, ownerUserId] = params as [string, string, string];
        const row = credentialsById.get(id);
        if (!row || row.tenant_id !== tenantId || row.owner_user_id !== ownerUserId) return { rowCount: 0, rows: [] };
        return { rowCount: 1, rows: [row] };
      }

      if (q.startsWith("select id, type, status, issuer_name, document_number")) {
        const [tenantId, ownerUserId] = params as [string, string];
        const rows = [...credentialsById.values()].filter((r) => r.tenant_id === tenantId && r.owner_user_id === ownerUserId);
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

  const otherTenantCredentialId = crypto.randomUUID();
  credentialsById.set(otherTenantCredentialId, {
    id: otherTenantCredentialId,
    tenant_id: "t-2",
    owner_user_id: "user-1",
    owner_did: "",
    type: "passport",
    status: "active",
    issuer_name: "",
    document_number: "",
    issue_date: null,
    expiry_date: null,
    issuing_authority: "",
    notes: "",
    encrypted_data: rawRow.encrypted_data,
    created_at: new Date(),
    updated_at: new Date()
  });

  const list = await fetch(`${baseUrl}/`, { method: "GET" });
  assert.equal(list.status, 200);
  const listBody = (await list.json()) as any[];
  assert.equal(listBody.length, 1);
  assert.equal(listBody[0]?.id, storeBody.id);

  const getOtherTenant = await fetch(`${baseUrl}/${otherTenantCredentialId}`, { method: "GET" });
  assert.equal(getOtherTenant.status, 404);

  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});
