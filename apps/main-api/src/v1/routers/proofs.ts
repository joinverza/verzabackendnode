import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";

import { canonicalJson, sha256Hex, signReceipt } from "@verza/crypto";
import { badRequest, notFound } from "@verza/http";

import type { MainApiContext } from "../routes.js";

const generateSchema = z.object({
  credential_id: z.string().uuid(),
  type: z.string().min(1).optional()
});

const verifySchema = z.object({
  proof: z.unknown(),
  sig_kid: z.string().min(1),
  sig_b64: z.string().min(1)
});

const proofIdSchema = z.object({ id: z.string().uuid() });

type CredentialRowForProof = {
  id: string;
  type: string;
  status: string;
  issuer_name: string;
  document_number: string;
  issue_date: Date | null;
  expiry_date: Date | null;
  issuing_authority: string;
  notes: string;
  encrypted_data: string;
};

export function createProofsRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.post("/generate", async (req, res, next) => {
    try {
      const body = generateSchema.parse(req.body);
      const created = await getOrCreateProofForCredential(ctx, {
        userId: req.auth.userId,
        credentialId: body.credential_id,
        ...(body.type ? { type: body.type } : {})
      });
      res.json(created);
    } catch (err) {
      next(err);
    }
  });

  router.post("/verify", async (req, res, next) => {
    try {
      const body = verifySchema.parse(req.body);
      const valid = verifyProofEnvelope(ctx, body);
      res.json({ valid });
    } catch (err) {
      next(err);
    }
  });

  router.get("/:id", async (req, res, next) => {
    try {
      const { id } = proofIdSchema.parse(req.params);
      const result = await ctx.pool.query<{ id: string; user_id: string; credential_id: string; type: string; status: string; proof_json: string; created_at: Date }>(
        "select id, user_id, credential_id, type, status, proof_json, created_at from proofs where id=$1 and user_id=$2 limit 1",
        [id, req.auth.userId]
      );
      const row = result.rows[0];
      if (!row) throw notFound("proof_not_found", "Proof not found");
      res.json({ ...row, proof: safeJson(row.proof_json) });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

export async function getOrCreateProofForCredential(
  ctx: MainApiContext,
  opts: { userId: string; credentialId: string; type?: string }
): Promise<{ id: string; credential_id: string; type: string; status: string; created_at: string; proof: unknown }> {
  const existing = await ctx.pool.query<{ id: string; credential_id: string; type: string; status: string; proof_json: string; created_at: Date }>(
    "select id, credential_id, type, status, proof_json, created_at from proofs where user_id=$1 and credential_id=$2 order by created_at desc limit 1",
    [opts.userId, opts.credentialId]
  );
  if (existing.rowCount) {
    const row = existing.rows[0]!;
    return { id: row.id, credential_id: row.credential_id, type: row.type, status: row.status, created_at: row.created_at.toISOString(), proof: safeJson(row.proof_json) };
  }

  const credResult = await ctx.pool.query<CredentialRowForProof>(
    "select id, type, status, issuer_name, document_number, issue_date, expiry_date, issuing_authority, notes, encrypted_data from credentials where id=$1 and owner_user_id=$2 limit 1",
    [opts.credentialId, opts.userId]
  );
  const cred = credResult.rows[0];
  if (!cred) throw notFound("credential_not_found", "Credential not found");

  const proofId = crypto.randomUUID();
  const createdAt = new Date();
  const proofType = opts.type ?? "zk";
  const proof = buildProofPayload({ proofId, createdAt, proofType, userId: opts.userId, credential: cred });
  const signed = signReceipt({ seedB64: ctx.config.RECEIPT_ED25519_SEED_B64, receipt: proof });
  const proofEnvelope = { proof, ...signed };

  await ctx.pool.query(
    "insert into proofs (id, user_id, credential_id, type, status, proof_json, created_at) values ($1,$2,$3,$4,$5,$6,$7)",
    [proofId, opts.userId, opts.credentialId, proofType, "created", JSON.stringify(proofEnvelope), createdAt]
  );

  return { id: proofId, credential_id: opts.credentialId, type: proofType, status: "created", created_at: createdAt.toISOString(), proof: proofEnvelope };
}

function buildProofPayload(opts: { proofId: string; createdAt: Date; proofType: string; userId: string; credential: CredentialRowForProof }) {
  const credential_digest = sha256Hex(
    canonicalJson({
      id: opts.credential.id,
      type: opts.credential.type,
      status: opts.credential.status,
      issuer_name: opts.credential.issuer_name,
      document_number: opts.credential.document_number,
      issue_date: opts.credential.issue_date?.toISOString() ?? null,
      expiry_date: opts.credential.expiry_date?.toISOString() ?? null,
      issuing_authority: opts.credential.issuing_authority,
      notes: opts.credential.notes,
      encrypted_data: opts.credential.encrypted_data
    })
  );

  return {
    proof_id: opts.proofId,
    type: opts.proofType,
    status: "created",
    issued_at: opts.createdAt.toISOString(),
    user_id: opts.userId,
    credential_id: opts.credential.id,
    credential_digest
  };
}

function safeJson(s: string) {
  try {
    return JSON.parse(s || "{}") as unknown;
  } catch {
    return {};
  }
}

function verifyProofEnvelope(ctx: MainApiContext, input: { proof?: unknown; sig_kid: string; sig_b64: string }) {
  if (input.proof === undefined) return false;
  const seed = Buffer.from(ctx.config.RECEIPT_ED25519_SEED_B64, "base64");
  if (seed.length !== 32) throw badRequest("invalid_signing_seed", "Invalid signing seed");
  const keyPair = crypto.generateKeyPairSync("ed25519", { seed });
  const pubDer = keyPair.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const expectedKid = `ed25519:${sha256Hex(pubDer).slice(0, 16)}`;
  if (input.sig_kid !== expectedKid) return false;
  const payload = Buffer.from(canonicalJson(input.proof), "utf8");
  const sig = base64UrlToBuf(input.sig_b64);
  if (!sig) return false;
  return crypto.verify(null, payload, keyPair.publicKey, sig);
}

function base64UrlToBuf(s: string) {
  const trimmed = s.trim();
  if (!trimmed) return null;
  const b64 = trimmed.replaceAll("-", "+").replaceAll("_", "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  try {
    return Buffer.from(b64 + pad, "base64");
  } catch {
    return null;
  }
}
