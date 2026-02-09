import type { Router } from "express";

import crypto from "node:crypto";

import express from "express";
import { z } from "zod";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

import { PERMISSIONS, requirePermission } from "@verza/auth";
import { badRequest, notFound } from "@verza/http";
import { canonicalJson, sha256Hex, signReceipt } from "@verza/crypto";

import type { MainApiContext } from "../routes.js";
import { appendAuditEvent, verifyAuditChain } from "./auditLog.js";

const tenantSchema = z.object({
  tenant_id: z.string().uuid()
});

const exportQuerySchema = z.object({
  tenant_id: z.string().uuid(),
  stream: z.string().optional(),
  from_seq: z.coerce.number().int().positive().optional(),
  to_seq: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().positive().max(5000).optional(),
  format: z.enum(["json", "ndjson"]).optional(),
  store_to_worm: z
    .string()
    .optional()
    .default("0")
    .transform((v) => v === "1" || v.toLowerCase() === "true"),
  worm_retention_days: z.coerce.number().int().positive().optional()
});

const evidenceCreateSchema = z.object({
  tenant_id: z.string().uuid(),
  subject_type: z.string().min(1),
  subject_id: z.string().min(1),
  content_type: z.string().min(1),
  blob_b64: z.string().optional(),
  content_sha256: z.string().optional(),
  owner_user_id: z.string().uuid().optional(),
  store_to_worm: z.boolean().optional().default(false),
  worm_retention_days: z.number().int().positive().optional()
});

const retentionSetSchema = z.object({
  tenant_id: z.string().uuid(),
  resource_type: z.string().min(1),
  retention_days: z.number().int().nonnegative(),
  action: z.enum(["delete", "anonymize"]).default("delete")
});

export function createAdminComplianceRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.get(
    "/audit/head",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_HEAD_READ,
      tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const { tenant_id } = tenantSchema.parse(req.query);
      const stream = typeof req.query.stream === "string" && req.query.stream.trim().length ? req.query.stream.trim() : "tenant";
      const result = await ctx.pool.query<{ tenant_id: string; stream: string; next_seq: string | number; head_hash: string; updated_at: Date }>(
        "select tenant_id,stream,next_seq,head_hash,updated_at from audit_chains where tenant_id=$1 and stream=$2 limit 1",
        [tenant_id, stream]
      );
      const row = result.rows[0];
      if (!row) throw notFound("audit_chain_not_found", "Audit chain not found");
      await appendAuditEvent(ctx.pool, {
        tenantId: tenant_id,
        eventType: "admin_audit_head_viewed",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "audit_chain",
        subjectId: stream,
        data: {}
      });
      res.json({ tenant_id: row.tenant_id, stream: row.stream, next_seq: Number(row.next_seq), head_hash: row.head_hash, updated_at: row.updated_at });
    } catch (err) {
      next(err);
    }
  }
  );

  router.get(
    "/audit/events",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_EVENTS_LIST,
      tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const q = exportQuerySchema.parse(req.query);
      const stream = (q.stream ?? "tenant").trim() || "tenant";
      const fromSeq = q.from_seq ?? 1;
      const limit = q.limit ?? 500;
      const result = await ctx.pool.query(
        "select id,tenant_id,stream,seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at,created_at_ms from audit_events where tenant_id=$1 and stream=$2 and seq >= $3 order by seq asc limit $4",
        [q.tenant_id, stream, fromSeq, limit]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: q.tenant_id,
        eventType: "admin_audit_events_listed",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "audit_events",
        subjectId: stream,
        data: { from_seq: fromSeq, limit }
      });
      res.json(result.rows.map((r) => ({ ...r, data: safeJson(String(r.data_json ?? "{}")) })));
    } catch (err) {
      next(err);
    }
  }
  );

  router.get(
    "/audit/export",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_EXPORT,
      tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const q = exportQuerySchema.parse(req.query);
      const stream = (q.stream ?? "tenant").trim() || "tenant";
      const fromSeq = q.from_seq ?? 1;
      const limit = q.limit ?? 5000;
      const upper = q.to_seq ?? null;
      const format = q.format ?? "json";
      const storeToWorm = ctx.config.COMPLIANCE_WORM_ENFORCE ? true : q.store_to_worm;

      const result = await ctx.pool.query(
        upper
          ? "select tenant_id,stream,seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at,created_at_ms from audit_events where tenant_id=$1 and stream=$2 and seq >= $3 and seq <= $4 order by seq asc limit $5"
          : "select tenant_id,stream,seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at,created_at_ms from audit_events where tenant_id=$1 and stream=$2 and seq >= $3 order by seq asc limit $4",
        upper ? [q.tenant_id, stream, fromSeq, upper, limit] : [q.tenant_id, stream, fromSeq, limit]
      );

      const items = result.rows.map((r: any) => ({
        tenant_id: r.tenant_id,
        stream: r.stream,
        seq: Number(r.seq),
        prev_hash: r.prev_hash,
        event_hash: r.event_hash,
        event_type: r.event_type,
        actor_type: r.actor_type,
        actor_id: r.actor_id,
        subject_type: r.subject_type,
        subject_id: r.subject_id,
        data: safeJson(String(r.data_json ?? "{}")),
        created_at: r.created_at,
        created_at_ms: Number(r.created_at_ms)
      }));

      const exportHash = sha256Hex(items.map((i) => i.event_hash).join("\n"));

      await appendAuditEvent(ctx.pool, {
        tenantId: q.tenant_id,
        eventType: "admin_audit_exported",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "audit_export",
        subjectId: stream,
        data: { from_seq: fromSeq, to_seq: upper ?? null, count: items.length, export_sha256: exportHash, format }
      });

      let worm: { evidence_id: string; bucket: string; key: string; retain_until: string; object_sha256: string } | null = null;
      if (storeToWorm) {
        const s3 = createComplianceS3ClientIfConfigured(ctx.config);
        if (!s3) throw badRequest("worm_not_configured", "WORM storage not configured");
        const now = new Date();
        const retentionDays = q.worm_retention_days ?? ctx.config.COMPLIANCE_S3_OBJECT_LOCK_DAYS;
        const retainUntil = new Date(now.getTime() + retentionDays * 24 * 60 * 60 * 1000);
        const key = buildWormKey({
          prefix: "audit_exports",
          tenantId: q.tenant_id,
          stream,
          createdAtMs: now.getTime(),
          sha256: exportHash,
          suffix: "ndjson"
        });
        const ndjson = encodeAuditExportNdjson({
          tenantId: q.tenant_id,
          stream,
          fromSeq,
          toSeq: upper ?? null,
          exportSha256: exportHash,
          events: items
        });
        const bodyBuf = Buffer.from(ndjson, "utf8");
        const bodySha = sha256Hex(bodyBuf);
        await s3.client.send(
          new PutObjectCommand({
            Bucket: s3.bucket,
            Key: key,
            Body: bodyBuf,
            ContentType: "application/x-ndjson",
            ObjectLockMode: "COMPLIANCE",
            ObjectLockRetainUntilDate: retainUntil,
            Metadata: {
              tenant_id: q.tenant_id,
              stream,
              from_seq: String(fromSeq),
              to_seq: upper ? String(upper) : "",
              export_sha256: exportHash,
              object_sha256: bodySha
            }
          })
        );

        const evidenceId = crypto.randomUUID();
        const createdAtMs = now.getTime();
        await ctx.pool.query(
          "insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
          [
            evidenceId,
            q.tenant_id,
            req.auth.userId,
            "audit_export",
            `${stream}:${fromSeq}:${upper ?? ""}:${exportHash}`,
            "application/x-ndjson",
            bodySha,
            "external",
            Buffer.from(JSON.stringify({ provider: "s3", bucket: s3.bucket, key, export_sha256: exportHash, retain_until: retainUntil.toISOString() }), "utf8").toString("base64"),
            now,
            createdAtMs
          ]
        );
        await appendAuditEvent(ctx.pool, {
          tenantId: q.tenant_id,
          eventType: "evidence_stored",
          actorType: "admin",
          actorId: req.auth.userId,
          subjectType: "audit_export",
          subjectId: evidenceId,
          data: { bucket: s3.bucket, key, export_sha256: exportHash, object_sha256: bodySha, retain_until: retainUntil.toISOString() }
        });
        worm = { evidence_id: evidenceId, bucket: s3.bucket, key, retain_until: retainUntil.toISOString(), object_sha256: bodySha };
      }

      if (format === "ndjson") {
        res.setHeader("content-type", "application/x-ndjson");
        res.write(
          JSON.stringify({
            type: "manifest",
            tenant_id: q.tenant_id,
            stream,
            from_seq: fromSeq,
            to_seq: upper ?? null,
            count: items.length,
            export_sha256: exportHash,
            worm
          }) + "\n"
        );
        for (const it of items) res.write(JSON.stringify({ type: "event", ...it }) + "\n");
        res.end();
        return;
      }

      res.json({
        manifest: { tenant_id: q.tenant_id, stream, from_seq: fromSeq, to_seq: upper ?? null, count: items.length, export_sha256: exportHash, worm },
        events: items
      });
    } catch (err) {
      next(err);
    }
  }
  );

  router.get(
    "/audit/anchors",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_ANCHORS_LIST,
      tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
      try {
        const { tenant_id } = tenantSchema.parse(req.query);
        const stream = typeof req.query.stream === "string" && req.query.stream.trim().length ? req.query.stream.trim() : null;
        const limit = typeof req.query.limit === "string" ? Number(req.query.limit) : 50;
        const lim = Number.isFinite(limit) ? Math.max(1, Math.min(500, Math.floor(limit))) : 50;
        const rows = await ctx.pool.query(
          stream
            ? "select id,tenant_id,stream,head_hash,next_seq,anchored_at,payload_json,sig_kid,sig_b64,anchor_target from audit_chain_anchors where tenant_id=$1 and stream=$2 order by anchored_at desc limit $3"
            : "select id,tenant_id,stream,head_hash,next_seq,anchored_at,payload_json,sig_kid,sig_b64,anchor_target from audit_chain_anchors where tenant_id=$1 order by anchored_at desc limit $2",
          stream ? [tenant_id, stream, lim] : [tenant_id, lim]
        );
        await appendAuditEvent(ctx.pool, {
          tenantId: tenant_id,
          eventType: "admin_audit_anchors_listed",
          actorType: "admin",
          actorId: req.auth.userId,
          subjectType: "audit_chain_anchors",
          subjectId: stream ?? "all",
          data: { limit: lim }
        });
        res.json(rows.rows.map((r) => ({ ...r, payload: safeJson(String(r.payload_json ?? "{}")) })));
      } catch (err) {
        next(err);
      }
    }
  );

  router.post(
    "/audit/anchor/run",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_ANCHOR_RUN,
      tenantId: (req) => (typeof (req as any)?.body?.tenant_id === "string" ? (req as any).body.tenant_id : null)
    }),
    async (req, res, next) => {
      try {
        const body = z
          .object({
            tenant_id: z.string().uuid(),
            stream: z.string().optional()
          })
          .parse(req.body ?? {});
        const stream = (body.stream ?? "tenant").trim() || "tenant";
        const row = await ctx.pool.query<{ head_hash: string; next_seq: string | number; updated_at: Date }>(
          "select head_hash,next_seq,updated_at from audit_chains where tenant_id=$1 and stream=$2 limit 1",
          [body.tenant_id, stream]
        );
        const head = row.rows[0];
        if (!head) throw notFound("audit_chain_not_found", "Audit chain not found");
        const anchoredAt = new Date();
        const payload = {
          type: "audit_chain_anchor",
          tenant_id: body.tenant_id,
          stream,
          head_hash: head.head_hash ?? "",
          next_seq: Number(head.next_seq ?? 1),
          chain_updated_at: head.updated_at?.toISOString?.() ?? null,
          anchored_at: anchoredAt.toISOString()
        };
        const payloadJson = canonicalJson(payload);
        const payloadSha = sha256Hex(payloadJson);
        const signed = signReceipt({ seedB64: ctx.config.RECEIPT_ED25519_SEED_B64, receipt: payload });

        const anchorId = crypto.randomUUID();
        await ctx.pool.query(
          "insert into audit_chain_anchors (id,tenant_id,stream,head_hash,next_seq,anchored_at,payload_json,sig_kid,sig_b64,anchor_target) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
          [anchorId, body.tenant_id, stream, payload.head_hash, payload.next_seq, anchoredAt, payloadJson, signed.sig_kid, signed.sig_b64, String(ctx.config.AUDIT_ANCHOR_URL ?? "")]
        );

        let evidence: { evidence_id: string; bucket: string; key: string; retain_until: string; object_sha256: string } | null = null;
        const storeToWorm = ctx.config.COMPLIANCE_WORM_ENFORCE ? true : Boolean(createComplianceS3ClientIfConfigured(ctx.config));
        if (storeToWorm) {
          const s3 = createComplianceS3ClientIfConfigured(ctx.config);
          if (!s3) throw badRequest("worm_not_configured", "WORM storage not configured");
          const now = new Date();
          const retainUntil = new Date(now.getTime() + ctx.config.COMPLIANCE_S3_OBJECT_LOCK_DAYS * 24 * 60 * 60 * 1000);
          const key = buildWormKey({
            prefix: "audit_anchors",
            tenantId: body.tenant_id,
            stream,
            createdAtMs: now.getTime(),
            sha256: payloadSha,
            suffix: "json"
          });
          const bodyBuf = Buffer.from(payloadJson, "utf8");
          const bodySha = sha256Hex(bodyBuf);
          await s3.client.send(
            new PutObjectCommand({
              Bucket: s3.bucket,
              Key: key,
              Body: bodyBuf,
              ContentType: "application/json",
              ObjectLockMode: "COMPLIANCE",
              ObjectLockRetainUntilDate: retainUntil,
              Metadata: { tenant_id: body.tenant_id, stream, payload_sha256: payloadSha, object_sha256: bodySha }
            })
          );
          const evidenceId = crypto.randomUUID();
          await ctx.pool.query(
            "insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            [
              evidenceId,
              body.tenant_id,
              req.auth.userId,
              "audit_anchor",
              anchorId,
              "application/json",
              bodySha,
              "external",
              Buffer.from(JSON.stringify({ provider: "s3", bucket: s3.bucket, key, payload_sha256: payloadSha, retain_until: retainUntil.toISOString() }), "utf8").toString(
                "base64"
              ),
              now,
              now.getTime()
            ]
          );
          evidence = { evidence_id: evidenceId, bucket: s3.bucket, key, retain_until: retainUntil.toISOString(), object_sha256: bodySha };
        }

        const anchorUrl = String(ctx.config.AUDIT_ANCHOR_URL ?? "").trim();
        const anchorSecret = String(ctx.config.AUDIT_ANCHOR_SECRET ?? "").trim();
        if (anchorUrl) {
          try {
            await fetch(anchorUrl, {
              method: "POST",
              headers: {
                "content-type": "application/json",
                ...(anchorSecret ? { "x-anchor-secret": anchorSecret } : {})
              },
              body: JSON.stringify({ ...payload, ...signed, payload_sha256: payloadSha })
            });
          } catch {
            void 0;
          }
        }

        await appendAuditEvent(ctx.pool, {
          tenantId: body.tenant_id,
          eventType: "admin_audit_anchor_created",
          actorType: "admin",
          actorId: req.auth.userId,
          subjectType: "audit_chain_anchor",
          subjectId: anchorId,
          data: { stream, head_hash: payload.head_hash, next_seq: payload.next_seq, payload_sha256: payloadSha, evidence }
        });

        res.status(201).json({ id: anchorId, tenant_id: body.tenant_id, stream, head_hash: payload.head_hash, next_seq: payload.next_seq, payload_sha256: payloadSha, ...signed, evidence });
      } catch (err) {
        next(err);
      }
    }
  );

  router.post(
    "/audit/verify",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_AUDIT_VERIFY,
      tenantId: (req) => (typeof (req as any)?.body?.tenant_id === "string" ? (req as any).body.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const body = z
        .object({
          tenant_id: z.string().uuid(),
          stream: z.string().optional(),
          from_seq: z.number().int().positive().optional(),
          to_seq: z.number().int().positive().optional()
        })
        .parse(req.body ?? {});
      const result = await verifyAuditChain(ctx.pool, {
        tenantId: body.tenant_id,
        ...(body.stream ? { stream: body.stream } : {}),
        ...(typeof body.from_seq === "number" ? { fromSeq: body.from_seq } : {}),
        ...(typeof body.to_seq === "number" ? { toSeq: body.to_seq } : {})
      });
      await appendAuditEvent(ctx.pool, {
        tenantId: body.tenant_id,
        eventType: "admin_audit_chain_verified",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "audit_chain",
        subjectId: (body.stream ?? "tenant").trim() || "tenant",
        data: { from_seq: body.from_seq ?? null, to_seq: body.to_seq ?? null, ok: (result as any)?.ok ?? null }
      });
      res.json(result);
    } catch (err) {
      next(err);
    }
  }
  );

  router.get(
    "/reports/summary",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_REPORTS_SUMMARY_READ,
      tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const { tenant_id } = tenantSchema.parse(req.query);
      const from = typeof req.query.from === "string" ? new Date(req.query.from) : null;
      const to = typeof req.query.to === "string" ? new Date(req.query.to) : null;
      const fromOk = from && Number.isFinite(from.getTime());
      const toOk = to && Number.isFinite(to.getTime());
      const where = fromOk && toOk ? "tenant_id=$1 and created_at >= $2 and created_at <= $3" : "tenant_id=$1";
      const params = fromOk && toOk ? [tenant_id, from, to] : [tenant_id];

      const events = await ctx.pool.query<{ event_type: string; count: string }>(
        `select event_type, count(*)::text as count from audit_events where ${where} group by event_type order by count(*) desc`,
        params
      );
      const dsar = await ctx.pool.query<{ request_type: string; status: string; count: string }>(
        `select request_type, status, count(*)::text as count from dsar_requests where ${where.replace("created_at", "requested_at")} group by request_type, status order by count(*) desc`,
        params
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: tenant_id,
        eventType: "admin_reports_summary_viewed",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "reports",
        subjectId: "summary",
        data: { from: fromOk ? from?.toISOString() : null, to: toOk ? to?.toISOString() : null }
      });
      res.json({
        tenant_id,
        from: fromOk ? from?.toISOString() : null,
        to: toOk ? to?.toISOString() : null,
        events: events.rows.map((r) => ({ event_type: r.event_type, count: Number(r.count) })),
        dsar: dsar.rows.map((r) => ({ request_type: r.request_type, status: r.status, count: Number(r.count) }))
      });
    } catch (err) {
      next(err);
    }
  }
  );

  router.post(
    "/evidence",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_EVIDENCE_CREATE,
      tenantId: (req) => (typeof (req as any)?.body?.tenant_id === "string" ? (req as any).body.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const body = evidenceCreateSchema.parse(req.body ?? {});
      const id = crypto.randomUUID();
      const createdAtMs = Date.now();
      const createdAt = new Date(createdAtMs);

      const storeToWorm = ctx.config.COMPLIANCE_WORM_ENFORCE ? true : body.store_to_worm;
      const blobB64 = body.blob_b64 ?? "";
      let contentSha = body.content_sha256 ?? "";
      let storage: "inline" | "external" = blobB64 ? "inline" : "external";
      let storedBlobB64 = blobB64;
      let wormInfo: { bucket: string; key: string; retain_until: string } | null = null;
      if (blobB64) {
        const buf = safeB64ToBuf(blobB64);
        if (!buf) throw badRequest("invalid_blob_b64", "Invalid blob_b64");
        contentSha = sha256Hex(buf);
        if (storeToWorm) {
          const s3 = createComplianceS3ClientIfConfigured(ctx.config);
          if (!s3) throw badRequest("worm_not_configured", "WORM storage not configured");
          const retentionDays = body.worm_retention_days ?? ctx.config.COMPLIANCE_S3_OBJECT_LOCK_DAYS;
          const retainUntil = new Date(createdAt.getTime() + retentionDays * 24 * 60 * 60 * 1000);
          const key = buildWormKey({
            prefix: "evidence",
            tenantId: body.tenant_id,
            stream: body.subject_type,
            createdAtMs,
            sha256: contentSha,
            suffix: "bin"
          });
          await s3.client.send(
            new PutObjectCommand({
              Bucket: s3.bucket,
              Key: key,
              Body: buf,
              ContentType: body.content_type,
              ObjectLockMode: "COMPLIANCE",
              ObjectLockRetainUntilDate: retainUntil,
              Metadata: {
                tenant_id: body.tenant_id,
                subject_type: body.subject_type,
                subject_id: body.subject_id,
                content_type: body.content_type,
                content_sha256: contentSha
              }
            })
          );
          storage = "external";
          storedBlobB64 = Buffer.from(
            JSON.stringify({ provider: "s3", bucket: s3.bucket, key, content_sha256: contentSha, retain_until: retainUntil.toISOString() }),
            "utf8"
          ).toString("base64");
          wormInfo = { bucket: s3.bucket, key, retain_until: retainUntil.toISOString() };
        }
      }
      if (!contentSha) throw badRequest("missing_content_sha256", "Missing content_sha256");

      await ctx.pool.query(
        "insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        [
          id,
          body.tenant_id,
          body.owner_user_id ?? null,
          body.subject_type,
          body.subject_id,
          body.content_type,
          contentSha,
          storage,
          storedBlobB64,
          createdAt,
          createdAtMs
        ]
      );

      await appendAuditEvent(ctx.pool, {
        tenantId: body.tenant_id,
        eventType: "evidence_stored",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: body.subject_type,
        subjectId: body.subject_id,
        data: { evidence_id: id, content_type: body.content_type, content_sha256: contentSha, worm: wormInfo }
      });

      res.status(201).json({ id, content_sha256: contentSha, worm: wormInfo });
    } catch (err) {
      next(err);
    }
  }
  );

  router.get(
    "/evidence/:id",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_EVIDENCE_READ,
      tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const id = String(req.params.id ?? "");
      if (!id || !id.match(/^[0-9a-f-]{36}$/i)) throw badRequest("invalid_id", "Invalid id");
      const { tenant_id } = tenantSchema.parse(req.query);
      const includeBlob = typeof req.query.include_blob === "string" && (req.query.include_blob === "1" || req.query.include_blob.toLowerCase() === "true");
      const result = await ctx.pool.query(
        "select id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms from evidence_objects where id=$1 and tenant_id=$2 limit 1",
        [id, tenant_id]
      );
      const row = result.rows[0];
      if (!row) throw notFound("evidence_not_found", "Evidence not found");
      if (!includeBlob) delete row.blob_b64;
      await appendAuditEvent(ctx.pool, {
        tenantId: tenant_id,
        eventType: "admin_evidence_viewed",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "evidence_object",
        subjectId: id,
        data: { include_blob: includeBlob }
      });
      res.json(row);
    } catch (err) {
      next(err);
    }
  }
  );

  router.get(
    "/privacy/requests",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_PRIVACY_REQUESTS_LIST,
      tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const { tenant_id } = tenantSchema.parse(req.query);
      const status = typeof req.query.status === "string" && req.query.status.trim().length ? req.query.status.trim() : null;
      const result = await ctx.pool.query(
        status
          ? "select id,tenant_id,user_id,request_type,status,reason,requested_at,processed_at,processed_by,result_json from dsar_requests where tenant_id=$1 and status=$2 order by requested_at desc limit 500"
          : "select id,tenant_id,user_id,request_type,status,reason,requested_at,processed_at,processed_by,result_json from dsar_requests where tenant_id=$1 order by requested_at desc limit 500",
        status ? [tenant_id, status] : [tenant_id]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: tenant_id,
        eventType: "admin_privacy_requests_listed",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "dsar_requests",
        subjectId: status ?? "all",
        data: {}
      });
      res.json(result.rows.map((r) => ({ ...r, result: safeJson(String(r.result_json ?? "{}")) })));
    } catch (err) {
      next(err);
    }
  }
  );

  router.post(
    "/privacy/requests/:id/approve",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_PRIVACY_REQUEST_APPROVE,
      tenantId: (req) => (typeof (req as any)?.body?.tenant_id === "string" ? (req as any).body.tenant_id : typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
      try {
        const id = String(req.params.id ?? "");
        if (!id || !id.match(/^[0-9a-f-]{36}$/i)) throw badRequest("invalid_id", "Invalid id");
        const body = z
          .object({
            tenant_id: z.string().uuid(),
            decision: z.enum(["approve", "reject"]),
            reason: z.string().optional()
          })
          .parse(req.body ?? {});

        const now = new Date();
        const approvalId = crypto.randomUUID();

        await ctx.pool.query("begin");
        try {
          const reqRow = await ctx.pool.query<{ id: string; request_type: string; status: string; user_id: string }>(
            "select id,request_type,status,user_id from dsar_requests where id=$1 and tenant_id=$2 limit 1 for update",
            [id, body.tenant_id]
          );
          const r = reqRow.rows[0];
          if (!r) throw notFound("dsar_request_not_found", "DSAR request not found");
          if (r.status === "completed" || r.status === "failed") throw badRequest("dsar_already_processed", "DSAR request already processed");

          const existingApproval = await ctx.pool.query<{ id: string }>(
            "select id from dsar_approvals where tenant_id=$1 and dsar_request_id=$2 and admin_user_id=$3 limit 1",
            [body.tenant_id, id, req.auth.userId]
          );
          if (existingApproval.rowCount) throw badRequest("dsar_already_approved_by_admin", "This admin already recorded a decision");

          await ctx.pool.query(
            "insert into dsar_approvals (id,tenant_id,dsar_request_id,admin_user_id,decision,reason,created_at) values ($1,$2,$3,$4,$5,$6,$7)",
            [approvalId, body.tenant_id, id, req.auth.userId, body.decision, body.reason ?? "", now]
          );

          const counts = await ctx.pool.query<{ decision: string; count: string }>(
            "select decision, count(*)::text as count from dsar_approvals where tenant_id=$1 and dsar_request_id=$2 group by decision",
            [body.tenant_id, id]
          );
          const approveCount = Number(counts.rows.find((x) => x.decision === "approve")?.count ?? 0);
          const rejectCount = Number(counts.rows.find((x) => x.decision === "reject")?.count ?? 0);

          let newStatus: string | null = null;
          if (rejectCount > 0) newStatus = "rejected";
          else if (approveCount >= ctx.config.DSAR_FOUR_EYES_REQUIRED) newStatus = "approved";
          else newStatus = "requested";

          if (newStatus !== r.status) {
            await ctx.pool.query("update dsar_requests set status=$1, processed_at=$2, processed_by=$3 where id=$4 and tenant_id=$5", [
              newStatus,
              now,
              "admin",
              id,
              body.tenant_id
            ]);
          }

          await ctx.pool.query("commit");

          await appendAuditEvent(ctx.pool, {
            tenantId: body.tenant_id,
            eventType: "dsar_approval_recorded",
            actorType: "admin",
            actorId: req.auth.userId,
            subjectType: "dsar_request",
            subjectId: id,
            data: { decision: body.decision, approve_count: approveCount, reject_count: rejectCount, new_status: newStatus }
          });

          res.json({ status: "ok", dsar_request_id: id, decision: body.decision, approve_count: approveCount, reject_count: rejectCount, new_status: newStatus });
        } catch (err) {
          await ctx.pool.query("rollback");
          throw err;
        }
      } catch (err) {
        next(err);
      }
    }
  );

  router.post(
    "/privacy/requests/:id/execute",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_PRIVACY_REQUEST_EXECUTE,
      tenantId: (req) => (typeof (req as any)?.body?.tenant_id === "string" ? (req as any).body.tenant_id : typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
      try {
        const id = String(req.params.id ?? "");
        if (!id || !id.match(/^[0-9a-f-]{36}$/i)) throw badRequest("invalid_id", "Invalid id");
        const body = z.object({ tenant_id: z.string().uuid() }).parse(req.body ?? {});

        const startedAt = new Date();
        await ctx.pool.query("begin");
        let userId = "";
        try {
          const reqRow = await ctx.pool.query<{ id: string; request_type: string; status: string; user_id: string; result_json: string }>(
            "select id,request_type,status,user_id,result_json from dsar_requests where id=$1 and tenant_id=$2 limit 1 for update",
            [id, body.tenant_id]
          );
          const r = reqRow.rows[0];
          if (!r) throw notFound("dsar_request_not_found", "DSAR request not found");
          userId = r.user_id;
          if (r.request_type !== "delete") throw badRequest("invalid_dsar_type", "Only delete requests can be executed");
          if (r.status !== "approved") throw badRequest("dsar_not_approved", "DSAR request not approved");

          await ctx.pool.query("update dsar_requests set status='processing', processed_at=$1, processed_by=$2 where id=$3 and tenant_id=$4", [
            startedAt,
            `admin:${req.auth.userId}`,
            id,
            body.tenant_id
          ]);

          const report = await performDsarDelete({ pool: ctx.pool, tenantId: body.tenant_id, userId, requestId: id });
          const reportJson = canonicalJson(report);
          const reportSha = sha256Hex(reportJson);
          const signed = signReceipt({ seedB64: ctx.config.RECEIPT_ED25519_SEED_B64, receipt: report });

          let evidence: { evidence_id: string; bucket: string; key: string; retain_until: string; object_sha256: string } | null = null;
          const storeToWorm = ctx.config.COMPLIANCE_WORM_ENFORCE ? true : Boolean(createComplianceS3ClientIfConfigured(ctx.config));
          if (storeToWorm) {
            const s3 = createComplianceS3ClientIfConfigured(ctx.config);
            if (!s3) throw badRequest("worm_not_configured", "WORM storage not configured");
            const now = new Date();
            const retainUntil = new Date(now.getTime() + ctx.config.COMPLIANCE_S3_OBJECT_LOCK_DAYS * 24 * 60 * 60 * 1000);
            const key = buildWormKey({
              prefix: "dsar_deletions",
              tenantId: body.tenant_id,
              stream: "delete",
              createdAtMs: now.getTime(),
              sha256: reportSha,
              suffix: "json"
            });
            const bodyBuf = Buffer.from(reportJson, "utf8");
            const bodySha = sha256Hex(bodyBuf);
            await s3.client.send(
              new PutObjectCommand({
                Bucket: s3.bucket,
                Key: key,
                Body: bodyBuf,
                ContentType: "application/json",
                ObjectLockMode: "COMPLIANCE",
                ObjectLockRetainUntilDate: retainUntil,
                Metadata: { tenant_id: body.tenant_id, dsar_request_id: id, report_sha256: reportSha, object_sha256: bodySha }
              })
            );
            const evidenceId = crypto.randomUUID();
            await ctx.pool.query(
              "insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
              [
                evidenceId,
                body.tenant_id,
                req.auth.userId,
                "dsar_deletion_report",
                id,
                "application/json",
                bodySha,
                "external",
                Buffer.from(JSON.stringify({ provider: "s3", bucket: s3.bucket, key, report_sha256: reportSha, retain_until: retainUntil.toISOString() }), "utf8").toString(
                  "base64"
                ),
                now,
                now.getTime()
              ]
            );
            evidence = { evidence_id: evidenceId, bucket: s3.bucket, key, retain_until: retainUntil.toISOString(), object_sha256: bodySha };
          }

          await ctx.pool.query("update dsar_requests set status='completed', processed_at=$1, processed_by=$2, result_json=$3 where id=$4 and tenant_id=$5", [
            new Date(),
            `admin:${req.auth.userId}`,
            JSON.stringify({ report_sha256: reportSha, sig_kid: signed.sig_kid, sig_b64: signed.sig_b64, evidence }),
            id,
            body.tenant_id
          ]);

          await ctx.pool.query("commit");

          await appendAuditEvent(ctx.pool, {
            tenantId: body.tenant_id,
            eventType: "dsar_delete_completed",
            actorType: "admin",
            actorId: req.auth.userId,
            subjectType: "user",
            subjectId: userId,
            data: { dsar_request_id: id, report_sha256: reportSha, evidence }
          });

          res.json({ status: "ok", dsar_request_id: id, report_sha256: reportSha, ...signed, evidence });
        } catch (err) {
          try {
            await ctx.pool.query("update dsar_requests set status='failed', processed_at=$1, processed_by=$2 where id=$3 and tenant_id=$4", [
              new Date(),
              `admin:${req.auth.userId}`,
              id,
              body.tenant_id
            ]);
          } catch {
            void 0;
          }
          await ctx.pool.query("rollback");
          throw err;
        }
      } catch (err) {
        next(err);
      }
    }
  );

  router.get(
    "/privacy/retention/reports",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_RETENTION_REPORTS_LIST,
      tenantId: (req) => (typeof req.query.tenant_id === "string" ? req.query.tenant_id : null)
    }),
    async (req, res, next) => {
      try {
        const { tenant_id } = tenantSchema.parse(req.query);
        const limit = typeof req.query.limit === "string" ? Number(req.query.limit) : 50;
        const lim = Number.isFinite(limit) ? Math.max(1, Math.min(500, Math.floor(limit))) : 50;
        const rows = await ctx.pool.query<{
          id: string;
          tenant_id: string;
          ran_at: Date;
          report_sha256: string;
          evidence_id: string | null;
          content_type: string | null;
          content_sha256: string | null;
          storage: string | null;
          created_at: Date | null;
        }>(
          "select r.id,r.tenant_id,r.ran_at,r.report_sha256,r.evidence_id,e.content_type,e.content_sha256,e.storage,e.created_at from retention_runs r left join evidence_objects e on e.id = r.evidence_id where r.tenant_id=$1 order by r.ran_at desc limit $2",
          [tenant_id, lim]
        );
        await appendAuditEvent(ctx.pool, {
          tenantId: tenant_id,
          eventType: "admin_retention_reports_listed",
          actorType: "admin",
          actorId: req.auth.userId,
          subjectType: "retention_runs",
          subjectId: "list",
          data: { limit: lim }
        });
        res.json(rows.rows.map((r) => ({ ...r, ran_at: r.ran_at.toISOString() })));
      } catch (err) {
        next(err);
      }
    }
  );

  router.post(
    "/privacy/retention",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_RETENTION_POLICY_SET,
      tenantId: (req) => (typeof (req as any)?.body?.tenant_id === "string" ? (req as any).body.tenant_id : null)
    }),
    async (req, res, next) => {
    try {
      const body = retentionSetSchema.parse(req.body ?? {});
      await ctx.pool.query(
        "insert into retention_policies (tenant_id,resource_type,retention_days,action,updated_at) values ($1,$2,$3,$4,$5) on conflict (tenant_id, resource_type) do update set retention_days=excluded.retention_days, action=excluded.action, updated_at=excluded.updated_at",
        [body.tenant_id, body.resource_type, body.retention_days, body.action, new Date()]
      );
      await appendAuditEvent(ctx.pool, {
        tenantId: body.tenant_id,
        eventType: "retention_policy_set",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "retention_policy",
        subjectId: body.resource_type,
        data: { retention_days: body.retention_days, action: body.action }
      });
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  }
  );

  router.post(
    "/privacy/retention/run",
    requirePermission(ctx, {
      action: PERMISSIONS.ADMIN_COMPLIANCE_RETENTION_RUN,
      tenantId: (req) => {
        const fromBody = typeof (req as any)?.body?.tenant_id === "string" ? (req as any).body.tenant_id : null;
        const fromQuery = typeof req.query.tenant_id === "string" ? req.query.tenant_id : null;
        return fromBody ?? fromQuery ?? null;
      }
    }),
    async (req, res, next) => {
    try {
      const tenantId = typeof req.body?.tenant_id === "string" ? req.body.tenant_id : typeof req.query.tenant_id === "string" ? req.query.tenant_id : null;
      const tenantFilter = z.string().uuid().parse(tenantId);
      const policies = await ctx.pool.query<{ tenant_id: string; resource_type: string; retention_days: number; action: string }>(
        "select tenant_id,resource_type,retention_days,action from retention_policies where tenant_id=$1",
        [tenantFilter]
      );
      const results: any[] = [];
      for (const p of policies.rows) {
        if (p.retention_days <= 0) continue;
        const cutoff = new Date(Date.now() - p.retention_days * 24 * 60 * 60 * 1000);
        if (p.resource_type === "identity_verifications" && p.action === "delete") {
          const del = await ctx.pool.query(
            "delete from identity_verifications where tenant_id=$1 and server_received_at < $2",
            [p.tenant_id, cutoff]
          );
          results.push({ tenant_id: p.tenant_id, resource_type: p.resource_type, action: p.action, cutoff: cutoff.toISOString(), deleted: del.rowCount });
        }
      }

      const ranAt = new Date();
      const report = {
        type: "retention_run_report",
        tenant_id: tenantFilter,
        ran_at: ranAt.toISOString(),
        results: results.map((r) => ({ ...r, deleted: Number(r.deleted ?? 0) }))
      };
      const reportJson = canonicalJson(report);
      const reportSha = sha256Hex(reportJson);
      const signed = signReceipt({ seedB64: ctx.config.RECEIPT_ED25519_SEED_B64, receipt: report });
      const envelopeJson = canonicalJson({ report, report_sha256: reportSha, ...signed });
      const envelopeSha = sha256Hex(envelopeJson);

      const retentionRunId = crypto.randomUUID();
      const evidenceId = crypto.randomUUID();
      const createdAtMs = ranAt.getTime();
      let evidence: { evidence_id: string; bucket?: string; key?: string; retain_until?: string; object_sha256: string } | null = null;
      const storeToWorm = ctx.config.COMPLIANCE_WORM_ENFORCE ? true : Boolean(createComplianceS3ClientIfConfigured(ctx.config));
      if (storeToWorm) {
        const s3 = createComplianceS3ClientIfConfigured(ctx.config);
        if (!s3) throw badRequest("worm_not_configured", "WORM storage not configured");
        const retentionDays = ctx.config.COMPLIANCE_S3_OBJECT_LOCK_DAYS;
        const retainUntil = new Date(ranAt.getTime() + retentionDays * 24 * 60 * 60 * 1000);
        const key = buildWormKey({
          prefix: "retention_runs",
          tenantId: tenantFilter,
          stream: "retention",
          createdAtMs,
          sha256: reportSha,
          suffix: "json"
        });
        const bodyBuf = Buffer.from(envelopeJson, "utf8");
        const bodySha = sha256Hex(bodyBuf);
        await s3.client.send(
          new PutObjectCommand({
            Bucket: s3.bucket,
            Key: key,
            Body: bodyBuf,
            ContentType: "application/json",
            ObjectLockMode: "COMPLIANCE",
            ObjectLockRetainUntilDate: retainUntil,
            Metadata: { tenant_id: tenantFilter, report_sha256: reportSha, object_sha256: bodySha, sig_kid: signed.sig_kid }
          })
        );
        await ctx.pool.query(
          "insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
          [
            evidenceId,
            tenantFilter,
            req.auth.userId,
            "retention_run_report",
            retentionRunId,
            "application/json",
            bodySha,
            "external",
            Buffer.from(JSON.stringify({ provider: "s3", bucket: s3.bucket, key, report_sha256: reportSha, sig_kid: signed.sig_kid, sig_b64: signed.sig_b64, retain_until: retainUntil.toISOString() }), "utf8").toString(
              "base64"
            ),
            ranAt,
            createdAtMs
          ]
        );
        evidence = { evidence_id: evidenceId, bucket: s3.bucket, key, retain_until: retainUntil.toISOString(), object_sha256: bodySha };
      } else {
        await ctx.pool.query(
          "insert into evidence_objects (id,tenant_id,owner_user_id,subject_type,subject_id,content_type,content_sha256,storage,blob_b64,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
          [
            evidenceId,
            tenantFilter,
            req.auth.userId,
            "retention_run_report",
            retentionRunId,
            "application/json",
            envelopeSha,
            "inline",
            Buffer.from(envelopeJson, "utf8").toString("base64"),
            ranAt,
            createdAtMs
          ]
        );
        evidence = { evidence_id: evidenceId, object_sha256: envelopeSha };
      }

      await ctx.pool.query("insert into retention_runs (id,tenant_id,ran_at,report_sha256,evidence_id) values ($1,$2,$3,$4,$5)", [
        retentionRunId,
        tenantFilter,
        ranAt,
        reportSha,
        evidenceId
      ]);

      await appendAuditEvent(ctx.pool, {
        tenantId: tenantFilter,
        eventType: "admin_retention_run",
        actorType: "admin",
        actorId: req.auth.userId,
        subjectType: "retention",
        subjectId: "run",
        data: { retention_run_id: retentionRunId, report_sha256: reportSha, evidence, results: results.map((r) => ({ ...r, deleted: Number(r.deleted ?? 0) })) }
      });
      res.json({ status: "ok", retention_run_id: retentionRunId, report_sha256: reportSha, ...signed, evidence, results });
    } catch (err) {
      next(err);
    }
  }
  );

  return router;
}

async function performDsarDelete(opts: { pool: MainApiContext["pool"]; tenantId: string; userId: string; requestId: string }) {
  const now = new Date();
  const countsBefore = await selectDsarCounts(opts.pool, { tenantId: opts.tenantId, userId: opts.userId });

  await opts.pool.query("update sessions set revoked_at=$1 where user_id=$2 and revoked_at is null", [now, opts.userId]);
  await opts.pool.query("delete from password_reset_tokens where user_id=$1", [opts.userId]);
  await opts.pool.query("delete from notifications where user_id=$1", [opts.userId]);
  await opts.pool.query("delete from credential_shares where tenant_id=$1 and owner_user_id=$2", [opts.tenantId, opts.userId]);
  await opts.pool.query("delete from consents where tenant_id=$1 and user_id=$2", [opts.tenantId, opts.userId]);
  await opts.pool.query("delete from proofs where tenant_id=$1 and user_id=$2", [opts.tenantId, opts.userId]);
  await opts.pool.query("delete from identity_verifications where tenant_id=$1 and user_id=$2", [opts.tenantId, opts.userId]);
  await opts.pool.query("delete from credentials where tenant_id=$1 and owner_user_id=$2", [opts.tenantId, opts.userId]);
  await opts.pool.query("delete from institution_members where user_id=$1", [opts.userId]);

  const tombstoneEmail = `deleted+${opts.userId}@example.invalid`;
  const tombstoneHash = sha256Hex(crypto.randomUUID());
  await opts.pool.query(
    "update users set email=$1, name='', phone='', bio='', avatar_url='', did='', status='deleted', password_hash=$2, twofa_enabled=false, twofa_secret='', backup_codes_sha='', last_login_at=null, updated_at=$3 where id=$4 and tenant_id=$5",
    [tombstoneEmail, tombstoneHash, now, opts.userId, opts.tenantId]
  );

  const countsAfter = await selectDsarCounts(opts.pool, { tenantId: opts.tenantId, userId: opts.userId });

  return {
    type: "dsar_deletion_report",
    tenant_id: opts.tenantId,
    user_id: opts.userId,
    dsar_request_id: opts.requestId,
    deleted_at: now.toISOString(),
    tombstone_email: tombstoneEmail,
    counts_before: countsBefore,
    counts_after: countsAfter,
    verified: {
      credentials: countsAfter.credentials === 0,
      identity_verifications: countsAfter.identity_verifications === 0,
      consents: countsAfter.consents === 0,
      proofs: countsAfter.proofs === 0,
      credential_shares: countsAfter.credential_shares === 0
    }
  };
}

async function selectDsarCounts(pool: MainApiContext["pool"], args: { tenantId: string; userId: string }) {
  const queries = await Promise.all([
    pool.query<{ count: string }>("select count(*)::text as count from credentials where tenant_id=$1 and owner_user_id=$2", [args.tenantId, args.userId]),
    pool.query<{ count: string }>("select count(*)::text as count from identity_verifications where tenant_id=$1 and user_id=$2", [args.tenantId, args.userId]),
    pool.query<{ count: string }>("select count(*)::text as count from consents where tenant_id=$1 and user_id=$2", [args.tenantId, args.userId]),
    pool.query<{ count: string }>("select count(*)::text as count from proofs where tenant_id=$1 and user_id=$2", [args.tenantId, args.userId]),
    pool.query<{ count: string }>("select count(*)::text as count from credential_shares where tenant_id=$1 and owner_user_id=$2", [args.tenantId, args.userId])
  ]);
  return {
    credentials: Number(queries[0].rows[0]?.count ?? 0),
    identity_verifications: Number(queries[1].rows[0]?.count ?? 0),
    consents: Number(queries[2].rows[0]?.count ?? 0),
    proofs: Number(queries[3].rows[0]?.count ?? 0),
    credential_shares: Number(queries[4].rows[0]?.count ?? 0)
  };
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}

function safeB64ToBuf(s: string) {
  try {
    return Buffer.from(s, "base64");
  } catch {
    return null;
  }
}

function createComplianceS3ClientIfConfigured(config: MainApiContext["config"]) {
  const endpoint = String(config.COMPLIANCE_S3_ENDPOINT ?? "").trim();
  const accessKeyId = String(config.COMPLIANCE_S3_ACCESS_KEY_ID ?? "").trim();
  const secretAccessKey = String(config.COMPLIANCE_S3_SECRET_ACCESS_KEY ?? "").trim();
  const bucket = String(config.COMPLIANCE_S3_BUCKET ?? "").trim();
  const region = String(config.COMPLIANCE_S3_REGION ?? "").trim();
  if (!endpoint || !accessKeyId || !secretAccessKey || !bucket || !region) return null;
  return {
    bucket,
    client: new S3Client({
      region,
      endpoint,
      forcePathStyle: config.COMPLIANCE_S3_FORCE_PATH_STYLE ?? false,
      credentials: { accessKeyId, secretAccessKey }
    })
  };
}

function buildWormKey(opts: { prefix: string; tenantId: string; stream: string; createdAtMs: number; sha256: string; suffix: string }) {
  const safeStream = opts.stream.replaceAll(/[^a-zA-Z0-9._-]/g, "_").slice(0, 64) || "tenant";
  return `compliance/${opts.prefix}/tenant=${opts.tenantId}/stream=${safeStream}/at_ms=${opts.createdAtMs}/${opts.sha256}.${opts.suffix}`;
}

function encodeAuditExportNdjson(opts: {
  tenantId: string;
  stream: string;
  fromSeq: number;
  toSeq: number | null;
  exportSha256: string;
  events: Array<Record<string, unknown>>;
}) {
  const lines: string[] = [];
  lines.push(
    JSON.stringify({
      type: "manifest",
      tenant_id: opts.tenantId,
      stream: opts.stream,
      from_seq: opts.fromSeq,
      to_seq: opts.toSeq,
      count: opts.events.length,
      export_sha256: opts.exportSha256
    })
  );
  for (const it of opts.events) lines.push(JSON.stringify({ type: "event", ...it }));
  return lines.join("\n") + "\n";
}
