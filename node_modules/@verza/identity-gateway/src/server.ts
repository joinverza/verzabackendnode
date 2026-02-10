import type { AddressInfo } from "node:net";
import http from "node:http";
import https from "node:https";
import fs from "node:fs";

import axios from "axios";
import type { Request } from "express";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { requireUser } from "@verza/auth";
import { createIdentityGatewayConfig } from "@verza/config";
import { createHttpApp, createRateLimiter, errorHandler, notFoundHandler } from "@verza/http";
import { createLogger, initTelemetry } from "@verza/observability";
import promClient from "prom-client";
import { z } from "zod";

const sessionsSchema = z.object({
  user_id: z.string().optional()
});

const presignSchema = z.object({
  key: z.string().min(1),
  content_type: z.string().min(1)
});

const createVerificationSchema = z.object({
  type: z.string().min(1),
  subject_id: z.string().optional()
});

export function createIdentityGatewayServer() {
  const config = createIdentityGatewayConfig(process.env);
  const logger = createLogger({ service: "identity-gateway", level: config.LOG_LEVEL });
  let telemetry: null | { enabled: boolean; shutdown: () => Promise<void> } = null;

  const app = createHttpApp({ logger, corsAllowedOrigins: config.CORS_ALLOWED_ORIGINS });
  app.get("/healthz", (_req, res) => res.json({ status: "ok" }));

  if (config.METRICS_ENABLED) {
    const register = new promClient.Registry();
    register.setDefaultLabels({ service: "identity-gateway" });
    promClient.collectDefaultMetrics({ register });
    app.get("/metrics", async (_req, res, next) => {
      try {
        res.setHeader("content-type", register.contentType);
        res.send(await register.metrics());
      } catch (err) {
        next(err);
      }
    });
  }

  const httpsAgent = buildMtlsAgent({
    caPath: config.ORCHESTRATOR_MTLS_CA_PATH,
    certPath: config.ORCHESTRATOR_MTLS_CERT_PATH,
    keyPath: config.ORCHESTRATOR_MTLS_KEY_PATH
  });
  assertMtlsConfigurationConsistent({ orchestratorUrl: config.ORCHESTRATOR_URL, httpsAgent, config });
  const httpClient = axios.create({
    baseURL: config.ORCHESTRATOR_URL,
    timeout: 30_000,
    ...(httpsAgent ? { httpsAgent } : {})
  });
  const auth = requireUser({
    config: { JWT_SECRET: config.JWT_SECRET, JWT_ISSUER: config.JWT_ISSUER, JWT_AUDIENCE: config.JWT_AUDIENCE }
  });
  const limiterKey = (req: any) => (req.auth?.userId ? `u:${req.auth.userId}` : `ip:${req.ip}`);

  const s3Config = getS3Config(config);
  const s3 = s3Config
    ? new S3Client({
        region: s3Config.region,
        endpoint: s3Config.endpoint,
        forcePathStyle: config.S3_FORCE_PATH_STYLE,
        credentials: {
          accessKeyId: s3Config.accessKeyId,
          secretAccessKey: s3Config.secretAccessKey
        }
      })
    : null;

  app.post(
    "/v1/sessions",
    auth,
    createRateLimiter({ windowMs: 60_000, limit: 60, keyGenerator: limiterKey }),
    (req: Request<Record<string, never>, unknown, unknown>, res, next) => {
    void (async () => {
      const body = sessionsSchema.parse(req.body);
      const resp = await httpClient.post("/internal/v1/sessions", body, { headers: passthroughHeaders(req.headers) });
      res.status(resp.status).json(resp.data);
    })().catch(next);
    }
  );

  app.post(
    "/v1/media/presign",
    auth,
    createRateLimiter({ windowMs: 60_000, limit: 30, keyGenerator: limiterKey }),
    (req: Request<Record<string, never>, unknown, unknown>, res, next) => {
    void (async () => {
      if (!s3 || !s3Config) {
        res.status(503).json({ error: "storage_not_configured" });
        return;
      }
      const body = presignSchema.parse(req.body);
      const command = new PutObjectCommand({
        Bucket: s3Config.bucket,
        Key: body.key,
        ContentType: body.content_type
      });
      const url = await getSignedUrl(s3, command, { expiresIn: 60 });
      res.json({ url, method: "PUT", headers: { "content-type": body.content_type } });
    })().catch(next);
    }
  );

  app.post(
    "/v1/verifications",
    auth,
    createRateLimiter({ windowMs: 60_000, limit: 30, keyGenerator: limiterKey }),
    (req: Request<Record<string, never>, unknown, unknown>, res, next) => {
    void (async () => {
      const body = createVerificationSchema.parse(req.body);
      const resp = await httpClient.post("/internal/v1/verifications", body, { headers: passthroughHeaders(req.headers) });
      res.status(resp.status).json(resp.data);
    })().catch(next);
    }
  );

  app.all(
    "/v1/verifications/:id",
    auth,
    createRateLimiter({ windowMs: 60_000, limit: 120, keyGenerator: limiterKey }),
    (req: Request<{ id: string }, unknown, unknown>, res, next) => {
      void (async () => {
        const id = String(req.params.id);
        const targetPath = `/internal/v1/verifications/${encodeURIComponent(id)}`;
        const resp = await httpClient.request({
          method: req.method,
          url: targetPath,
          data: req.body,
          headers: passthroughHeaders(req.headers),
          validateStatus: () => true
        });
        res.status(resp.status).json(resp.data);
      })().catch(next);
    }
  );

  app.all(
    "/v1/verifications/:id/*",
    auth,
    createRateLimiter({ windowMs: 60_000, limit: 120, keyGenerator: limiterKey }),
    (req: Request<{ id: string }, unknown, unknown>, res, next) => {
    void (async () => {
      const id = String(req.params.id);
      const paramsAny = req.params as unknown as Record<string, string | undefined>;
      const suffix = paramsAny["0"] ? String(paramsAny["0"]) : "";
      const targetPath = `/internal/v1/verifications/${encodeURIComponent(id)}/${suffix}`;
      const resp = await httpClient.request({
        method: req.method,
        url: targetPath,
        data: req.body,
        headers: passthroughHeaders(req.headers),
        validateStatus: () => true
      });
      res.status(resp.status).json(resp.data);
    })().catch(next);
    }
  );

  app.use(notFoundHandler);
  app.use(errorHandler());

  const server = http.createServer(app);

  return {
    start: async () => {
      if (!telemetry) telemetry = await initTelemetry({ serviceName: "identity-gateway" });
      await new Promise<void>((resolve) => server.listen(config.PORT, config.HOST, resolve));
      logger.info({ addr: server.address() as AddressInfo }, "identity-gateway listening");
      return server.address() as AddressInfo;
    },
    stop: async () => {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
      if (telemetry) await telemetry.shutdown();
    }
  };
}

function passthroughHeaders(headers: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  const requestId = typeof headers["x-request-id"] === "string" ? headers["x-request-id"] : undefined;
  if (requestId) out["x-request-id"] = requestId;
  const traceparent = typeof headers.traceparent === "string" ? headers.traceparent : undefined;
  if (traceparent) out.traceparent = traceparent;
  const auth = typeof headers.authorization === "string" ? headers.authorization : undefined;
  if (auth) out.authorization = auth;
  const idem = typeof headers["idempotency-key"] === "string" ? headers["idempotency-key"] : undefined;
  if (idem) out["idempotency-key"] = idem;
  return out;
}

function getS3Config(config: {
  S3_ENDPOINT?: string | undefined;
  S3_REGION?: string | undefined;
  S3_BUCKET?: string | undefined;
  S3_ACCESS_KEY_ID?: string | undefined;
  S3_SECRET_ACCESS_KEY?: string | undefined;
}) {
  const endpoint = String(config.S3_ENDPOINT ?? "").trim();
  const region = String(config.S3_REGION ?? "").trim();
  const bucket = String(config.S3_BUCKET ?? "").trim();
  const accessKeyId = String(config.S3_ACCESS_KEY_ID ?? "").trim();
  const secretAccessKey = String(config.S3_SECRET_ACCESS_KEY ?? "").trim();
  if (!endpoint || !region || !bucket || !accessKeyId || !secretAccessKey) return null;
  return { endpoint, region, bucket, accessKeyId, secretAccessKey };
}

function buildMtlsAgent(opts: { caPath?: string | undefined; certPath?: string | undefined; keyPath?: string | undefined }) {
  const caPath = String(opts.caPath ?? "").trim();
  const certPath = String(opts.certPath ?? "").trim();
  const keyPath = String(opts.keyPath ?? "").trim();
  const hasAny = Boolean(caPath || certPath || keyPath);
  if (!hasAny) return null;

  const ca = caPath ? fs.readFileSync(caPath) : undefined;
  const cert = certPath ? fs.readFileSync(certPath) : undefined;
  const key = keyPath ? fs.readFileSync(keyPath) : undefined;

  return new https.Agent({
    ...(ca ? { ca } : {}),
    ...(cert ? { cert } : {}),
    ...(key ? { key } : {}),
    rejectUnauthorized: true
  });
}

function assertMtlsConfigurationConsistent(opts: {
  orchestratorUrl: string;
  httpsAgent: https.Agent | null;
  config: { ORCHESTRATOR_MTLS_CA_PATH?: string | undefined; ORCHESTRATOR_MTLS_CERT_PATH?: string | undefined; ORCHESTRATOR_MTLS_KEY_PATH?: string | undefined };
}) {
  const url = String(opts.orchestratorUrl ?? "").trim();
  const ca = String(opts.config.ORCHESTRATOR_MTLS_CA_PATH ?? "").trim();
  const cert = String(opts.config.ORCHESTRATOR_MTLS_CERT_PATH ?? "").trim();
  const key = String(opts.config.ORCHESTRATOR_MTLS_KEY_PATH ?? "").trim();
  const wantsMtls = Boolean(ca || cert || key);
  const isHttps = url.toLowerCase().startsWith("https://");
  if (isHttps) {
    if (!wantsMtls) throw new Error("identity-gateway ORCHESTRATOR_URL is https:// but mTLS is not configured");
    if (!opts.httpsAgent) throw new Error("identity-gateway mTLS misconfigured");
    if (!ca || !cert || !key) throw new Error("identity-gateway mTLS requires ORCHESTRATOR_MTLS_CA_PATH, ORCHESTRATOR_MTLS_CERT_PATH, ORCHESTRATOR_MTLS_KEY_PATH");
  } else {
    if (wantsMtls) throw new Error("identity-gateway mTLS is configured but ORCHESTRATOR_URL is not https://");
  }
}
