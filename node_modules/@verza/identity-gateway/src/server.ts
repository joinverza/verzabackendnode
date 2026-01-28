import type { AddressInfo } from "node:net";
import http from "node:http";

import axios from "axios";
import type { Request } from "express";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { createIdentityGatewayConfig } from "@verza/config";
import { createHttpApp, errorHandler, notFoundHandler } from "@verza/http";
import { createLogger } from "@verza/observability";
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

  const httpClient = axios.create({ baseURL: config.ORCHESTRATOR_URL, timeout: 30_000 });

  const s3 = new S3Client({
    region: config.S3_REGION,
    endpoint: config.S3_ENDPOINT,
    forcePathStyle: config.S3_FORCE_PATH_STYLE,
    credentials: {
      accessKeyId: config.S3_ACCESS_KEY_ID,
      secretAccessKey: config.S3_SECRET_ACCESS_KEY
    }
  });

  app.post("/v1/sessions", (req: Request<Record<string, never>, unknown, unknown>, res, next) => {
    void (async () => {
      const body = sessionsSchema.parse(req.body);
      const resp = await httpClient.post("/internal/v1/sessions", body, { headers: passthroughHeaders(req.headers) });
      res.status(resp.status).json(resp.data);
    })().catch(next);
  });

  app.post("/v1/media/presign", (req: Request<Record<string, never>, unknown, unknown>, res, next) => {
    void (async () => {
      const body = presignSchema.parse(req.body);
      const command = new PutObjectCommand({
        Bucket: config.S3_BUCKET,
        Key: body.key,
        ContentType: body.content_type
      });
      const url = await getSignedUrl(s3, command, { expiresIn: 60 });
      res.json({ url, method: "PUT", headers: { "content-type": body.content_type } });
    })().catch(next);
  });

  app.post("/v1/verifications", (req: Request<Record<string, never>, unknown, unknown>, res, next) => {
    void (async () => {
      const body = createVerificationSchema.parse(req.body);
      const resp = await httpClient.post("/internal/v1/verifications", body, { headers: passthroughHeaders(req.headers) });
      res.status(resp.status).json(resp.data);
    })().catch(next);
  });

  app.all("/v1/verifications/:id/*", (req: Request<{ id: string }, unknown, unknown>, res, next) => {
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
  });

  app.use(notFoundHandler);
  app.use(errorHandler());

  const server = http.createServer(app);

  return {
    start: async () => {
      await new Promise<void>((resolve) => server.listen(config.PORT, config.HOST, resolve));
      logger.info({ addr: server.address() as AddressInfo }, "identity-gateway listening");
      return server.address() as AddressInfo;
    },
    stop: async () => {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
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
  return out;
}
