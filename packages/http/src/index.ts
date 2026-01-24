import type { ErrorRequestHandler, RequestHandler } from "express";
import type { Logger } from "@verza/observability";

import crypto from "node:crypto";

import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import { pinoHttp } from "pino-http";

export class HttpError extends Error {
  public status: number;
  public code: string;
  public details: Record<string, unknown> | undefined;
  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function badRequest(code: string, message: string, details?: Record<string, unknown>) {
  return new HttpError(400, code, message, details);
}
export function unauthorized(code: string, message: string, details?: Record<string, unknown>) {
  return new HttpError(401, code, message, details);
}
export function forbidden(code: string, message: string, details?: Record<string, unknown>) {
  return new HttpError(403, code, message, details);
}
export function notFound(code: string, message: string, details?: Record<string, unknown>) {
  return new HttpError(404, code, message, details);
}

export function createHttpApp(opts: { logger: Logger; corsAllowedOrigins: string[] }) {
  const app = express();

  app.use(requestIdMiddleware());
  app.use(
    pinoHttp({
      logger: opts.logger,
      customProps: (req: express.Request) => ({ request_id: req.requestId })
    })
  );
  app.use(
    cors({
      origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        if (!opts.corsAllowedOrigins.length) return cb(null, true);
        cb(null, opts.corsAllowedOrigins.includes(origin));
      },
      credentials: true
    })
  );
  app.use(
    rateLimit({
      windowMs: 60_000,
      limit: 120,
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => req.path.startsWith("/health") || req.path === "/healthz"
    })
  );

  app.use(
    express.json({
      limit: "1mb",
      verify: (req: express.Request, _res, buf) => {
        req.bodyRaw = Buffer.from(buf);
      }
    })
  );

  return app;
}

export const notFoundHandler: RequestHandler = (req, _res, next) => {
  next(notFound("not_found", `Route not found: ${req.method} ${req.path}`));
};

declare module "express-serve-static-core" {
  interface Request {
    requestId: string;
    bodyRaw?: Buffer;
  }
}

function requestIdMiddleware(): RequestHandler {
  return (req, res, next) => {
    const incoming = req.header("x-request-id");
    const requestId = incoming && incoming.trim().length ? incoming : crypto.randomUUID();
    req.requestId = requestId;
    res.setHeader("x-request-id", requestId);
    next();
  };
}

export function errorHandler(): ErrorRequestHandler {
  return (err, req, res, _next) => {
    void _next;
    const requestId = req.requestId || "";
    if (err instanceof HttpError) {
      res.status(err.status).json({
        error: { code: err.code, message: err.message, details: err.details ?? {}, request_id: requestId }
      });
      return;
    }
    const message = err instanceof Error ? err.message : "Unknown error";
    res.status(500).json({
      error: { code: "internal", message, details: {}, request_id: requestId }
    });
  };
}
