import type { ErrorRequestHandler, RequestHandler } from "express";
import type { Logger } from "@verza/observability";

import crypto from "node:crypto";

import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import { SpanKind, SpanStatusCode, context, propagation, trace } from "@opentelemetry/api";
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
  app.use(traceMiddleware());
  app.use(
    pinoHttp({
      logger: opts.logger,
      customProps: (req: express.Request) => ({ request_id: req.requestId, trace_id: req.traceId ?? "", span_id: req.spanId ?? "" })
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

export function createRateLimiter(opts: {
  windowMs: number;
  limit: number;
  message?: { code: string; message: string };
  keyGenerator?: (req: express.Request) => string;
  skip?: (req: express.Request) => boolean;
}) {
  const config = {
    windowMs: opts.windowMs,
    limit: opts.limit,
    standardHeaders: true,
    legacyHeaders: false,
    ...(opts.skip ? { skip: opts.skip } : {}),
    ...(opts.keyGenerator ? { keyGenerator: opts.keyGenerator } : {}),
    handler: (req: express.Request, res: express.Response) => {
      res.status(429).json({
        error: {
          code: opts.message?.code ?? "rate_limited",
          message: opts.message?.message ?? "Too many requests",
          details: {},
          request_id: req.requestId || ""
        }
      });
    }
  };
  return rateLimit(config);
}

export const notFoundHandler: RequestHandler = (req, _res, next) => {
  next(notFound("not_found", `Route not found: ${req.method} ${req.path}`));
};

declare module "express-serve-static-core" {
  interface Request {
    requestId: string;
    bodyRaw?: Buffer;
    traceId?: string;
    spanId?: string;
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

function traceMiddleware(): RequestHandler {
  return (req, res, next) => {
    const getter = {
      get: (carrier: Record<string, string | string[] | undefined>, key: string) => {
        const v = carrier[key.toLowerCase()];
        if (!v) return undefined;
        if (Array.isArray(v)) return v.join(",");
        return v;
      },
      keys: (carrier: Record<string, string | string[] | undefined>) => Object.keys(carrier)
    };
    const extracted = propagation.extract(context.active(), req.headers as unknown as Record<string, string | string[] | undefined>, getter);
    const tracer = trace.getTracer("verza-http");
    const attrs: Record<string, string> = {
      "http.method": req.method,
      "http.target": req.path,
      "http.request_id": req.requestId
    };
    const ua = req.headers["user-agent"];
    if (typeof ua === "string" && ua.trim().length) attrs["http.user_agent"] = ua;
    const routePath = (req as any).route?.path;
    if (typeof routePath === "string" && routePath.trim().length) attrs["http.route"] = routePath;
    const span = tracer.startSpan(
      `${req.method} ${req.path}`,
      {
        kind: SpanKind.SERVER,
        attributes: attrs
      },
      extracted
    );

    const sc = span.spanContext();
    req.traceId = sc.traceId;
    req.spanId = sc.spanId;

    const spanCtx = trace.setSpan(extracted, span);
    const setter = { set: (carrier: Record<string, string>, key: string, value: string) => (carrier[key] = value) };
    const carrierOut: Record<string, string> = {};
    propagation.inject(spanCtx, carrierOut, setter);
    if (carrierOut.traceparent) res.setHeader("traceparent", carrierOut.traceparent);

    res.on("finish", () => {
      span.setAttribute("http.status_code", res.statusCode);
      if (res.statusCode >= 500) span.setStatus({ code: SpanStatusCode.ERROR });
      else span.setStatus({ code: SpanStatusCode.OK });
      span.end();
    });

    context.with(spanCtx, next);
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
