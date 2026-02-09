import crypto from "node:crypto";
import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import { SpanKind, SpanStatusCode, context, propagation, trace } from "@opentelemetry/api";
import { pinoHttp } from "pino-http";
export class HttpError extends Error {
    status;
    code;
    details;
    constructor(status, code, message, details) {
        super(message);
        this.status = status;
        this.code = code;
        this.details = details;
    }
}
export function badRequest(code, message, details) {
    return new HttpError(400, code, message, details);
}
export function unauthorized(code, message, details) {
    return new HttpError(401, code, message, details);
}
export function forbidden(code, message, details) {
    return new HttpError(403, code, message, details);
}
export function notFound(code, message, details) {
    return new HttpError(404, code, message, details);
}
export function createHttpApp(opts) {
    const app = express();
    app.use(requestIdMiddleware());
    app.use(traceMiddleware());
    app.use(pinoHttp({
        logger: opts.logger,
        customProps: (req) => ({ request_id: req.requestId, trace_id: req.traceId ?? "", span_id: req.spanId ?? "" })
    }));
    app.use(cors({
        origin: (origin, cb) => {
            if (!origin)
                return cb(null, true);
            if (!opts.corsAllowedOrigins.length)
                return cb(null, true);
            cb(null, opts.corsAllowedOrigins.includes(origin));
        },
        credentials: true
    }));
    app.use(rateLimit({
        windowMs: 60_000,
        limit: 120,
        standardHeaders: true,
        legacyHeaders: false,
        skip: (req) => req.path.startsWith("/health") || req.path === "/healthz"
    }));
    app.use(express.json({
        limit: "1mb",
        verify: (req, _res, buf) => {
            req.bodyRaw = Buffer.from(buf);
        }
    }));
    return app;
}
export function createRateLimiter(opts) {
    const config = {
        windowMs: opts.windowMs,
        limit: opts.limit,
        standardHeaders: true,
        legacyHeaders: false,
        ...(opts.skip ? { skip: opts.skip } : {}),
        ...(opts.keyGenerator ? { keyGenerator: opts.keyGenerator } : {}),
        handler: (req, res) => {
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
export const notFoundHandler = (req, _res, next) => {
    next(notFound("not_found", `Route not found: ${req.method} ${req.path}`));
};
function requestIdMiddleware() {
    return (req, res, next) => {
        const incoming = req.header("x-request-id");
        const requestId = incoming && incoming.trim().length ? incoming : crypto.randomUUID();
        req.requestId = requestId;
        res.setHeader("x-request-id", requestId);
        next();
    };
}
function traceMiddleware() {
    return (req, res, next) => {
        const getter = {
            get: (carrier, key) => {
                const v = carrier[key.toLowerCase()];
                if (!v)
                    return undefined;
                if (Array.isArray(v))
                    return v.join(",");
                return v;
            },
            keys: (carrier) => Object.keys(carrier)
        };
        const extracted = propagation.extract(context.active(), req.headers, getter);
        const tracer = trace.getTracer("verza-http");
        const attrs = {
            "http.method": req.method,
            "http.target": req.path,
            "http.request_id": req.requestId
        };
        const ua = req.headers["user-agent"];
        if (typeof ua === "string" && ua.trim().length)
            attrs["http.user_agent"] = ua;
        const routePath = req.route?.path;
        if (typeof routePath === "string" && routePath.trim().length)
            attrs["http.route"] = routePath;
        const span = tracer.startSpan(`${req.method} ${req.path}`, {
            kind: SpanKind.SERVER,
            attributes: attrs
        }, extracted);
        const sc = span.spanContext();
        req.traceId = sc.traceId;
        req.spanId = sc.spanId;
        const spanCtx = trace.setSpan(extracted, span);
        const setter = { set: (carrier, key, value) => (carrier[key] = value) };
        const carrierOut = {};
        propagation.inject(spanCtx, carrierOut, setter);
        if (carrierOut.traceparent)
            res.setHeader("traceparent", carrierOut.traceparent);
        res.on("finish", () => {
            span.setAttribute("http.status_code", res.statusCode);
            if (res.statusCode >= 500)
                span.setStatus({ code: SpanStatusCode.ERROR });
            else
                span.setStatus({ code: SpanStatusCode.OK });
            span.end();
        });
        context.with(spanCtx, next);
    };
}
export function errorHandler() {
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
//# sourceMappingURL=index.js.map