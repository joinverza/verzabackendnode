import type { ErrorRequestHandler, RequestHandler } from "express";
import type { Logger } from "@verza/observability";
export declare class HttpError extends Error {
    status: number;
    code: string;
    details: Record<string, unknown> | undefined;
    constructor(status: number, code: string, message: string, details?: Record<string, unknown>);
}
export declare function badRequest(code: string, message: string, details?: Record<string, unknown>): HttpError;
export declare function unauthorized(code: string, message: string, details?: Record<string, unknown>): HttpError;
export declare function forbidden(code: string, message: string, details?: Record<string, unknown>): HttpError;
export declare function notFound(code: string, message: string, details?: Record<string, unknown>): HttpError;
export declare function createHttpApp(opts: {
    logger: Logger;
    corsAllowedOrigins: string[];
}): import("express-serve-static-core").Express;
export declare const notFoundHandler: RequestHandler;
declare module "express-serve-static-core" {
    interface Request {
        requestId: string;
        bodyRaw?: Buffer;
    }
}
export declare function errorHandler(): ErrorRequestHandler;
//# sourceMappingURL=index.d.ts.map