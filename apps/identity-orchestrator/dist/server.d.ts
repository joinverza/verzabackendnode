import type { AddressInfo } from "node:net";
import axios from "axios";
import { S3Client } from "@aws-sdk/client-s3";
import { createPgPool } from "@verza/db";
import { createLogger } from "@verza/observability";
type RedisClient = {
    connect: () => Promise<void>;
    rPush: (key: string, value: string) => Promise<number>;
    blPop: (key: string, timeout: number) => Promise<{
        key: string;
        element: string;
    } | null>;
    quit: () => Promise<void>;
    isOpen: boolean;
};
export declare function createIdentityOrchestratorServer(): Promise<{
    start: () => Promise<AddressInfo>;
    stop: () => Promise<void>;
}>;
export declare function createIdentityOrchestratorApp(opts: {
    config: {
        JWT_SECRET: string;
        JWT_ISSUER: string;
        CORS_ALLOWED_ORIGINS?: string[];
        METRICS_ENABLED?: boolean;
        IDENTITY_RETENTION_DAYS?: number;
    };
    logger: ReturnType<typeof createLogger>;
    pool: ReturnType<typeof createPgPool>;
    inference: ReturnType<typeof axios.create>;
    redis: RedisClient | null;
    s3: {
        client: S3Client;
        bucket: string;
    } | null;
}): import("express-serve-static-core").Express;
export {};
//# sourceMappingURL=server.d.ts.map