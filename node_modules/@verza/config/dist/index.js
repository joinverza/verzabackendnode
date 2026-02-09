import { z } from "zod";
const baseSchema = z.object({
    NODE_ENV: z.string().optional(),
    HOST: z.string().default("0.0.0.0"),
    PORT: z.coerce.number().default(8090),
    LOG_LEVEL: z.string().default("info"),
    METRICS_ENABLED: z
        .string()
        .optional()
        .default("0")
        .transform((v) => v === "1" || v.toLowerCase() === "true"),
    CORS_ALLOWED_ORIGINS: z
        .string()
        .default("")
        .transform((v) => v
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean))
});
const mainApiSchema = baseSchema.extend({
    DATABASE_URL: z.string().min(1),
    REDIS_URL: z.string().optional(),
    JWT_SECRET: z.string().min(16),
    JWT_ISSUER: z.string().min(1).default("verza"),
    JWT_AUDIENCE: z.string().min(1).default("verza"),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
    REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 30),
    ENCRYPTION_MASTER_KEY_B64: z.string().min(1),
    RECEIPT_ED25519_SEED_B64: z.string().min(1),
    IDENTITY_GATEWAY_URL: z.string().optional(),
    IDENTITY_RETENTION_DAYS: z.coerce.number().int().nonnegative().optional().default(0),
    COMPLIANCE_S3_ENDPOINT: z.string().optional(),
    COMPLIANCE_S3_ACCESS_KEY_ID: z.string().optional(),
    COMPLIANCE_S3_SECRET_ACCESS_KEY: z.string().optional(),
    COMPLIANCE_S3_BUCKET: z.string().optional(),
    COMPLIANCE_S3_REGION: z.string().optional(),
    COMPLIANCE_S3_FORCE_PATH_STYLE: z
        .string()
        .optional()
        .default("0")
        .transform((v) => v === "1" || v.toLowerCase() === "true"),
    COMPLIANCE_S3_OBJECT_LOCK_DAYS: z.coerce.number().int().positive().optional().default(3650),
    COMPLIANCE_WORM_ENFORCE: z
        .string()
        .optional()
        .default("0")
        .transform((v) => v === "1" || v.toLowerCase() === "true"),
    AUDIT_ANCHOR_URL: z.string().optional(),
    AUDIT_ANCHOR_SECRET: z.string().optional(),
    AUDIT_ANCHOR_INTERVAL_SECONDS: z.coerce.number().int().positive().optional().default(3600),
    RETENTION_JOB_ENABLED: z
        .string()
        .optional()
        .default("0")
        .transform((v) => v === "1" || v.toLowerCase() === "true"),
    RETENTION_JOB_INTERVAL_SECONDS: z.coerce.number().int().positive().optional().default(86400),
    DSAR_FOUR_EYES_REQUIRED: z.coerce.number().int().positive().optional().default(2),
    DID_SESSION_SECRET: z.string().optional(),
    REQUIRE_ADMIN_2FA: z
        .string()
        .optional()
        .default("1")
        .transform((v) => v === "1" || v.toLowerCase() === "true"),
    PASSWORD_RESET_BASE_URL: z.string().optional(),
    SMTP_HOST: z.string().optional(),
    SMTP_PORT: z.coerce.number().optional(),
    SMTP_SECURE: z
        .string()
        .optional()
        .transform((v) => v === "1" || v?.toLowerCase() === "true"),
    SMTP_USER: z.string().optional(),
    SMTP_PASS: z.string().optional(),
    SMTP_FROM: z.string().optional(),
    TWILIO_ACCOUNT_SID: z.string().optional(),
    TWILIO_AUTH_TOKEN: z.string().optional(),
    TWILIO_FROM_NUMBER: z.string().optional(),
    STRIPE_SECRET_KEY: z.string().optional(),
    STRIPE_WEBHOOK_SECRET: z.string().optional()
});
export function createMainApiConfig(env) {
    const parsed = mainApiSchema.parse({
        ...env,
        PORT: env.PORT ?? env.VERZA_ADDR?.split(":").pop()
    });
    return {
        ...parsed,
        DID_SESSION_SECRET: parsed.DID_SESSION_SECRET ?? parsed.JWT_SECRET
    };
}
const identityGatewaySchema = baseSchema.extend({
    PORT: z.coerce.number().default(8088),
    ORCHESTRATOR_URL: z.string().min(1),
    JWT_SECRET: z.string().min(16),
    JWT_ISSUER: z.string().min(1).default("verza"),
    JWT_AUDIENCE: z.string().min(1).default("verza"),
    ORCHESTRATOR_MTLS_CA_PATH: z.string().optional(),
    ORCHESTRATOR_MTLS_CERT_PATH: z.string().optional(),
    ORCHESTRATOR_MTLS_KEY_PATH: z.string().optional(),
    S3_ENDPOINT: z.string().min(1),
    S3_ACCESS_KEY_ID: z.string().min(1),
    S3_SECRET_ACCESS_KEY: z.string().min(1),
    S3_BUCKET: z.string().min(1),
    S3_REGION: z.string().min(1),
    S3_FORCE_PATH_STYLE: z
        .string()
        .default("0")
        .transform((v) => v === "1" || v.toLowerCase() === "true")
});
export function createIdentityGatewayConfig(env) {
    return identityGatewaySchema.parse(env);
}
const identityOrchestratorSchema = baseSchema.extend({
    PORT: z.coerce.number().default(8089),
    IDENTITY_DATABASE_URL: z.string().min(1),
    INFERENCE_URL: z.string().min(1),
    REDIS_URL: z.string().optional(),
    JWT_SECRET: z.string().min(16),
    JWT_ISSUER: z.string().min(1).default("verza"),
    JWT_AUDIENCE: z.string().min(1).default("verza"),
    IDENTITY_RETENTION_DAYS: z.coerce.number().int().nonnegative().optional().default(0),
    TLS_KEY_PATH: z.string().optional(),
    TLS_CERT_PATH: z.string().optional(),
    TLS_CA_PATH: z.string().optional(),
    TLS_REQUIRE_CLIENT_CERT: z
        .string()
        .optional()
        .default("0")
        .transform((v) => v === "1" || v?.toLowerCase() === "true"),
    S3_ENDPOINT: z.string().optional(),
    S3_ACCESS_KEY_ID: z.string().optional(),
    S3_SECRET_ACCESS_KEY: z.string().optional(),
    S3_BUCKET: z.string().optional(),
    S3_REGION: z.string().optional(),
    S3_FORCE_PATH_STYLE: z
        .string()
        .optional()
        .transform((v) => v === "1" || v?.toLowerCase() === "true")
});
export function createIdentityOrchestratorConfig(env) {
    return identityOrchestratorSchema.parse(env);
}
//# sourceMappingURL=index.js.map