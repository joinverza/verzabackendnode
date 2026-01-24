import { z } from "zod";

export type MainApiConfig = ReturnType<typeof createMainApiConfig>;
export type IdentityGatewayConfig = ReturnType<typeof createIdentityGatewayConfig>;
export type IdentityOrchestratorConfig = ReturnType<typeof createIdentityOrchestratorConfig>;

const baseSchema = z.object({
  NODE_ENV: z.string().optional(),
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().default(8090),
  LOG_LEVEL: z.string().default("info"),
  CORS_ALLOWED_ORIGINS: z
    .string()
    .default("")
    .transform((v) =>
      v
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    )
});

const mainApiSchema = baseSchema.extend({
  DATABASE_URL: z.string().min(1),
  JWT_SECRET: z.string().min(16),
  JWT_ISSUER: z.string().default(""),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 30),
  ENCRYPTION_MASTER_KEY_B64: z.string().min(1),
  RECEIPT_ED25519_SEED_B64: z.string().min(1),
  DID_SESSION_SECRET: z.string().optional()
});

export function createMainApiConfig(env: NodeJS.ProcessEnv) {
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

export function createIdentityGatewayConfig(env: NodeJS.ProcessEnv) {
  return identityGatewaySchema.parse(env);
}

const identityOrchestratorSchema = baseSchema.extend({
  PORT: z.coerce.number().default(8089),
  IDENTITY_DATABASE_URL: z.string().min(1),
  INFERENCE_URL: z.string().min(1),
  REDIS_URL: z.string().optional(),
  JWT_SECRET: z.string().min(16),
  JWT_ISSUER: z.string().default(""),
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

export function createIdentityOrchestratorConfig(env: NodeJS.ProcessEnv) {
  return identityOrchestratorSchema.parse(env);
}

