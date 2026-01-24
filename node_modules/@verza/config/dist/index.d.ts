export type MainApiConfig = ReturnType<typeof createMainApiConfig>;
export type IdentityGatewayConfig = ReturnType<typeof createIdentityGatewayConfig>;
export type IdentityOrchestratorConfig = ReturnType<typeof createIdentityOrchestratorConfig>;
export declare function createMainApiConfig(env: NodeJS.ProcessEnv): {
    DID_SESSION_SECRET: string;
    HOST: string;
    PORT: number;
    LOG_LEVEL: string;
    CORS_ALLOWED_ORIGINS: string[];
    DATABASE_URL: string;
    JWT_SECRET: string;
    JWT_ISSUER: string;
    ACCESS_TOKEN_TTL_SECONDS: number;
    REFRESH_TOKEN_TTL_SECONDS: number;
    ENCRYPTION_MASTER_KEY_B64: string;
    RECEIPT_ED25519_SEED_B64: string;
    NODE_ENV?: string | undefined;
};
export declare function createIdentityGatewayConfig(env: NodeJS.ProcessEnv): {
    HOST: string;
    PORT: number;
    LOG_LEVEL: string;
    CORS_ALLOWED_ORIGINS: string[];
    ORCHESTRATOR_URL: string;
    S3_ENDPOINT: string;
    S3_ACCESS_KEY_ID: string;
    S3_SECRET_ACCESS_KEY: string;
    S3_BUCKET: string;
    S3_REGION: string;
    S3_FORCE_PATH_STYLE: boolean;
    NODE_ENV?: string | undefined;
};
export declare function createIdentityOrchestratorConfig(env: NodeJS.ProcessEnv): {
    HOST: string;
    PORT: number;
    LOG_LEVEL: string;
    CORS_ALLOWED_ORIGINS: string[];
    IDENTITY_DATABASE_URL: string;
    INFERENCE_URL: string;
    NODE_ENV?: string | undefined;
    REDIS_URL?: string | undefined;
};
//# sourceMappingURL=index.d.ts.map