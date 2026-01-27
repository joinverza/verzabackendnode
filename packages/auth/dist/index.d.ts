import type { RequestHandler } from "express";
import type { Pool } from "pg";
type JwtClaims = {
    iss?: string;
    sub: string;
    email: string;
    role: string;
    sid: string;
    iat: number;
    exp: number;
};
export declare function createAccessToken(opts: {
    secret: string;
    issuer: string;
    ttlSeconds: number;
    claims: {
        sub: string;
        email: string;
        role: string;
        sid: string;
    };
}): string;
export declare function generateRefreshToken(): string;
export declare function verifyAccessToken(opts: {
    token: string;
    secret: string;
    issuer: string;
}): JwtClaims | null;
export type AuthContext = {
    config: {
        JWT_SECRET: string;
        JWT_ISSUER: string;
    };
};
export declare function requireUser(ctx: AuthContext): RequestHandler;
export declare function requireAdmin(ctx: AuthContext): RequestHandler;
export type InstitutionAuthContext = {
    pool: Pool;
};
export declare function requireInstitutionApiKey(ctx: InstitutionAuthContext & AuthContext): RequestHandler;
declare module "express-serve-static-core" {
    interface Request {
        auth: {
            userId: string;
            role: string;
            sessionId: string;
            email: string;
        };
        institution: {
            id: string;
            name: string;
            status: string;
            apiKeyId: string;
        };
    }
}
export declare function generateTwoFactorSetup(): {
    secret: string;
    backupCodes: string[];
};
export declare function verifyTotp(opts: {
    secretBase32: string;
    code: string;
}): boolean;
export declare function verifyTwoFactorOrThrow(opts: {
    totpSecretBase32: string;
    backupCodesShaJson: string;
    twofaCode?: string;
    backupCode?: string;
}): {
    usedBackupCodeSha?: never;
} | {
    usedBackupCodeSha: string;
};
export {};
//# sourceMappingURL=index.d.ts.map