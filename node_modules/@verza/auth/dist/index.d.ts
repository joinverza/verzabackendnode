import type { RequestHandler } from "express";
import type { Pool } from "pg";
type JwtClaims = {
    iss: string;
    aud: string;
    sub: string;
    email: string;
    role: string;
    sid: string;
    tid?: string;
    iat: number;
    exp: number;
};
export declare function createAccessToken(opts: {
    secret: string;
    issuer: string;
    audience: string;
    ttlSeconds: number;
    claims: {
        sub: string;
        email: string;
        role: string;
        sid: string;
        tid?: string;
    };
}): string;
export declare function generateRefreshToken(): string;
export declare function verifyAccessToken(opts: {
    token: string;
    secret: string;
    issuer: string;
    audience: string;
}): JwtClaims | null;
export type AuthContext = {
    config: {
        JWT_SECRET: string;
        JWT_ISSUER: string;
        JWT_AUDIENCE: string;
    };
};
export declare const PERMISSIONS: {
    readonly ADMIN_BRIDGE_TRANSACTIONS_LIST: "admin.bridge.transactions.list";
    readonly ADMIN_BRIDGE_TRANSACTION_READ: "admin.bridge.transactions.read";
    readonly ADMIN_BRIDGE_TRANSACTION_STATUS_SET: "admin.bridge.transactions.status.set";
    readonly ADMIN_BRIDGE_TRANSACTION_RETRY: "admin.bridge.transactions.retry";
    readonly ADMIN_BRIDGE_CREDENTIAL_METADATA_READ: "admin.bridge.credential_metadata.read";
    readonly ADMIN_BRIDGE_CREDENTIAL_METADATA_UPSERT: "admin.bridge.credential_metadata.upsert";
    readonly ADMIN_INSTITUTIONS_LIST: "admin.institutions.list";
    readonly ADMIN_INSTITUTIONS_CREATE: "admin.institutions.create";
    readonly ADMIN_INSTITUTIONS_READ: "admin.institutions.read";
    readonly ADMIN_INSTITUTIONS_STATUS_SET: "admin.institutions.status.set";
    readonly ADMIN_INSTITUTIONS_API_KEYS_LIST: "admin.institutions.api_keys.list";
    readonly ADMIN_INSTITUTIONS_API_KEYS_CREATE: "admin.institutions.api_keys.create";
    readonly ADMIN_INSTITUTIONS_API_KEYS_REVOKE: "admin.institutions.api_keys.revoke";
    readonly ADMIN_INSTITUTIONS_MEMBERS_LIST: "admin.institutions.members.list";
    readonly ADMIN_INSTITUTIONS_MEMBERS_UPSERT: "admin.institutions.members.upsert";
    readonly ADMIN_INSTITUTIONS_MEMBERS_UPDATE: "admin.institutions.members.update";
    readonly ADMIN_COMPLIANCE_AUDIT_HEAD_READ: "admin.compliance.audit.head.read";
    readonly ADMIN_COMPLIANCE_AUDIT_EVENTS_LIST: "admin.compliance.audit.events.list";
    readonly ADMIN_COMPLIANCE_AUDIT_EXPORT: "admin.compliance.audit.export";
    readonly ADMIN_COMPLIANCE_AUDIT_VERIFY: "admin.compliance.audit.verify";
    readonly ADMIN_COMPLIANCE_REPORTS_SUMMARY_READ: "admin.compliance.reports.summary.read";
    readonly ADMIN_COMPLIANCE_EVIDENCE_CREATE: "admin.compliance.evidence.create";
    readonly ADMIN_COMPLIANCE_EVIDENCE_READ: "admin.compliance.evidence.read";
    readonly ADMIN_COMPLIANCE_PRIVACY_REQUESTS_LIST: "admin.compliance.privacy.requests.list";
    readonly ADMIN_COMPLIANCE_RETENTION_POLICY_SET: "admin.compliance.privacy.retention.set";
    readonly ADMIN_COMPLIANCE_RETENTION_RUN: "admin.compliance.privacy.retention.run";
};
export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];
export declare function requireUser(ctx: AuthContext): RequestHandler;
export declare function requireAdmin(ctx: AuthContext): RequestHandler;
export type RequirePermissionArgs = {
    action: Permission;
    tenantId?: (req: Parameters<RequestHandler>[0]) => string | null;
};
export declare function requirePermission(ctx: AuthContext, args: RequirePermissionArgs): RequestHandler;
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
            tenantId: string;
        };
        institution: {
            id: string;
            name: string;
            status: string;
            apiKeyId: string;
            tenantId: string;
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