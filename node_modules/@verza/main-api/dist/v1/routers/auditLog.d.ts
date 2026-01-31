import type { Pool } from "pg";
export type AuditAppendArgs = {
    tenantId: string;
    stream?: string;
    eventType: string;
    actorType: string;
    actorId: string;
    subjectType: string;
    subjectId: string;
    data?: unknown;
};
export declare function appendAuditEvent(pool: Pool, args: AuditAppendArgs): Promise<{
    id: `${string}-${string}-${string}-${string}-${string}`;
    seq: number;
    prevHash: string;
    eventHash: string;
    createdAt: Date;
    createdAtMs: number;
    stream: string;
}>;
export declare function verifyAuditChain(pool: Pool, args: {
    tenantId: string;
    stream?: string;
    fromSeq?: number;
    toSeq?: number;
}): Promise<{
    ok: false;
    badSeq: number;
    expected: string;
    actual: string;
    stream?: never;
    headHash?: never;
    nextSeq?: never;
    verifiedFromSeq?: never;
} | {
    ok: true;
    stream: string;
    headHash: string;
    nextSeq: number;
    verifiedFromSeq: number;
    badSeq?: never;
    expected?: never;
    actual?: never;
}>;
export declare function sanitizeAuditData(input: unknown): unknown;
//# sourceMappingURL=auditLog.d.ts.map