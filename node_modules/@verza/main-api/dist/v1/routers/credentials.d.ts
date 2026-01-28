import type { Router } from "express";
import { z } from "zod";
import type { MainApiContext } from "../routes.js";
export declare const storeSchema: z.ZodObject<{
    type: z.ZodString;
    issuer_name: z.ZodOptional<z.ZodString>;
    document_number: z.ZodOptional<z.ZodString>;
    issue_date: z.ZodOptional<z.ZodString>;
    expiry_date: z.ZodOptional<z.ZodString>;
    issuing_authority: z.ZodOptional<z.ZodString>;
    notes: z.ZodOptional<z.ZodString>;
    data: z.ZodUnknown;
}, "strip", z.ZodTypeAny, {
    type: string;
    data?: unknown;
    issuer_name?: string | undefined;
    document_number?: string | undefined;
    issue_date?: string | undefined;
    expiry_date?: string | undefined;
    issuing_authority?: string | undefined;
    notes?: string | undefined;
}, {
    type: string;
    data?: unknown;
    issuer_name?: string | undefined;
    document_number?: string | undefined;
    issue_date?: string | undefined;
    expiry_date?: string | undefined;
    issuing_authority?: string | undefined;
    notes?: string | undefined;
}>;
export declare const shareSchema: z.ZodObject<{
    credential_id: z.ZodString;
    recipient_did: z.ZodOptional<z.ZodString>;
    recipient: z.ZodOptional<z.ZodString>;
    permission: z.ZodOptional<z.ZodString>;
    purpose: z.ZodOptional<z.ZodString>;
    expires_at: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    credential_id: string;
    purpose?: string | undefined;
    expires_at?: string | undefined;
    recipient_did?: string | undefined;
    recipient?: string | undefined;
    permission?: string | undefined;
}, {
    credential_id: string;
    purpose?: string | undefined;
    expires_at?: string | undefined;
    recipient_did?: string | undefined;
    recipient?: string | undefined;
    permission?: string | undefined;
}>;
export declare const storeResponseSchema: z.ZodObject<{
    id: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
}, {
    id: string;
}>;
export declare const shareResponseSchema: z.ZodObject<{
    id: z.ZodString;
    token: z.ZodString;
}, "strip", z.ZodTypeAny, {
    token: string;
    id: string;
}, {
    token: string;
    id: string;
}>;
export declare function createCredentialsRouter(ctx: MainApiContext): Router;
export declare function createPublicSharesRouter(ctx: MainApiContext): Router;
//# sourceMappingURL=credentials.d.ts.map