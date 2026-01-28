import type { Router } from "express";
import { z } from "zod";
import type { MainApiContext } from "../routes.js";
export declare const initiateSchema: z.ZodObject<{
    amount_minor: z.ZodNumber;
    currency: z.ZodString;
}, "strip", z.ZodTypeAny, {
    amount_minor: number;
    currency: string;
}, {
    amount_minor: number;
    currency: string;
}>;
export declare const idSchema: z.ZodObject<{
    id: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
}, {
    id: string;
}>;
export declare const initiateResponseSchema: z.ZodObject<{
    id: z.ZodString;
    status: z.ZodLiteral<"initiated">;
    stripe_payment_intent_id: z.ZodNullable<z.ZodString>;
    stripe_status: z.ZodNullable<z.ZodString>;
    stripe_client_secret: z.ZodNullable<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    status: "initiated";
    id: string;
    stripe_payment_intent_id: string | null;
    stripe_status: string | null;
    stripe_client_secret: string | null;
}, {
    status: "initiated";
    id: string;
    stripe_payment_intent_id: string | null;
    stripe_status: string | null;
    stripe_client_secret: string | null;
}>;
export declare const paymentStatusResponseSchema: z.ZodObject<{
    id: z.ZodString;
    status: z.ZodString;
    stripe_status: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    amount_minor: z.ZodUnion<[z.ZodNumber, z.ZodString]>;
    currency: z.ZodString;
    created_at: z.ZodAny;
    updated_at: z.ZodAny;
}, "strip", z.ZodTypeAny, {
    status: string;
    id: string;
    amount_minor: string | number;
    currency: string;
    created_at?: any;
    stripe_status?: string | null | undefined;
    updated_at?: any;
}, {
    status: string;
    id: string;
    amount_minor: string | number;
    currency: string;
    created_at?: any;
    stripe_status?: string | null | undefined;
    updated_at?: any;
}>;
export declare const receiptQuerySchema: z.ZodObject<{
    format: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    format?: string | undefined;
}, {
    format?: string | undefined;
}>;
export declare const receiptResponseSchema: z.ZodObject<{
    receipt: z.ZodObject<{
        payment_id: z.ZodString;
        amount_minor: z.ZodUnion<[z.ZodNumber, z.ZodString]>;
        currency: z.ZodString;
        issued_at: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        amount_minor: string | number;
        currency: string;
        payment_id: string;
        issued_at: string;
    }, {
        amount_minor: string | number;
        currency: string;
        payment_id: string;
        issued_at: string;
    }>;
    sig_kid: z.ZodString;
    sig_b64: z.ZodString;
}, "strip", z.ZodTypeAny, {
    sig_kid: string;
    sig_b64: string;
    receipt: {
        amount_minor: string | number;
        currency: string;
        payment_id: string;
        issued_at: string;
    };
}, {
    sig_kid: string;
    sig_b64: string;
    receipt: {
        amount_minor: string | number;
        currency: string;
        payment_id: string;
        issued_at: string;
    };
}>;
export declare const reconcileResponseSchema: z.ZodObject<{
    status: z.ZodLiteral<"ok">;
    checked: z.ZodNumber;
    updated: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    status: "ok";
    checked: number;
    updated: number;
}, {
    status: "ok";
    checked: number;
    updated: number;
}>;
export declare const notConfiguredResponseSchema: z.ZodObject<{
    status: z.ZodLiteral<"not_configured">;
}, "strip", z.ZodTypeAny, {
    status: "not_configured";
}, {
    status: "not_configured";
}>;
export declare function createFiatPaymentsRouter(ctx: MainApiContext): Router;
//# sourceMappingURL=fiatPayments.d.ts.map