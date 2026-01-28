import type { Router } from "express";
import { z } from "zod";
import type { MainApiContext } from "../routes.js";
export declare const signupSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    name: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    name: string;
}, {
    email: string;
    password: string;
    name: string;
}>;
export declare const loginSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    twofa_code: z.ZodOptional<z.ZodString>;
    backup_code: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    twofa_code?: string | undefined;
    backup_code?: string | undefined;
}, {
    email: string;
    password: string;
    twofa_code?: string | undefined;
    backup_code?: string | undefined;
}>;
export declare const refreshSchema: z.ZodObject<{
    refresh_token: z.ZodString;
}, "strip", z.ZodTypeAny, {
    refresh_token: string;
}, {
    refresh_token: string;
}>;
export declare const forgotPasswordSchema: z.ZodEffects<z.ZodObject<{
    email: z.ZodOptional<z.ZodString>;
    phone: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    email?: string | undefined;
    phone?: string | undefined;
}, {
    email?: string | undefined;
    phone?: string | undefined;
}>, {
    email?: string | undefined;
    phone?: string | undefined;
}, {
    email?: string | undefined;
    phone?: string | undefined;
}>;
export declare const resetPasswordSchema: z.ZodObject<{
    token: z.ZodString;
    new_password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    token: string;
    new_password: string;
}, {
    token: string;
    new_password: string;
}>;
export declare const authTokensResponseSchema: z.ZodObject<{
    user: z.ZodObject<{
        id: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        id: string;
    }, {
        id: string;
    }>;
    access_token: z.ZodString;
    refresh_token: z.ZodString;
}, "strip", z.ZodTypeAny, {
    refresh_token: string;
    user: {
        id: string;
    };
    access_token: string;
}, {
    refresh_token: string;
    user: {
        id: string;
    };
    access_token: string;
}>;
export declare const okResponseSchema: z.ZodObject<{
    status: z.ZodLiteral<"ok">;
}, "strip", z.ZodTypeAny, {
    status: "ok";
}, {
    status: "ok";
}>;
export declare function createAuthRouter(ctx: MainApiContext): Router;
//# sourceMappingURL=auth.d.ts.map