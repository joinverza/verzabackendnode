import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import express from "express";
import { z } from "zod";
import { sha256Hex } from "@verza/crypto";
import { badRequest, unauthorized } from "@verza/http";
const patchMeSchema = z.object({
    name: z.string().min(1).optional(),
    phone: z.string().optional(),
    bio: z.string().optional(),
    avatar_url: z.string().url().optional(),
    did: z.string().optional()
});
const changePasswordSchema = z.object({
    current_password: z.string().min(8),
    new_password: z.string().min(8)
});
const verify2faSchema = z.object({
    twofa_code: z.string().min(6)
});
const disable2faSchema = z.object({
    password: z.string().min(8),
    twofa_code: z.string().optional(),
    backup_code: z.string().optional()
});
const revokeSessionSchema = z.object({
    session_id: z.string().uuid()
});
export function createMeRouter(ctx) {
    const router = express.Router();
    router.get("/", async (req, res, next) => {
        try {
            const userId = req.auth.userId;
            const result = await ctx.pool.query("select id,email,name,phone,bio,avatar_url,did,role,status,created_at,updated_at from users where id=$1 limit 1", [userId]);
            const u = result.rows[0];
            if (!u)
                throw unauthorized("missing_user", "User not found");
            res.json({
                id: u.id,
                email: u.email,
                name: u.name,
                phone: u.phone,
                bio: u.bio,
                avatar_url: u.avatar_url,
                did: u.did,
                role: u.role,
                status: u.status,
                created_at: u.created_at,
                updated_at: u.updated_at
            });
        }
        catch (err) {
            next(err);
        }
    });
    router.patch("/", async (req, res, next) => {
        try {
            const userId = req.auth.userId;
            const body = patchMeSchema.parse(req.body);
            const ts = new Date();
            await ctx.pool.query("update users set name=coalesce($1,name), phone=coalesce($2,phone), bio=coalesce($3,bio), avatar_url=coalesce($4,avatar_url), did=coalesce($5,did), updated_at=$6 where id=$7", [body.name ?? null, body.phone ?? null, body.bio ?? null, body.avatar_url ?? null, body.did ?? null, ts, userId]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/change-password", async (req, res, next) => {
        try {
            const userId = req.auth.userId;
            const body = changePasswordSchema.parse(req.body);
            const result = await ctx.pool.query("select password_hash from users where id=$1", [userId]);
            const row = result.rows[0];
            if (!row)
                throw unauthorized("missing_user", "User not found");
            const ok = await bcrypt.compare(body.current_password, row.password_hash);
            if (!ok)
                throw unauthorized("invalid_password", "Invalid password");
            const newHash = await bcrypt.hash(body.new_password, 10);
            const ts = new Date();
            await ctx.pool.query("update users set password_hash=$1, updated_at=$2 where id=$3", [newHash, ts, userId]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.get("/sessions", async (req, res, next) => {
        try {
            const userId = req.auth.userId;
            const result = await ctx.pool.query("select id,user_id,created_at,expires_at,revoked_at,user_agent,ip from sessions where user_id=$1 order by created_at desc", [userId]);
            res.json(result.rows);
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/sessions/revoke", async (req, res, next) => {
        try {
            const userId = req.auth.userId;
            const body = revokeSessionSchema.parse(req.body);
            await ctx.pool.query("update sessions set revoked_at=$1 where id=$2 and user_id=$3", [new Date(), body.session_id, userId]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/2fa/setup", async (req, res, next) => {
        try {
            const { generateTwoFactorSetup } = await import("@verza/auth");
            const setup = generateTwoFactorSetup();
            await ctx.pool.query("update users set twofa_secret=$1, twofa_enabled=false, backup_codes_sha=$2, updated_at=$3 where id=$4", [
                setup.secret,
                "[]",
                new Date(),
                req.auth.userId
            ]);
            res.json({ secret: setup.secret, backup_codes: setup.backupCodes });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/2fa/verify", async (req, res, next) => {
        try {
            const body = verify2faSchema.parse(req.body);
            const userId = req.auth.userId;
            const result = await ctx.pool.query("select twofa_secret from users where id=$1", [userId]);
            const row = result.rows[0];
            if (!row || !row.twofa_secret)
                throw badRequest("twofa_not_setup", "2FA not set up");
            const { verifyTotp } = await import("@verza/auth");
            const ok = verifyTotp({ secretBase32: row.twofa_secret, code: body.twofa_code });
            if (!ok)
                throw badRequest("invalid_twofa_code", "Invalid 2FA code");
            const backup = generateBackupCodesSha();
            await ctx.pool.query("update users set twofa_enabled=true, backup_codes_sha=$1, updated_at=$2 where id=$3", [
                JSON.stringify(backup.codesSha),
                new Date(),
                userId
            ]);
            res.json({ status: "ok", backup_codes: backup.rawCodes });
        }
        catch (err) {
            next(err);
        }
    });
    router.post("/2fa/disable", async (req, res, next) => {
        try {
            const body = disable2faSchema.parse(req.body);
            const userId = req.auth.userId;
            const result = await ctx.pool.query("select password_hash,twofa_secret,backup_codes_sha from users where id=$1", [userId]);
            const row = result.rows[0];
            if (!row)
                throw unauthorized("missing_user", "User not found");
            const okPass = await bcrypt.compare(body.password, row.password_hash);
            if (!okPass)
                throw unauthorized("invalid_password", "Invalid password");
            const { verifyTwoFactorOrThrow } = await import("@verza/auth");
            const twofaArgs = {
                totpSecretBase32: row.twofa_secret,
                backupCodesShaJson: row.backup_codes_sha
            };
            if (body.twofa_code)
                twofaArgs.twofaCode = body.twofa_code;
            if (body.backup_code)
                twofaArgs.backupCode = body.backup_code;
            verifyTwoFactorOrThrow(twofaArgs);
            await ctx.pool.query("update users set twofa_enabled=false, twofa_secret='', backup_codes_sha='', updated_at=$1 where id=$2", [
                new Date(),
                userId
            ]);
            res.json({ status: "ok" });
        }
        catch (err) {
            next(err);
        }
    });
    return router;
}
function generateBackupCodesSha() {
    const rawCodes = [];
    const codesSha = [];
    for (let i = 0; i < 10; i++) {
        const code = crypto.randomUUID().replaceAll("-", "").slice(0, 10);
        rawCodes.push(code);
        codesSha.push(sha256Hex(code));
    }
    return { rawCodes, codesSha };
}
//# sourceMappingURL=me.js.map