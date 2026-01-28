import type { Router } from "express";

import crypto from "node:crypto";

import bcrypt from "bcryptjs";
import express from "express";
import nodemailer from "nodemailer";
import { z } from "zod";

import { createAccessToken, generateRefreshToken, requireUser } from "@verza/auth";
import { sha256Hex } from "@verza/crypto";
import { badRequest, unauthorized } from "@verza/http";

import type { MainApiContext } from "../routes.js";

export const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(1)
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  twofa_code: z.string().optional(),
  backup_code: z.string().optional()
});

export const refreshSchema = z.object({
  refresh_token: z.string().min(10)
});

export const forgotPasswordSchema = z
  .object({
    email: z.string().email().optional(),
    phone: z.string().min(6).optional()
  })
  .refine((v) => Boolean(v.email) || Boolean(v.phone), { message: "email or phone required" });

export const resetPasswordSchema = z.object({
  token: z.string().min(10),
  new_password: z.string().min(8)
});

export const authTokensResponseSchema = z.object({
  user: z.object({ id: z.string().uuid() }),
  access_token: z.string().min(1),
  refresh_token: z.string().min(1)
});

export const okResponseSchema = z.object({
  status: z.literal("ok")
});

function now() {
  return new Date();
}

function randomUuid() {
  return crypto.randomUUID();
}

export function createAuthRouter(ctx: MainApiContext): Router {
  const router = express.Router();

  router.post("/signup", async (req, res, next) => {
    try {
      const body = signupSchema.parse(req.body);
      const existing = await ctx.pool.query<{ id: string }>("select id from users where email=$1 limit 1", [
        body.email.toLowerCase()
      ]);
      if (existing.rowCount && existing.rows[0]) {
        throw badRequest("email_taken", "Email already exists");
      }
      const passwordHash = await bcrypt.hash(body.password, 10);
      const userId = randomUuid();
      const ts = now();

      await ctx.pool.query(
        "insert into users (id, email, name, password_hash, created_at, updated_at) values ($1,$2,$3,$4,$5,$6)",
        [userId, body.email.toLowerCase(), body.name, passwordHash, ts, ts]
      );

      const refreshToken = generateRefreshToken();
      const refreshHash = sha256Hex(refreshToken);
      const sessionId = randomUuid();
      const expiresAt = new Date(Date.now() + ctx.config.REFRESH_TOKEN_TTL_SECONDS * 1000);

      await ctx.pool.query(
        "insert into sessions (id, user_id, refresh_token_hash, created_at, expires_at, user_agent, ip) values ($1,$2,$3,$4,$5,$6,$7)",
        [sessionId, userId, refreshHash, ts, expiresAt, String(req.headers["user-agent"] ?? ""), req.ip]
      );

      const accessToken = createAccessToken({
        secret: ctx.config.JWT_SECRET,
        issuer: ctx.config.JWT_ISSUER,
        ttlSeconds: ctx.config.ACCESS_TOKEN_TTL_SECONDS,
        claims: { sub: userId, email: body.email.toLowerCase(), role: "user", sid: sessionId }
      });

      res.json({ user: { id: userId }, access_token: accessToken, refresh_token: refreshToken });
    } catch (err) {
      next(err);
    }
  });

  router.post("/login", async (req, res, next) => {
    try {
      const body = loginSchema.parse(req.body);
      const result = await ctx.pool.query<{
        id: string;
        email: string;
        password_hash: string;
        role: string;
        twofa_enabled: boolean;
        twofa_secret: string;
        backup_codes_sha: string;
      }>(
        "select id,email,password_hash,role,twofa_enabled,twofa_secret,backup_codes_sha from users where email=$1 limit 1",
        [body.email.toLowerCase()]
      );
      const user = result.rows[0];
      if (!user) throw unauthorized("invalid_credentials", "Invalid credentials");
      const ok = await bcrypt.compare(body.password, user.password_hash);
      if (!ok) throw unauthorized("invalid_credentials", "Invalid credentials");

      if (user.twofa_enabled) {
        const { verifyTwoFactorOrThrow } = await import("@verza/auth");
        const twofaArgs: { totpSecretBase32: string; backupCodesShaJson: string; twofaCode?: string; backupCode?: string } = {
          totpSecretBase32: user.twofa_secret,
          backupCodesShaJson: user.backup_codes_sha
        };
        if (body.twofa_code) twofaArgs.twofaCode = body.twofa_code;
        if (body.backup_code) twofaArgs.backupCode = body.backup_code;
        const twofa = verifyTwoFactorOrThrow(twofaArgs);
        if (twofa.usedBackupCodeSha) {
          const codes = parseJsonArray(user.backup_codes_sha).filter((h) => h !== twofa.usedBackupCodeSha);
          await ctx.pool.query("update users set backup_codes_sha=$1, updated_at=$2 where id=$3", [
            JSON.stringify(codes),
            now(),
            user.id
          ]);
        }
      }

      const refreshToken = generateRefreshToken();
      const refreshHash = sha256Hex(refreshToken);
      const sessionId = randomUuid();
      const ts = now();
      const expiresAt = new Date(Date.now() + ctx.config.REFRESH_TOKEN_TTL_SECONDS * 1000);

      await ctx.pool.query(
        "insert into sessions (id, user_id, refresh_token_hash, created_at, expires_at, user_agent, ip) values ($1,$2,$3,$4,$5,$6,$7)",
        [sessionId, user.id, refreshHash, ts, expiresAt, String(req.headers["user-agent"] ?? ""), req.ip]
      );

      await ctx.pool.query("update users set last_login_at=$1, updated_at=$1 where id=$2", [ts, user.id]);

      const accessToken = createAccessToken({
        secret: ctx.config.JWT_SECRET,
        issuer: ctx.config.JWT_ISSUER,
        ttlSeconds: ctx.config.ACCESS_TOKEN_TTL_SECONDS,
        claims: { sub: user.id, email: user.email, role: user.role, sid: sessionId }
      });

      res.json({ user: { id: user.id }, access_token: accessToken, refresh_token: refreshToken });
    } catch (err) {
      next(err);
    }
  });

  router.post("/refresh", async (req, res, next) => {
    try {
      const body = refreshSchema.parse(req.body);
      const refreshHash = sha256Hex(body.refresh_token);
      const result = await ctx.pool.query<{
        id: string;
        user_id: string;
        expires_at: Date;
        revoked_at: Date | null;
        role: string;
        email: string;
      }>(
        "select s.id, s.user_id, s.expires_at, s.revoked_at, u.role, u.email from sessions s join users u on u.id = s.user_id where s.refresh_token_hash=$1 limit 1",
        [refreshHash]
      );
      const row = result.rows[0];
      if (!row) throw unauthorized("invalid_refresh", "Invalid refresh token");
      if (row.revoked_at) throw unauthorized("revoked_session", "Session revoked");
      if (row.expires_at.getTime() <= Date.now()) throw unauthorized("expired_session", "Session expired");

      const newRefreshToken = generateRefreshToken();
      const newHash = sha256Hex(newRefreshToken);
      const newExpiresAt = new Date(Date.now() + ctx.config.REFRESH_TOKEN_TTL_SECONDS * 1000);
      await ctx.pool.query("update sessions set refresh_token_hash=$1, expires_at=$2 where id=$3", [
        newHash,
        newExpiresAt,
        row.id
      ]);

      const accessToken = createAccessToken({
        secret: ctx.config.JWT_SECRET,
        issuer: ctx.config.JWT_ISSUER,
        ttlSeconds: ctx.config.ACCESS_TOKEN_TTL_SECONDS,
        claims: { sub: row.user_id, email: row.email, role: row.role, sid: row.id }
      });

      res.json({ user: { id: row.user_id }, access_token: accessToken, refresh_token: newRefreshToken });
    } catch (err) {
      next(err);
    }
  });

  router.post("/forgot-password", async (req, res, next) => {
    try {
      const body = forgotPasswordSchema.parse(req.body);
      const email = body.email ? body.email.toLowerCase() : null;
      const phone = body.phone ? body.phone.trim() : null;
      const result = await ctx.pool.query<{ id: string; email: string; phone: string }>(
        email
          ? "select id,email,phone from users where email=$1 limit 1"
          : "select id,email,phone from users where phone=$1 limit 1",
        [email ?? phone ?? ""]
      );
      const user = result.rows[0];
      if (user) {
        const token = generateRefreshToken();
        const tokenHash = sha256Hex(token);
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
        await ctx.pool.query(
          "insert into password_reset_tokens (token_hash, user_id, expires_at, created_at) values ($1,$2,$3,$4) on conflict (token_hash) do nothing",
          [tokenHash, user.id, expiresAt, now()]
        );
        const resetUrl = buildPasswordResetUrl({ baseUrl: ctx.config.PASSWORD_RESET_BASE_URL, token });
        await deliverPasswordReset({
          ctx,
          toEmail: user.email || null,
          toPhone: user.phone || null,
          resetUrl
        });
      }
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.post("/reset-password", async (req, res, next) => {
    try {
      const body = resetPasswordSchema.parse(req.body);
      const tokenHash = sha256Hex(body.token);
      const result = await ctx.pool.query<{ user_id: string; expires_at: Date; used_at: Date | null }>(
        "select user_id, expires_at, used_at from password_reset_tokens where token_hash=$1 limit 1",
        [tokenHash]
      );
      const row = result.rows[0];
      if (!row) throw badRequest("invalid_token", "Invalid token");
      if (row.used_at) throw badRequest("used_token", "Token already used");
      if (row.expires_at.getTime() <= Date.now()) throw badRequest("expired_token", "Token expired");
      const newHash = await bcrypt.hash(body.new_password, 10);
      const ts = now();
      await ctx.pool.query("update users set password_hash=$1, updated_at=$2 where id=$3", [newHash, ts, row.user_id]);
      await ctx.pool.query("update sessions set revoked_at=$1 where user_id=$2 and revoked_at is null", [ts, row.user_id]);
      await ctx.pool.query("update password_reset_tokens set used_at=$1 where token_hash=$2", [ts, tokenHash]);
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  router.post("/logout", requireUser(ctx), async (req, res, next) => {
    try {
      await ctx.pool.query("update sessions set revoked_at=$1 where id=$2 and user_id=$3", [
        new Date(),
        req.auth.sessionId,
        req.auth.userId
      ]);
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

function buildPasswordResetUrl(opts: { baseUrl: string | undefined; token: string }) {
  const base = (opts.baseUrl ?? "").trim();
  if (!base) return null;
  const url = new URL(base);
  url.searchParams.set("token", opts.token);
  return url.toString();
}

function parseJsonArray(s: string) {
  try {
    const parsed: unknown = JSON.parse(s || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((x): x is string => typeof x === "string");
  } catch {
    return [];
  }
}

async function deliverPasswordReset(opts: {
  ctx: MainApiContext;
  toEmail: string | null;
  toPhone: string | null;
  resetUrl: string | null;
}) {
  if (!opts.resetUrl) return;

  const emailOk = await trySendPasswordResetEmail({
    ctx: opts.ctx,
    toEmail: opts.toEmail,
    resetUrl: opts.resetUrl
  });

  if (emailOk) return;

  await trySendPasswordResetSms({
    ctx: opts.ctx,
    toPhone: opts.toPhone,
    resetUrl: opts.resetUrl
  });
}

async function trySendPasswordResetEmail(opts: { ctx: MainApiContext; toEmail: string | null; resetUrl: string }) {
  const to = (opts.toEmail ?? "").trim();
  if (!to) return false;
  const host = String(opts.ctx.config.SMTP_HOST ?? "").trim();
  const port = typeof opts.ctx.config.SMTP_PORT === "number" ? opts.ctx.config.SMTP_PORT : null;
  const from = String(opts.ctx.config.SMTP_FROM ?? "").trim();
  if (!host || !port || !from) return false;

  const transport = nodemailer.createTransport({
    host,
    port,
    secure: Boolean(opts.ctx.config.SMTP_SECURE),
    auth:
      opts.ctx.config.SMTP_USER && opts.ctx.config.SMTP_PASS
        ? { user: opts.ctx.config.SMTP_USER, pass: opts.ctx.config.SMTP_PASS }
        : undefined
  });

  try {
    await transport.sendMail({
      from,
      to,
      subject: "Reset your Verza password",
      text: `Use this link to reset your password:\n\n${opts.resetUrl}\n\nIf you did not request this, you can ignore this email.`,
      html: `<p>Use this link to reset your password:</p><p><a href="${opts.resetUrl}">${opts.resetUrl}</a></p><p>If you did not request this, you can ignore this email.</p>`
    });
    return true;
  } catch (err) {
    opts.ctx.logger.error({ err }, "password reset email delivery failed");
    return false;
  }
}

async function trySendPasswordResetSms(opts: { ctx: MainApiContext; toPhone: string | null; resetUrl: string }) {
  const to = (opts.toPhone ?? "").trim();
  if (!to) return false;
  const sid = String(opts.ctx.config.TWILIO_ACCOUNT_SID ?? "").trim();
  const token = String(opts.ctx.config.TWILIO_AUTH_TOKEN ?? "").trim();
  const from = String(opts.ctx.config.TWILIO_FROM_NUMBER ?? "").trim();
  if (!sid || !token || !from) return false;

  const auth = Buffer.from(`${sid}:${token}`, "utf8").toString("base64");
  const body = new URLSearchParams();
  body.set("To", to);
  body.set("From", from);
  body.set("Body", `Reset your Verza password: ${opts.resetUrl}`);

  try {
    const resp = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(sid)}/Messages.json`, {
      method: "POST",
      headers: {
        authorization: `Basic ${auth}`,
        "content-type": "application/x-www-form-urlencoded"
      },
      body
    });
    if (!resp.ok) {
      const text = await resp.text();
      opts.ctx.logger.error({ status: resp.status, body: text }, "password reset sms delivery failed");
      return false;
    }
    return true;
  } catch (err) {
    opts.ctx.logger.error({ err }, "password reset sms delivery failed");
    return false;
  }
}
