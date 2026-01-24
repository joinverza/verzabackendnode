import type { Express } from "express";
import type { Pool } from "pg";
import type { Logger } from "@verza/observability";
import type { MainApiConfig } from "@verza/config";

import express from "express";

import { requireAdmin, requireInstitutionApiKey, requireUser } from "@verza/auth";

import { createAuthRouter } from "./routers/auth.js";
import { createConsentsRouter } from "./routers/consents.js";
import { createCredentialsRouter, createPublicSharesRouter } from "./routers/credentials.js";
import { createFiatPaymentsRouter } from "./routers/fiatPayments.js";
import { createIdentityVerificationsRouter } from "./routers/identityVerifications.js";
import { createInstitutionRouter } from "./routers/institution.js";
import { createMeRouter } from "./routers/me.js";
import { createNotificationsRouter } from "./routers/notifications.js";
import { createStubRouter } from "./routers/stubs.js";
import { createVerifiersRouter } from "./routers/verifiers.js";

export type MainApiContext = {
  config: MainApiConfig;
  logger: Logger;
  pool: Pool;
};

export function registerMainApiRoutes(app: Express, ctx: MainApiContext) {
  const api = express.Router();

  api.use("/auth", createAuthRouter(ctx));
  api.use("/me", requireUser(ctx), createMeRouter(ctx));
  api.use("/notifications", requireUser(ctx), createNotificationsRouter(ctx));
  api.use("/credentials", requireUser(ctx), createCredentialsRouter(ctx));
  api.use("/consents", requireUser(ctx), createConsentsRouter(ctx));

  api.all("/proofs/*", requireUser(ctx), createStubRouter());
  api.use("/proofs", requireUser(ctx), createStubRouter());
  api.use("/verifiers", requireUser(ctx), createVerifiersRouter(ctx));
  api.use("/escrow", requireUser(ctx), createStubRouter());
  api.use("/governance", requireUser(ctx), createStubRouter());
  api.use("/verifications", requireUser(ctx), createStubRouter());
  api.use("/identity/verifications", requireUser(ctx), createIdentityVerificationsRouter(ctx));
  api.use("/fiat/payments", createFiatPaymentsRouter(ctx));
  api.use("/search", requireUser(ctx), createStubRouter());
  api.use("/shares", createPublicSharesRouter(ctx));

  app.use("/api/v1", api);

  const admin = express.Router();
  admin.use("/bridge", requireAdmin(ctx), createStubRouter());
  admin.use("/institutions", requireAdmin(ctx), createStubRouter());
  app.use("/admin", admin);

  const institution = express.Router();
  institution.use(requireInstitutionApiKey(ctx));
  institution.use("/", createInstitutionRouter(ctx));
  app.use("/api/v1/institution", institution);
}
