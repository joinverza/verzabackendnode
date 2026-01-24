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
import { createEscrowRouter } from "./routers/escrow.js";
import { createGovernanceRouter } from "./routers/governance.js";
import { createProofsRouter } from "./routers/proofs.js";
import { createSearchRouter } from "./routers/search.js";
import { createAdminBridgeRouter } from "./routers/adminBridge.js";
import { createAdminInstitutionsRouter } from "./routers/adminInstitutions.js";
import { createVerifiersRouter } from "./routers/verifiers.js";
import { createVerificationsRouter } from "./routers/verifications.js";

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

  api.use("/proofs", requireUser(ctx), createProofsRouter(ctx));
  api.use("/verifiers", requireUser(ctx), createVerifiersRouter(ctx));
  api.use("/escrow", requireUser(ctx), createEscrowRouter(ctx));
  api.use("/governance", requireUser(ctx), createGovernanceRouter(ctx));
  api.use("/verifications", requireUser(ctx), createVerificationsRouter(ctx));
  api.use("/identity/verifications", requireUser(ctx), createIdentityVerificationsRouter(ctx));
  api.use("/fiat/payments", createFiatPaymentsRouter(ctx));
  api.use("/search", requireUser(ctx), createSearchRouter(ctx));
  api.use("/shares", createPublicSharesRouter(ctx));

  app.use("/api/v1", api);

  const admin = express.Router();
  admin.use("/bridge", requireAdmin(ctx), createAdminBridgeRouter(ctx));
  admin.use("/institutions", requireAdmin(ctx), createAdminInstitutionsRouter(ctx));
  app.use("/admin", admin);

  const institution = express.Router();
  institution.use(requireInstitutionApiKey(ctx));
  institution.use("/", createInstitutionRouter(ctx));
  app.use("/api/v1/institution", institution);
}
