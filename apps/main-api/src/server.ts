import type { AddressInfo } from "node:net";
import http from "node:http";

import { createMainApiConfig } from "@verza/config";
import { createPgPool, migrateDatabase } from "@verza/db";
import { createHttpApp, errorHandler, notFoundHandler } from "@verza/http";
import { createLogger } from "@verza/observability";

import { registerMainApiRoutes } from "./v1/routes.js";

export async function createMainApiServer() {
  const config = createMainApiConfig(process.env);
  const logger = createLogger({ service: "main-api", level: config.LOG_LEVEL });
  const pool = createPgPool(config.DATABASE_URL);

  await migrateDatabase({
    db: "main",
    databaseUrl: config.DATABASE_URL,
    logger
  });

  const app = createHttpApp({ logger, corsAllowedOrigins: config.CORS_ALLOWED_ORIGINS });
  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  app.get("/health/db", async (_req, res, next) => {
    try {
      await pool.query("select 1 as ok");
      res.json({ status: "ok" });
    } catch (err) {
      next(err);
    }
  });
  app.get("/health/redis", (_req, res) => res.json({ status: "ok" }));

  app.get("/openapi.json", (_req, res) => res.json({ openapi: "3.0.0", paths: {} }));
  app.get("/swagger.json", (_req, res) => res.json({ swagger: "2.0", paths: {} }));
  app.get("/openapi.yaml", (_req, res) => res.type("text/yaml").send("openapi: 3.0.0\npaths: {}\n"));
  app.get("/swagger.yaml", (_req, res) => res.type("text/yaml").send("swagger: '2.0'\npaths: {}\n"));

  registerMainApiRoutes(app, { config, logger, pool });
  app.use(notFoundHandler);
  app.use(errorHandler());

  const server = http.createServer(app);

  return {
    start: async () => {
      await new Promise<void>((resolve) => {
        server.listen(config.PORT, config.HOST, resolve);
      });
      const addr = server.address() as AddressInfo;
      logger.info({ addr }, "main-api listening");
    },
    stop: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await pool.end();
    }
  };
}

