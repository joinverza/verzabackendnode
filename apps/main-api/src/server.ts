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
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("x-frame-options", "DENY");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader("permissions-policy", "geolocation=(), microphone=(), camera=()");
    const xfProto = (req.header("x-forwarded-proto") ?? "").toLowerCase();
    if (req.secure || xfProto === "https") {
      res.setHeader("strict-transport-security", "max-age=15552000; includeSubDomains");
    }
    next();
  });
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

  const openapi = buildOpenApiSpec({
    title: "Verza Main API",
    version: "1.0.0",
    serverUrl: `http://localhost:${config.PORT}`
  });

  app.get("/openapi.json", (_req, res) => {
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-robots-tag", "noindex, nofollow");
    res.json(openapi);
  });
  app.get("/swagger.json", (_req, res) => {
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-robots-tag", "noindex, nofollow");
    res.json(openapi);
  });
  app.get("/swaggerdocs", (_req, res) => res.redirect(302, "/docs"));
  app.get("/docs", (_req, res) => {
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-robots-tag", "noindex, nofollow");
    res.type("text/html").send(getSwaggerUiHtml({ specUrl: "/openapi.json", title: "Verza API Docs" }));
  });

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

function buildOpenApiSpec(input: { title: string; version: string; serverUrl: string }) {
  return {
    openapi: "3.0.3",
    info: {
      title: input.title,
      version: input.version
    },
    servers: [{ url: input.serverUrl }],
    tags: [
      { name: "Health" },
      { name: "Auth" },
      { name: "Me" },
      { name: "Credentials" },
      { name: "Consents" },
      { name: "Identity Verifications" },
      { name: "Verifiers" }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT"
        },
        institutionApiKey: {
          type: "apiKey",
          in: "header",
          name: "x-institution-api-key"
        }
      },
      schemas: {
        ErrorResponse: {
          type: "object",
          properties: {
            error: { type: "string" },
            message: { type: "string" }
          }
        },
        Consent: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            user_id: { type: "string", format: "uuid" },
            institution_id: { type: "string", format: "uuid" },
            credential_id: { type: "string", format: "uuid" },
            allowed_fields: { type: "array", items: { type: "string" } },
            purpose: { type: "string" },
            status: { type: "string" },
            expires_at: { type: "string", format: "date-time", nullable: true },
            revoked_at: { type: "string", format: "date-time", nullable: true },
            created_at: { type: "string", format: "date-time" }
          }
        },
        IdentityVerification: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            user_id: { type: "string", format: "uuid" },
            credential_id: { type: "string", format: "uuid", nullable: true },
            status: { type: "string" },
            provider: { type: "string" },
            document_type: { type: "string" },
            confidence_threshold: { type: "number" },
            scores: { type: "object", additionalProperties: { type: "number" } },
            reasons: { type: "array", items: { type: "string" } },
            signals: { type: "object", additionalProperties: true },
            locale: { type: "string" },
            server_received_at: { type: "string", format: "date-time" },
            completed_at: { type: "string", format: "date-time", nullable: true }
          }
        },
        Verifier: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            owner_user_id: { type: "string", format: "uuid" },
            name: { type: "string" },
            did: { type: "string" },
            status: { type: "string" },
            website_url: { type: "string" },
            description: { type: "string" },
            metadata: { type: "object", additionalProperties: true },
            created_at: { type: "string", format: "date-time" },
            updated_at: { type: "string", format: "date-time" }
          }
        }
      }
    },
    paths: {
      "/health": {
        get: {
          tags: ["Health"],
          summary: "Health check",
          responses: {
            200: {
              description: "OK",
              content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } }
            }
          }
        }
      },
      "/api/v1/consents": {
        get: {
          tags: ["Consents"],
          summary: "List user consents",
          security: [{ bearerAuth: [] }],
          responses: {
            200: {
              description: "Consents",
              content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Consent" } } } }
            }
          }
        },
        post: {
          tags: ["Consents"],
          summary: "Create consent",
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["institution_id", "credential_id"],
                  properties: {
                    institution_id: { type: "string", format: "uuid" },
                    credential_id: { type: "string", format: "uuid" },
                    allowed_fields: { type: "array", items: { type: "string" } },
                    purpose: { type: "string" },
                    expires_at: { type: "string", format: "date-time" }
                  }
                }
              }
            }
          },
          responses: {
            201: {
              description: "Created",
              content: { "application/json": { schema: { type: "object", properties: { id: { type: "string", format: "uuid" } } } } }
            },
            400: { description: "Bad Request", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
          }
        }
      },
      "/api/v1/consents/{consentId}": {
        get: {
          tags: ["Consents"],
          summary: "Get consent",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "consentId", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: {
            200: { description: "Consent", content: { "application/json": { schema: { $ref: "#/components/schemas/Consent" } } } },
            404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
          }
        }
      },
      "/api/v1/consents/{consentId}/revoke": {
        post: {
          tags: ["Consents"],
          summary: "Revoke consent",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "consentId", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: {
            200: { description: "OK", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } } },
            404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
          }
        }
      },
      "/api/v1/consents/{consentId}/audit": {
        get: {
          tags: ["Consents"],
          summary: "List consent audit events",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "consentId", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: {
            200: {
              description: "Events",
              content: {
                "application/json": {
                  schema: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        id: { type: "string", format: "uuid" },
                        event_type: { type: "string" },
                        actor_type: { type: "string" },
                        actor_id: { type: "string" },
                        data: { type: "object", additionalProperties: true },
                        created_at: { type: "string", format: "date-time" }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/v1/identity/verifications/request": {
        post: {
          tags: ["Identity Verifications"],
          summary: "Request identity verification",
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    credential_id: { type: "string", format: "uuid" },
                    provider: { type: "string" },
                    document_type: { type: "string" },
                    confidence_threshold: { type: "number" },
                    locale: { type: "string" }
                  }
                }
              }
            }
          },
          responses: {
            201: {
              description: "Created",
              content: {
                "application/json": {
                  schema: { type: "object", properties: { id: { type: "string", format: "uuid" }, status: { type: "string" } } }
                }
              }
            }
          }
        }
      },
      "/api/v1/identity/verifications": {
        get: {
          tags: ["Identity Verifications"],
          summary: "List identity verifications",
          security: [{ bearerAuth: [] }],
          responses: {
            200: {
              description: "Verifications",
              content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/IdentityVerification" } } } }
            }
          }
        }
      },
      "/api/v1/identity/verifications/{id}": {
        get: {
          tags: ["Identity Verifications"],
          summary: "Get identity verification",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: {
            200: { description: "Verification", content: { "application/json": { schema: { $ref: "#/components/schemas/IdentityVerification" } } } },
            404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
          }
        }
      },
      "/api/v1/identity/verifications/{id}/status": {
        post: {
          tags: ["Identity Verifications"],
          summary: "Get identity verification status",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: {
            200: { description: "Status", content: { "application/json": { schema: { type: "object", properties: { id: { type: "string" }, status: { type: "string" } } } } } },
            404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
          }
        }
      },
      "/api/v1/identity/verifications/{id}/complete": {
        post: {
          tags: ["Identity Verifications"],
          summary: "Complete identity verification",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: { type: "string", enum: ["approved", "rejected", "completed"] },
                    scores: { type: "object", additionalProperties: { type: "number" } },
                    reasons: { type: "array", items: { type: "string" } },
                    signals: { type: "object", additionalProperties: true }
                  }
                }
              }
            }
          },
          responses: { 200: { description: "OK", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } } } }
        }
      },
      "/api/v1/identity/verifications/{id}/cancel": {
        post: {
          tags: ["Identity Verifications"],
          summary: "Cancel identity verification",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: {
            200: { description: "OK", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } } },
            404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
          }
        }
      },
      "/api/v1/identity/verifications/{id}/audit": {
        get: {
          tags: ["Identity Verifications"],
          summary: "List identity verification audit events",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: {
            200: {
              description: "Events",
              content: {
                "application/json": {
                  schema: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        id: { type: "string", format: "uuid" },
                        verification_id: { type: "string", format: "uuid" },
                        user_id: { type: "string", format: "uuid" },
                        event_type: { type: "string" },
                        data: { type: "object", additionalProperties: true },
                        created_at: { type: "string", format: "date-time" }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/v1/verifiers": {
        post: {
          tags: ["Verifiers"],
          summary: "Create verifier (owned by current user)",
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["name"],
                  properties: {
                    name: { type: "string" },
                    did: { type: "string" },
                    website_url: { type: "string" },
                    description: { type: "string" },
                    metadata: { type: "object", additionalProperties: true }
                  }
                }
              }
            }
          },
          responses: {
            201: { description: "Created", content: { "application/json": { schema: { type: "object", properties: { id: { type: "string", format: "uuid" } } } } } }
          }
        },
        get: {
          tags: ["Verifiers"],
          summary: "List verifiers (owned, or search active with q)",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "q", in: "query", required: false, schema: { type: "string" } }],
          responses: {
            200: { description: "Verifiers", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Verifier" } } } } }
          }
        }
      },
      "/api/v1/verifiers/{id}": {
        get: {
          tags: ["Verifiers"],
          summary: "Get verifier",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          responses: {
            200: { description: "Verifier", content: { "application/json": { schema: { $ref: "#/components/schemas/Verifier" } } } },
            404: { description: "Not Found", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
          }
        },
        patch: {
          tags: ["Verifiers"],
          summary: "Update verifier (owner only)",
          security: [{ bearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    did: { type: "string" },
                    website_url: { type: "string" },
                    description: { type: "string" },
                    status: { type: "string", enum: ["active", "inactive"] },
                    metadata: { type: "object", additionalProperties: true }
                  }
                }
              }
            }
          },
          responses: { 200: { description: "OK", content: { "application/json": { schema: { type: "object", properties: { status: { type: "string" } } } } } } }
        }
      }
    }
  };
}

function getSwaggerUiHtml(input: { specUrl: string; title: string }) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(input.title)}</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: ${JSON.stringify(input.specUrl)},
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout"
      });
    </script>
  </body>
</html>`;
}

function escapeHtml(s: string) {
  return s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}
