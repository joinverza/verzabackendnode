import type { Express } from "express";
import type { Pool } from "pg";
import type { Logger } from "@verza/observability";
import type { MainApiConfig } from "@verza/config";
export type MainApiContext = {
    config: MainApiConfig;
    logger: Logger;
    pool: Pool;
};
export declare function registerMainApiRoutes(app: Express, ctx: MainApiContext): void;
//# sourceMappingURL=routes.d.ts.map