import type { Logger } from "@verza/observability";
import { Pool } from "pg";
export declare function createPgPool(databaseUrl: string): Pool;
export declare function migrateDatabase(opts: {
    db: "main" | "identity";
    databaseUrl: string;
    logger: Logger;
}): Promise<void>;
//# sourceMappingURL=index.d.ts.map