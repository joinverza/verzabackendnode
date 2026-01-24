import type { Logger } from "@verza/observability";

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";

export function createPgPool(databaseUrl: string) {
  return new Pool({ connectionString: databaseUrl, max: 10 });
}

export async function migrateDatabase(opts: { db: "main" | "identity"; databaseUrl: string; logger: Logger }) {
  const pool = createPgPool(opts.databaseUrl);
  try {
    await pool.query("create table if not exists schema_migrations (id text primary key, applied_at timestamp not null)");
    const dir = migrationsDir(opts.db);
    const entries = await fs.readdir(dir);
    const sqlFiles = entries.filter((e) => e.endsWith(".sql")).sort();

    const applied = await pool.query<{ id: string }>("select id from schema_migrations");
    const appliedSet = new Set(applied.rows.map((r: { id: string }) => r.id));

    for (const file of sqlFiles) {
      if (appliedSet.has(file)) continue;
      const sql = await fs.readFile(path.join(dir, file), "utf8");
      opts.logger.info({ file }, "applying migration");
      await pool.query("begin");
      try {
        await pool.query(sql);
        await pool.query("insert into schema_migrations (id, applied_at) values ($1, now())", [file]);
        await pool.query("commit");
      } catch (err) {
        await pool.query("rollback");
        throw err;
      }
    }
  } finally {
    await pool.end();
  }
}

function migrationsDir(db: "main" | "identity") {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  return path.join(__dirname, "..", "migrations", db);
}
