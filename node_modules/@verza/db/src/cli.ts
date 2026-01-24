import { createLogger } from "@verza/observability";

import { migrateDatabase } from "./index.js";

function parseArgs(argv: string[]) {
  const args = new Map<string, string>();
  for (const a of argv) {
    const [k, v] = a.split("=", 2);
    if (k && v && k.startsWith("--")) args.set(k.slice(2), v);
  }
  return args;
}

const [command] = process.argv.slice(2);
const args = parseArgs(process.argv.slice(2));

if (command !== "migrate") {
  process.stderr.write("Usage: verza-db migrate --db=main|identity\n");
  process.exit(2);
}

const db = (args.get("db") ?? "main") as "main" | "identity";
const envVar = db === "main" ? "DATABASE_URL" : "IDENTITY_DATABASE_URL";
const databaseUrl = process.env[envVar];
if (!databaseUrl) {
  process.stderr.write(`Missing ${envVar}\n`);
  process.exit(2);
}

const logger = createLogger({ service: "db", level: process.env.LOG_LEVEL ?? "info" });
await migrateDatabase({ db, databaseUrl, logger });

