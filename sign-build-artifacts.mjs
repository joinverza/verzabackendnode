import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, sha256Hex, signReceipt } from "@verza/crypto";

const repoRoot = path.dirname(fileURLToPath(import.meta.url));

async function pathExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function listWorkspaceDistDirs() {
  const out = [];
  for (const top of ["apps", "packages"]) {
    const base = path.join(repoRoot, top);
    if (!(await pathExists(base))) continue;
    const entries = await fs.readdir(base, { withFileTypes: true });
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const dist = path.join(base, e.name, "dist");
      if (await pathExists(dist)) out.push(dist);
    }
  }
  return out;
}

async function walkFiles(dir) {
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    const entries = await fs.readdir(cur, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(full);
      else if (e.isFile()) out.push(full);
    }
  }
  return out;
}

function rel(p) {
  return path.relative(repoRoot, p).split(path.sep).join("/");
}

async function main() {
  const seedB64 = String(process.env.RECEIPT_ED25519_SEED_B64 ?? "").trim();
  if (!seedB64) {
    console.error("Missing RECEIPT_ED25519_SEED_B64; cannot sign build artifacts.");
    process.exit(2);
  }

  const distDirs = await listWorkspaceDistDirs();
  const files = [];
  for (const d of distDirs) files.push(...(await walkFiles(d)));

  const entries = [];
  for (const f of files) {
    const buf = await fs.readFile(f);
    const sha = crypto.createHash("sha256").update(buf).digest("hex");
    entries.push({ path: rel(f), sha256: sha, size: buf.length });
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const manifest = {
    type: "build_artifacts_manifest",
    generated_at: new Date().toISOString(),
    node_version: process.version,
    entries
  };
  const manifestJson = canonicalJson(manifest);
  const manifestSha256 = sha256Hex(manifestJson);
  const signed = signReceipt({ seedB64, receipt: manifest });

  const envelope = { manifest, manifest_sha256: manifestSha256, ...signed };
  const outPath = path.join(repoRoot, "build_artifacts_receipt.json");
  await fs.writeFile(outPath, canonicalJson(envelope), "utf8");

  console.log(
    JSON.stringify(
      { status: "ok", output: rel(outPath), entries: entries.length, manifest_sha256: manifestSha256, sig_kid: signed.sig_kid },
      null,
      2
    )
  );
}

await main();

