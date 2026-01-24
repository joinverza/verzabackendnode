import crypto from "node:crypto";

export function sha256Hex(input: string | Buffer) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function hkdfSha256(ikm: Buffer, salt: Buffer, info: Buffer, length: number) {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, salt, info, length));
}

export function encryptJson(opts: { masterKeyB64: string; plaintext: unknown }) {
  const master = Buffer.from(opts.masterKeyB64, "base64");
  const salt = crypto.randomBytes(16);
  const info = Buffer.from("verza:aesgcm:v1", "utf8");
  const key = hkdfSha256(master, salt, info, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const pt = Buffer.from(JSON.stringify(opts.plaintext), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  const packed = Buffer.concat([salt, iv, tag, ct]);
  return packed.toString("base64");
}

export function decryptJson(opts: { masterKeyB64: string; ciphertextB64: string }): unknown {
  const master = Buffer.from(opts.masterKeyB64, "base64");
  const packed = Buffer.from(opts.ciphertextB64, "base64");
  const salt = packed.subarray(0, 16);
  const iv = packed.subarray(16, 28);
  const tag = packed.subarray(28, 44);
  const ct = packed.subarray(44);
  const info = Buffer.from("verza:aesgcm:v1", "utf8");
  const key = hkdfSha256(master, salt, info, 32);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  return JSON.parse(pt);
}

export function canonicalJson(value: unknown) {
  return stableStringify(value);
}

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const entries = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

export function signReceipt(opts: { seedB64: string; receipt: unknown }) {
  const seed = Buffer.from(opts.seedB64, "base64");
  const keyPair = crypto.generateKeyPairSync("ed25519", { seed });
  const pubDer = keyPair.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const kid = `ed25519:${sha256Hex(pubDer).slice(0, 16)}`;
  const payload = Buffer.from(canonicalJson(opts.receipt), "utf8");
  const sig = crypto.sign(null, payload, keyPair.privateKey);
  return { sig_kid: kid, sig_b64: base64Url(sig) };
}

export function verifyDidSignedRequest(opts: {
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  rawBody: Buffer;
  did: string;
  signature: string;
}) {
  const tsMs = Date.parse(opts.timestamp);
  if (!Number.isFinite(tsMs)) return false;
  const now = Date.now();
  if (tsMs > now + 30_000) return false;
  if (tsMs < now - 5 * 60_000) return false;

  const pubkey = didToEd25519PublicKey(opts.did);
  if (!pubkey) return false;

  const bodyHashHex = sha256Hex(opts.rawBody);
  const canonical =
    `${opts.method.toUpperCase()}\n` +
    `${opts.path}\n` +
    `${opts.timestamp}\n` +
    `${opts.nonce}\n` +
    `${bodyHashHex}`;
  const sigBytes = parseSignature(opts.signature);
  if (!sigBytes) return false;
  return crypto.verify(null, Buffer.from(canonical, "utf8"), pubkey, sigBytes);
}

function parseSignature(signature: string) {
  const s = signature.trim();
  try {
    if (s.includes("-") || s.includes("_")) return Buffer.from(s.replaceAll("-", "+").replaceAll("_", "/"), "base64");
    return Buffer.from(s, "base64");
  } catch {
    return null;
  }
}

function didToEd25519PublicKey(did: string): crypto.KeyObject | null {
  if (did.startsWith("did:jwk:")) {
    const encoded = did.slice("did:jwk:".length);
    const json = Buffer.from(encoded.replaceAll("-", "+").replaceAll("_", "/"), "base64").toString("utf8");
    const jwk = JSON.parse(json) as { kty: string; crv: string; x: string };
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
    const pub = Buffer.from(jwk.x.replaceAll("-", "+").replaceAll("_", "/"), "base64");
    if (pub.length !== 32) return null;
    return crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  }
  if (did.startsWith("did:key:z")) {
    const multibase = did.slice("did:key:".length);
    const bytes = base58btcDecode(multibase);
    if (!bytes) return null;
    const { value: code, offset: o1 } = readUvarint(bytes, 0) ?? {};
    if (code !== 0xed) return null;
    const { value: code2, offset: o2 } = readUvarint(bytes, o1 ?? 0) ?? {};
    if (code2 !== 0x01) return null;
    const keyBytes = bytes.subarray(o2 ?? 0);
    if (keyBytes.length !== 32) return null;
    const x = base64Url(keyBytes);
    return crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
  }
  return null;
}

function readUvarint(buf: Buffer, offset: number) {
  let x = 0;
  let s = 0;
  let i = offset;
  for (; i < buf.length; i++) {
    const b = buf[i]!;
    if (b < 0x80) {
      if (i - offset > 9 || (i - offset === 9 && b > 1)) return null;
      return { value: x | (b << s), offset: i + 1 };
    }
    x |= (b & 0x7f) << s;
    s += 7;
  }
  return null;
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcDecode(input: string) {
  if (!input.startsWith("z")) return null;
  const s = input.slice(1);
  let bytes = [0];
  for (const c of s) {
    const val = base58Alphabet.indexOf(c);
    if (val === -1) return null;
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const c of s) {
    if (c === "1") bytes.push(0);
    else break;
  }
  bytes = bytes.reverse();
  return Buffer.from(bytes);
}

function base64Url(bytes: Buffer) {
  return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
