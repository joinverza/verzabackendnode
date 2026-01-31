import crypto from "node:crypto";
import { canonicalJson, sha256Hex } from "@verza/crypto";
export async function appendAuditEvent(pool, args) {
    const stream = (args.stream ?? "tenant").trim() || "tenant";
    const createdAtMs = Date.now();
    const createdAt = new Date(createdAtMs);
    const id = crypto.randomUUID();
    const dataJson = canonicalJson(sanitizeAuditData(args.data));
    await pool.query("begin");
    try {
        const chain = await pool.query("select next_seq, head_hash from audit_chains where tenant_id=$1 and stream=$2 for update", [args.tenantId, stream]);
        if (!chain.rowCount) {
            await pool.query("insert into audit_chains (tenant_id, stream, next_seq, head_hash, updated_at) values ($1,$2,1,'',$3) on conflict (tenant_id, stream) do nothing", [
                args.tenantId,
                stream,
                createdAt
            ]);
        }
        const chain2 = await pool.query("select next_seq, head_hash from audit_chains where tenant_id=$1 and stream=$2 for update", [args.tenantId, stream]);
        const row = chain2.rows[0];
        const seq = typeof row?.next_seq === "string" ? Number(row.next_seq) : Number(row?.next_seq ?? 1);
        const prevHash = row?.head_hash ?? "";
        const eventHash = computeAuditEventHash({
            tenant_id: args.tenantId,
            stream,
            seq,
            prev_hash: prevHash,
            event_type: args.eventType,
            actor_type: args.actorType,
            actor_id: args.actorId,
            subject_type: args.subjectType,
            subject_id: args.subjectId,
            data_json: dataJson,
            created_at_ms: createdAtMs
        });
        await pool.query("insert into audit_events (id,tenant_id,stream,seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at,created_at_ms) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", [
            id,
            args.tenantId,
            stream,
            seq,
            prevHash,
            eventHash,
            args.eventType,
            args.actorType,
            args.actorId,
            args.subjectType,
            args.subjectId,
            dataJson,
            createdAt,
            createdAtMs
        ]);
        await pool.query("update audit_chains set next_seq=next_seq+1, head_hash=$1, updated_at=$2 where tenant_id=$3 and stream=$4", [
            eventHash,
            createdAt,
            args.tenantId,
            stream
        ]);
        await pool.query("commit");
        return { id, seq, prevHash, eventHash, createdAt, createdAtMs, stream };
    }
    catch (err) {
        await pool.query("rollback");
        throw err;
    }
}
export async function verifyAuditChain(pool, args) {
    const stream = (args.stream ?? "tenant").trim() || "tenant";
    const fromSeq = Math.max(1, Math.floor(args.fromSeq ?? 1));
    const upper = args.toSeq ? Math.floor(args.toSeq) : null;
    let expectedPrev = "";
    if (fromSeq > 1) {
        const prev = await pool.query("select event_hash from audit_events where tenant_id=$1 and stream=$2 and seq=$3 limit 1", [args.tenantId, stream, fromSeq - 1]);
        const prevRow = prev.rows[0];
        if (!prevRow?.event_hash)
            return { ok: false, badSeq: fromSeq, expected: "missing_prev_event", actual: "" };
        expectedPrev = prevRow.event_hash;
    }
    const rows = await pool.query(upper
        ? "select seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at_ms from audit_events where tenant_id=$1 and stream=$2 and seq >= $3 and seq <= $4 order by seq asc"
        : "select seq,prev_hash,event_hash,event_type,actor_type,actor_id,subject_type,subject_id,data_json,created_at_ms from audit_events where tenant_id=$1 and stream=$2 and seq >= $3 order by seq asc", upper ? [args.tenantId, stream, fromSeq, upper] : [args.tenantId, stream, fromSeq]);
    for (const r of rows.rows) {
        const seq = typeof r.seq === "string" ? Number(r.seq) : Number(r.seq);
        if (r.prev_hash !== expectedPrev)
            return { ok: false, badSeq: seq, expected: expectedPrev, actual: r.prev_hash };
        const createdAtMs = typeof r.created_at_ms === "string" ? Number(r.created_at_ms) : Number(r.created_at_ms);
        const expected = computeAuditEventHash({
            tenant_id: args.tenantId,
            stream,
            seq,
            prev_hash: r.prev_hash ?? "",
            event_type: r.event_type ?? "",
            actor_type: r.actor_type ?? "",
            actor_id: r.actor_id ?? "",
            subject_type: r.subject_type ?? "",
            subject_id: r.subject_id ?? "",
            data_json: typeof r.data_json === "string" ? r.data_json : canonicalJson(r.data_json),
            created_at_ms: createdAtMs
        });
        if (expected !== r.event_hash)
            return { ok: false, badSeq: seq, expected, actual: r.event_hash };
        expectedPrev = r.event_hash;
    }
    const head = await pool.query("select head_hash,next_seq from audit_chains where tenant_id=$1 and stream=$2 limit 1", [
        args.tenantId,
        stream
    ]);
    const headRow = head.rows[0];
    return { ok: true, stream, headHash: headRow?.head_hash ?? "", nextSeq: Number(headRow?.next_seq ?? 1), verifiedFromSeq: fromSeq };
}
function computeAuditEventHash(fields) {
    return sha256Hex(canonicalJson({
        tenant_id: fields.tenant_id,
        stream: fields.stream,
        seq: fields.seq,
        prev_hash: fields.prev_hash,
        event_type: fields.event_type,
        actor_type: fields.actor_type,
        actor_id: fields.actor_id,
        subject_type: fields.subject_type,
        subject_id: fields.subject_id,
        data_json: fields.data_json,
        created_at_ms: fields.created_at_ms
    }));
}
export function sanitizeAuditData(input) {
    const dropKeys = new Set([
        "password",
        "current_password",
        "new_password",
        "refresh_token",
        "access_token",
        "token",
        "secret",
        "api_key",
        "authorization",
        "encrypted_data",
        "backup_codes",
        "twofa_secret"
    ]);
    const maxDepth = 6;
    const maxString = 2048;
    const seen = new WeakSet();
    const walk = (v, depth) => {
        if (depth > maxDepth)
            return "[truncated]";
        if (v === null || v === undefined)
            return null;
        if (typeof v === "string")
            return v.length > maxString ? `${v.slice(0, maxString)}…` : v;
        if (typeof v === "number" || typeof v === "boolean")
            return v;
        if (Array.isArray(v))
            return v.slice(0, 100).map((x) => walk(x, depth + 1));
        if (typeof v === "object") {
            const o = v;
            if (seen.has(o))
                return "[circular]";
            seen.add(o);
            const out = {};
            const keys = Object.keys(o).slice(0, 200);
            for (const k of keys) {
                if (dropKeys.has(k.toLowerCase()))
                    continue;
                out[k] = walk(o[k], depth + 1);
            }
            return out;
        }
        if (typeof v === "bigint")
            return v.toString();
        if (typeof v === "symbol")
            return v.description ?? v.toString();
        if (typeof v === "function")
            return "[function]";
        return typeof v;
    };
    const sanitized = walk(input, 0);
    const json = canonicalJson(sanitized);
    if (json.length <= 8192)
        return sanitized;
    return { truncated: true, sha256: sha256Hex(json) };
}
//# sourceMappingURL=auditLog.js.map