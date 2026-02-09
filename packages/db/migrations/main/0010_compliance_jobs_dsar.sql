CREATE TABLE IF NOT EXISTS audit_chain_anchors (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stream TEXT NOT NULL DEFAULT 'tenant',
    head_hash TEXT NOT NULL DEFAULT '',
    next_seq BIGINT NOT NULL DEFAULT 1,
    anchored_at TIMESTAMP NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    sig_kid TEXT NOT NULL DEFAULT '',
    sig_b64 TEXT NOT NULL DEFAULT '',
    anchor_target TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_anchors_tenant_stream_time ON audit_chain_anchors(tenant_id, stream, anchored_at DESC);

CREATE TABLE IF NOT EXISTS retention_runs (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ran_at TIMESTAMP NOT NULL,
    report_sha256 TEXT NOT NULL DEFAULT '',
    evidence_id UUID REFERENCES evidence_objects(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_retention_runs_tenant_time ON retention_runs(tenant_id, ran_at DESC);

CREATE TABLE IF NOT EXISTS dsar_approvals (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dsar_request_id UUID NOT NULL REFERENCES dsar_requests(id) ON DELETE CASCADE,
    admin_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    decision TEXT NOT NULL DEFAULT 'approve',
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    UNIQUE (dsar_request_id, admin_user_id)
);

CREATE INDEX IF NOT EXISTS idx_dsar_approvals_tenant_request ON dsar_approvals(tenant_id, dsar_request_id, created_at DESC);

DROP TRIGGER IF EXISTS trg_audit_chain_anchors_immutable ON audit_chain_anchors;
CREATE TRIGGER trg_audit_chain_anchors_immutable
BEFORE UPDATE OR DELETE ON audit_chain_anchors
FOR EACH ROW EXECUTE FUNCTION prevent_update_or_delete();

DROP TRIGGER IF EXISTS trg_retention_runs_immutable ON retention_runs;
CREATE TRIGGER trg_retention_runs_immutable
BEFORE UPDATE OR DELETE ON retention_runs
FOR EACH ROW EXECUTE FUNCTION prevent_update_or_delete();

DROP TRIGGER IF EXISTS trg_dsar_approvals_immutable ON dsar_approvals;
CREATE TRIGGER trg_dsar_approvals_immutable
BEFORE UPDATE OR DELETE ON dsar_approvals
FOR EACH ROW EXECUTE FUNCTION prevent_update_or_delete();
