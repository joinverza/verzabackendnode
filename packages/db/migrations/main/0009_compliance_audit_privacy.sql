CREATE TABLE IF NOT EXISTS audit_chains (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stream TEXT NOT NULL DEFAULT 'tenant',
    next_seq BIGINT NOT NULL DEFAULT 1,
    head_hash TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (tenant_id, stream)
);

INSERT INTO audit_chains (tenant_id, stream, next_seq, head_hash, updated_at)
SELECT t.id, 'tenant', 1, '', NOW()
FROM tenants t
ON CONFLICT (tenant_id, stream) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stream TEXT NOT NULL DEFAULT 'tenant',
    seq BIGINT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL,
    event_type TEXT NOT NULL DEFAULT '',
    actor_type TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL DEFAULT '',
    subject_type TEXT NOT NULL DEFAULT '',
    subject_id TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL,
    created_at_ms BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_tenant_stream_seq ON audit_events(tenant_id, stream, seq);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created_at ON audit_events(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_subject ON audit_events(tenant_id, subject_type, subject_id);

CREATE TABLE IF NOT EXISTS evidence_objects (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    subject_type TEXT NOT NULL DEFAULT '',
    subject_id TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL DEFAULT '',
    storage TEXT NOT NULL DEFAULT 'inline',
    blob_b64 TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_objects_tenant_created_at ON evidence_objects(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_objects_tenant_subject ON evidence_objects(tenant_id, subject_type, subject_id);

ALTER TABLE consents ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS consent_versions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    consent_id UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    version INT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    credential_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    allowed_fields_json TEXT NOT NULL DEFAULT '[]',
    purpose TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_consent_versions_consent_version ON consent_versions(tenant_id, consent_id, version);
CREATE INDEX IF NOT EXISTS idx_consent_versions_tenant_user ON consent_versions(tenant_id, user_id);

ALTER TABLE consent_audit_events ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_consent_audit_events_tenant_consent ON consent_audit_events(tenant_id, consent_id);

CREATE TABLE IF NOT EXISTS dsar_requests (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    request_type TEXT NOT NULL DEFAULT 'delete',
    status TEXT NOT NULL DEFAULT 'requested',
    reason TEXT NOT NULL DEFAULT '',
    requested_at TIMESTAMP NOT NULL,
    processed_at TIMESTAMP,
    processed_by TEXT NOT NULL DEFAULT '',
    result_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_dsar_requests_tenant_user ON dsar_requests(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_dsar_requests_tenant_status ON dsar_requests(tenant_id, status);

CREATE TABLE IF NOT EXISTS retention_policies (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL DEFAULT '',
    retention_days INT NOT NULL DEFAULT 0,
    action TEXT NOT NULL DEFAULT 'delete',
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (tenant_id, resource_type)
);

CREATE OR REPLACE FUNCTION prevent_update_or_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'immutable_table';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events;
CREATE TRIGGER trg_audit_events_immutable
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_update_or_delete();

DROP TRIGGER IF EXISTS trg_evidence_objects_immutable ON evidence_objects;
CREATE TRIGGER trg_evidence_objects_immutable
BEFORE UPDATE OR DELETE ON evidence_objects
FOR EACH ROW EXECUTE FUNCTION prevent_update_or_delete();

