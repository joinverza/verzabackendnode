CREATE TABLE IF NOT EXISTS identity_verifications (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id UUID REFERENCES credentials(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    provider TEXT NOT NULL DEFAULT 'internal',
    document_type TEXT NOT NULL DEFAULT '',
    confidence_threshold REAL NOT NULL DEFAULT 0.98,
    scores_json TEXT NOT NULL DEFAULT '{}',
    reasons_json TEXT NOT NULL DEFAULT '[]',
    signals_json TEXT NOT NULL DEFAULT '{}',
    locale TEXT NOT NULL DEFAULT '',
    client_timestamp TIMESTAMP,
    geo_lat REAL NOT NULL DEFAULT 0,
    geo_lon REAL NOT NULL DEFAULT 0,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    server_received_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_identity_verifications_user_id ON identity_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_identity_verifications_credential_id ON identity_verifications(credential_id);
CREATE INDEX IF NOT EXISTS idx_identity_verifications_status ON identity_verifications(status);

CREATE TABLE IF NOT EXISTS identity_verification_audit_events (
    id UUID PRIMARY KEY,
    verification_id UUID NOT NULL REFERENCES identity_verifications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_verification_audit_verification_id ON identity_verification_audit_events(verification_id);
CREATE INDEX IF NOT EXISTS idx_identity_verification_audit_user_id ON identity_verification_audit_events(user_id);

