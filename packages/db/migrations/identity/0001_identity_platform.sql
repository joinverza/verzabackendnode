CREATE TABLE IF NOT EXISTS identity_sessions (
    id UUID PRIMARY KEY,
    user_id UUID,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_verifications_v2 (
    id UUID PRIMARY KEY,
    type TEXT NOT NULL,
    subject_id TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_verification_audit_v2 (
    id UUID PRIMARY KEY,
    verification_id UUID NOT NULL REFERENCES identity_verifications_v2(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_media (
    id UUID PRIMARY KEY,
    verification_id UUID NOT NULL REFERENCES identity_verifications_v2(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    kind TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_idempotency (
    id UUID PRIMARY KEY,
    verification_id UUID NOT NULL REFERENCES identity_verifications_v2(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    UNIQUE (verification_id, key)
);

