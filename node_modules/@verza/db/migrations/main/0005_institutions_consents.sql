CREATE TABLE IF NOT EXISTS institutions (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS institution_members (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL,
    UNIQUE(institution_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_institution_members_user_id ON institution_members(user_id);
CREATE INDEX IF NOT EXISTS idx_institution_members_institution_id ON institution_members(institution_id);

CREATE TABLE IF NOT EXISTS institution_api_keys (
    id UUID PRIMARY KEY,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    key_hash TEXT UNIQUE NOT NULL,
    last4 TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_institution_api_keys_institution_id ON institution_api_keys(institution_id);

CREATE TABLE IF NOT EXISTS consents (
    id UUID PRIMARY KEY,
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

CREATE INDEX IF NOT EXISTS idx_consents_user_id ON consents(user_id);
CREATE INDEX IF NOT EXISTS idx_consents_institution_id ON consents(institution_id);
CREATE INDEX IF NOT EXISTS idx_consents_credential_id ON consents(credential_id);
CREATE INDEX IF NOT EXISTS idx_consents_status ON consents(status);

CREATE TABLE IF NOT EXISTS consent_audit_events (
    id UUID PRIMARY KEY,
    consent_id UUID NOT NULL REFERENCES consents(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL DEFAULT '',
    actor_type TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_consent_audit_events_consent_id ON consent_audit_events(consent_id);

