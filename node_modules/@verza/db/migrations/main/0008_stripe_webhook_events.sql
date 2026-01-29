CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    stripe_payment_intent_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_pi ON stripe_webhook_events(stripe_payment_intent_id);

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

INSERT INTO tenants (id, name, status, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'active', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_credentials_tenant_owner ON credentials(tenant_id, owner_user_id);

ALTER TABLE credential_shares ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_credential_shares_tenant_credential ON credential_shares(tenant_id, credential_id);

ALTER TABLE institutions ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_institutions_tenant_id ON institutions(tenant_id);

ALTER TABLE consents ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_consents_tenant_user ON consents(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_consents_tenant_institution ON consents(tenant_id, institution_id);

ALTER TABLE identity_verifications ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_identity_verifications_tenant_user ON identity_verifications(tenant_id, user_id);

ALTER TABLE identity_verification_audit_events ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_identity_verification_audit_tenant_verification ON identity_verification_audit_events(tenant_id, verification_id);

ALTER TABLE verifiers ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_verifiers_tenant_owner ON verifiers(tenant_id, owner_user_id);

ALTER TABLE proofs ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_proofs_tenant_user ON proofs(tenant_id, user_id);
