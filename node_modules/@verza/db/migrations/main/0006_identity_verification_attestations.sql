ALTER TABLE identity_verifications
    ADD COLUMN IF NOT EXISTS verifier_institution_id UUID REFERENCES institutions(id) ON DELETE SET NULL;

ALTER TABLE identity_verifications
    ADD COLUMN IF NOT EXISTS standard TEXT NOT NULL DEFAULT '';

ALTER TABLE identity_verifications
    ADD COLUMN IF NOT EXISTS verifier_reference TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_identity_verifications_verifier_institution_id ON identity_verifications(verifier_institution_id);

