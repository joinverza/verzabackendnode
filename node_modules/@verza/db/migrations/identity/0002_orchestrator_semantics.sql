ALTER TABLE identity_verifications_v2
  ADD COLUMN IF NOT EXISTS user_id UUID;

ALTER TABLE identity_verifications_v2
  ADD COLUMN IF NOT EXISTS attempt_count INT NOT NULL DEFAULT 0;

ALTER TABLE identity_verifications_v2
  ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '';

ALTER TABLE identity_verifications_v2
  ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_identity_verifications_v2_user_id ON identity_verifications_v2(user_id);

CREATE TABLE IF NOT EXISTS identity_inference_outputs_v2 (
    id UUID PRIMARY KEY,
    verification_id UUID NOT NULL REFERENCES identity_verifications_v2(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    output_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_inference_outputs_v2_verification_id ON identity_inference_outputs_v2(verification_id);

CREATE TABLE IF NOT EXISTS identity_verification_decisions_v2 (
    id UUID PRIMARY KEY,
    verification_id UUID NOT NULL REFERENCES identity_verifications_v2(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    scores_json TEXT NOT NULL DEFAULT '{}',
    reasons_json TEXT NOT NULL DEFAULT '[]',
    signals_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_verification_decisions_v2_verification_id ON identity_verification_decisions_v2(verification_id);

