CREATE TABLE IF NOT EXISTS verifiers (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    did TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    website_url TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verifiers_owner_user_id ON verifiers(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_verifiers_status ON verifiers(status);

CREATE TABLE IF NOT EXISTS proofs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    type TEXT NOT NULL DEFAULT 'zk',
    status TEXT NOT NULL DEFAULT 'created',
    proof_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_proofs_user_id ON proofs(user_id);
CREATE INDEX IF NOT EXISTS idx_proofs_credential_id ON proofs(credential_id);

CREATE TABLE IF NOT EXISTS escrows (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount_minor BIGINT NOT NULL,
    currency TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'created',
    memo TEXT NOT NULL DEFAULT '',
    disputed_at TIMESTAMP,
    dispute_reason TEXT NOT NULL DEFAULT '',
    released_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_escrows_user_id ON escrows(user_id);
CREATE INDEX IF NOT EXISTS idx_escrows_status ON escrows(status);

CREATE TABLE IF NOT EXISTS governance_proposals (
    id UUID PRIMARY KEY,
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_governance_proposals_status ON governance_proposals(status);

CREATE TABLE IF NOT EXISTS governance_votes (
    id UUID PRIMARY KEY,
    proposal_id UUID NOT NULL REFERENCES governance_proposals(id) ON DELETE CASCADE,
    voter_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vote TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    UNIQUE(proposal_id, voter_user_id)
);

CREATE INDEX IF NOT EXISTS idx_governance_votes_proposal_id ON governance_votes(proposal_id);
