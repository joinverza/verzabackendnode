CREATE TABLE IF NOT EXISTS did_revocations (
    did_hash TEXT PRIMARY KEY,
    revoked_at TIMESTAMP NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS did_sessions (
    id UUID PRIMARY KEY,
    did_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_did_sessions_did_hash ON did_sessions(did_hash);

CREATE TABLE IF NOT EXISTS fiat_payment_sessions (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    did_hash TEXT NOT NULL,
    did_enc TEXT NOT NULL DEFAULT '',
    did_nonce_b64 TEXT NOT NULL DEFAULT '',
    amount_minor BIGINT NOT NULL,
    currency TEXT NOT NULL,
    preferred_currency TEXT NOT NULL DEFAULT '',
    stripe_payment_intent_id TEXT NOT NULL DEFAULT '',
    stripe_client_secret TEXT NOT NULL DEFAULT '',
    stripe_status TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'initiated',
    fx_rate REAL NOT NULL DEFAULT 0,
    fx_source_currency TEXT NOT NULL DEFAULT '',
    fx_target_currency TEXT NOT NULL DEFAULT '',
    fx_locked_until TIMESTAMP,
    zk_token_hash TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fiat_payment_sessions_user_id ON fiat_payment_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_fiat_payment_sessions_did_hash ON fiat_payment_sessions(did_hash);
CREATE INDEX IF NOT EXISTS idx_fiat_payment_sessions_stripe_id ON fiat_payment_sessions(stripe_payment_intent_id);
CREATE INDEX IF NOT EXISTS idx_fiat_payment_sessions_status ON fiat_payment_sessions(status);

CREATE TABLE IF NOT EXISTS payment_audit_events (
    id UUID PRIMARY KEY,
    payment_id UUID NOT NULL REFERENCES fiat_payment_sessions(id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    type TEXT NOT NULL,
    at TIMESTAMP NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    prev_hash_hex TEXT NOT NULL DEFAULT '',
    hash_hex TEXT NOT NULL,
    sig_kid TEXT NOT NULL DEFAULT '',
    sig_b64 TEXT NOT NULL DEFAULT '',
    UNIQUE (payment_id, seq),
    UNIQUE (hash_hex)
);

CREATE INDEX IF NOT EXISTS idx_payment_audit_payment ON payment_audit_events(payment_id);

CREATE TABLE IF NOT EXISTS payment_receipts (
    id UUID PRIMARY KEY,
    payment_id UUID NOT NULL REFERENCES fiat_payment_sessions(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    receipt_json TEXT NOT NULL DEFAULT '{}',
    receipt_hash_hex TEXT NOT NULL,
    sig_kid TEXT NOT NULL DEFAULT '',
    sig_b64 TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_payment_receipts_payment ON payment_receipts(payment_id);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id UUID PRIMARY KEY,
    payment_id UUID NOT NULL REFERENCES fiat_payment_sessions(id) ON DELETE CASCADE,
    amount_minor BIGINT NOT NULL,
    currency TEXT NOT NULL,
    stripe_payment_intent_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_entries_payment ON ledger_entries(payment_id);

CREATE TABLE IF NOT EXISTS reconciliation_reports (
    id UUID PRIMARY KEY,
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    report_json TEXT NOT NULL DEFAULT '{}',
    zk_proof_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL
);

