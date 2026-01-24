CREATE TABLE IF NOT EXISTS cross_chain_transactions (
    id UUID PRIMARY KEY,
    midnight_tx_hash VARCHAR(66),
    cardano_tx_hash VARCHAR(66),
    operation_type VARCHAR(50),
    status VARCHAR(20),
    retry_count INT DEFAULT 0,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credential_metadata (
    credential_id VARCHAR(66) PRIMARY KEY,
    midnight_address VARCHAR(100),
    cardano_escrow_id VARCHAR(66),
    verifier_did VARCHAR(100),
    status VARCHAR(20),
    created_at TIMESTAMP
);

